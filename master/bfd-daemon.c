#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <linux/bpf.h>
#include <asm/unistd.h>

#define DEBUG 0
#define SR6_TLV_BFD 142

#ifndef __u8
#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __be32 uint32_t
#define __u64 uint64_t
#endif

struct sr6_tlv {
	__u8 type;
	__u8 len;
	__u8 value[0];
};

struct sr6_tlv_bfd {
	__u8 type;
	__u8 len;
	__u16 session;
	__u16 seq;
	__u16 ack;
	__u32 min_master_interval;
	__u32 min_slave_interval;
};

struct ipv6_sr_hdr {
        __u8    nexthdr;
        __u8    hdrlen;
        __u8    type;
        __u8    segments_left;
        __u8    first_segment;
        __u8    flags;
        __u16   tag;

        struct in6_addr segments[0];
}; // Basic length : 8 bytes

struct daemon_state {
	// Values set by main()
        struct in6_addr bindaddr;
	unsigned int nb_segments;
        struct in6_addr *segments;
	__u16 session;

	// Read by receiver, written by sender thread
	__u16 seq;

	// Controlled by receiver thread, read by sender
	bool link_up;
	bool sending;
	unsigned int threshold;
	struct timespec snd_interval;
	__u16 ack;
} state;

pthread_mutex_t lock;
int bpf_map_fd;

#define debug_print(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#ifdef __NR_bpf
	return syscall(__NR_bpf, cmd, attr, size);
#else
	fprintf(stderr, "No bpf syscall, kernel headers too old?\n");
	errno = ENOSYS;
	return -1;
#endif
}

__u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

int bpf_update_elem(int fd, void *key, void *value, __u64 flags)
{
	union bpf_attr attr = {};
	attr.map_fd = fd;
	attr.key    = bpf_ptr_to_u64(key);
	attr.value  = bpf_ptr_to_u64(value);
	attr.flags  = flags;

	static int nb = 0;
	nb++;
	int ret = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	if (ret < 0) {
		fprintf(stderr, "Map update #%d failed: %s\n", nb, strerror(errno));
	}
	
	return ret;
}

int bpf_get_map(char *path)
{
	union bpf_attr attr_obj = {};
	int fd;

	attr_obj.map_fd = 0;
	attr_obj.pathname = bpf_ptr_to_u64(path);
	fd = bpf(BPF_OBJ_GET, &attr_obj, sizeof(attr_obj));
	if (fd <= 0) {
		fprintf(stderr, "Getting BPF map failed: %s\n", strerror(errno));
		return -1;
	}

	return fd;
}

void update_link_state(bool status)
{
	state.link_up = status;
	__u32 key = 0;
	__u32 val = (__u32) status;
	bpf_update_elem(bpf_map_fd, &key, &val, 0);

	if (status)
		printf("Link is up\n");
	else
		printf("Link is down\n");
}

struct ipv6_sr_hdr *build_srh(unsigned int nb_segments,
			      struct in6_addr segments[], size_t *srh_len)
{
	*srh_len = sizeof(struct ipv6_sr_hdr) +
			  (nb_segments + 1) * sizeof(struct in6_addr)
			  + sizeof(struct sr6_tlv_bfd);

	void *ptr = malloc(*srh_len);
	if (!ptr)
		return NULL;

	memset(ptr, 0, *srh_len);
	struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)ptr;
	struct sr6_tlv_bfd *tlv = (struct sr6_tlv_bfd *)((char *)ptr + 
				  sizeof(struct ipv6_sr_hdr) +
				  (nb_segments + 1) * sizeof(struct in6_addr));

	memcpy(&srh->segments[1], segments, sizeof(struct in6_addr) * nb_segments);

	srh->nexthdr = 0;
	srh->type = 4;
	srh->hdrlen = (1 + nb_segments)*2 + (sizeof(struct sr6_tlv_bfd) >> 3);
	srh->segments_left = nb_segments;
	srh->first_segment = nb_segments;
	srh->tag = 0;
	srh->flags = 0;

	tlv->type = SR6_TLV_BFD;
	tlv->len = sizeof(*tlv) - 2;
	tlv->session = htons(state.session);

	return srh;
}

void *sender(void *ptr)
{
	int fd = *(int *)ptr;
	int err;

	size_t srh_len;
	struct ipv6_sr_hdr *srh = build_srh(state.nb_segments, state.segments,
					    &srh_len);
	if (!srh) {
		perror("malloc");
		return NULL;
	}

	struct sr6_tlv_bfd *tlv = (struct sr6_tlv_bfd *)((char *)srh + 
				  sizeof(struct ipv6_sr_hdr) +
				  (state.nb_segments + 1) * sizeof(struct in6_addr));


	err = setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, srh, (socklen_t) srh_len);
	if (err < 0)
		goto clean;

	char buf[] = "SRv6 BFD";
	while (state.sending) {
		pthread_mutex_lock(&lock);
		if (state.link_up) {
			state.seq++;

			if ((state.seq > state.ack && state.seq - state.ack > state.threshold) ||
			    (state.seq < state.ack && 65536 - state.ack + state.seq > state.threshold)) {
				debug_print("Threshold limit reached: SEQ=%d ACK=%d\n", state.seq, state.ack);
				state.seq = 0;
				state.ack = 0;
				update_link_state(false);
			}

			debug_print("Sending probe with SEQ=%d\n", state.seq);
			tlv->seq = htons(state.seq);
			tlv->ack = htons(state.ack);
		} else {
			tlv->seq = 0;
			tlv->ack = 0;
		}
		pthread_mutex_unlock(&lock);

		err = setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, srh, (socklen_t) srh_len);
		if (err < 0)
			goto clean;

		send(fd, buf, sizeof(buf), 0);
		// TODO: we're not checking against any sending errors at the
		// moment, but a logging function should be inserted here

		nanosleep(&state.snd_interval, NULL);
	}

	return NULL;

clean:
	state.sending = 0;
	free(srh);
	return NULL;
}

void parse_srh(struct ipv6_sr_hdr *srh)
{
	// Look for BFD TLV
	struct sr6_tlv_bfd *tlv = NULL;
	char *ptr = (char *)srh + 8 + ((srh->first_segment + 1) << 4);

	while (ptr < (char *)srh + ((srh->hdrlen + 1) << 3)) {
		struct sr6_tlv *cur = (struct sr6_tlv *)ptr;
		if (cur->type == SR6_TLV_BFD && cur->len + 2 == sizeof(struct sr6_tlv_bfd)) {
			tlv = (struct sr6_tlv_bfd *)ptr;
			break;
		}

		ptr += 2 + cur->len;
	}

	if (!tlv || ntohs(tlv->session) != state.session)
		return;

	__u16 seq = ntohs(tlv->seq);
	__u16 ack = ntohs(tlv->ack);
	debug_print("Received probe SEQ=%d ACK=%d\n", seq, ack);

	pthread_mutex_lock(&lock);
	if (!state.link_up && seq == 0 && ack == 0) {
		update_link_state(true);
	} else if ((state.seq > state.ack && seq > state.ack && seq <= state.seq) ||
		   (state.seq < state.ack && (seq >= 0 && seq <= state.seq || seq > state.ack))) 
	{
		state.ack = seq;
	}
	pthread_mutex_unlock(&lock);

	// TODO interval management
}

int receiver(int fd)
{
	char buffer[548];
	char srh_buffer[100];
	struct sockaddr_in6 src_addr;

	struct timeval tv;
	tv.tv_sec = state.snd_interval.tv_sec * state.threshold * 2;
	tv.tv_usec = 0;
	// helps to avoid a deadlock when the sender stopped and no further
	// packet is received
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

	struct iovec iov[1];
	iov[0].iov_base = buffer;
	iov[0].iov_len = sizeof(buffer);

	struct msghdr message;
	message.msg_name = &src_addr;
	message.msg_namelen = sizeof(src_addr);
	message.msg_iov = iov;
	message.msg_iovlen = 1;
	message.msg_control = srh_buffer;
	message.msg_controllen = sizeof(srh_buffer);

	while (state.sending) {
		struct ipv6_sr_hdr *srh = NULL;
		ssize_t count = recvmsg(fd, &message, 0);

		if (count == -1) {
			if (errno == 11) // EAGAIN might be raised by SO_RCVTIMEO
				continue;

			perror("recvmsg failed");
		} else if (message.msg_flags&MSG_TRUNC) {
			printf("datagram too large for buffer: truncated\n");
		} else {
			// Ensure message has been sent by our sending socket
			if (memcmp(&src_addr.sin6_addr, &state.bindaddr, sizeof(struct in6_addr)))
				continue;

			// Find SRH in the ancillary data
			struct cmsghdr *cmsg;
			for (cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL;
			     cmsg = CMSG_NXTHDR(&message,cmsg)) {
			    if (cmsg->cmsg_level == IPPROTO_IPV6
				&& cmsg->cmsg_type == IPV6_RTHDR) {
					parse_srh((struct ipv6_sr_hdr *) CMSG_DATA(cmsg));
					break;
			    }
			}
		}
	}

	return 0;
}

int main(int ac, char **av)
{
	if (ac < 8)
		goto usage;

	if (!inet_pton(AF_INET6, av[1], &state.bindaddr))
		goto usage;

	short port = (short) atoi(av[2]);
	state.session = (short) atoi(av[3]);
	state.threshold = atoi(av[4]);
	unsigned int interval = atoi(av[5]);
	if (!port || !state.session || !state.threshold || !interval)
		goto usage;

	state.snd_interval.tv_sec = interval / 1000000;
	state.snd_interval.tv_nsec = (interval % 1000000) * 1000;

	bpf_map_fd = bpf_get_map(av[6]);
	if (bpf_map_fd < 0)
		goto usage;

	state.nb_segments = ac - 7;
	state.segments = (struct in6_addr *)malloc(sizeof(struct in6_addr) * state.nb_segments);
	if (!state.segments) {
		perror("malloc");
		return -1;
	}

	for(int i=7; i < ac; i++) {
		if (!inet_pton(AF_INET6, av[i], &state.segments[i-7]))
			goto usage;
	}

	/* ---- */

	if (pthread_mutex_init(&lock, NULL)) {
		perror("pthread_mutex_init");
		free(state.segments);
		return -1;
	}

	int err;
	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(port);
	memcpy(&sin6.sin6_addr, &state.bindaddr, sizeof(struct in6_addr));

	int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	int bind_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0 || bind_fd < 0) {
		perror("socket");
		goto out;
	}

	int val = 1;
	err = setsockopt(bind_fd, IPPROTO_IPV6, IPV6_RECVRTHDR, &val, (socklen_t) sizeof(val));
	if (err < 0) {
		perror("setsockopt");
		goto out;
	}

	err = connect(fd, (struct sockaddr *)&sin6, sizeof(sin6));
	if (err < 0) {
		perror("connect");
		goto out;
	}

	err = bind(bind_fd, (struct sockaddr *)&sin6, sizeof(sin6));
	if (err < 0) {
		perror("bind");
		goto out;
	}

	state.link_up = 0;
	state.seq = 0;
	state.ack = 0;
	pthread_t th_sender;

	state.sending = 1;
	if (pthread_create(&th_sender, NULL, sender, (void *)&fd)) {
		perror("pthread_create");
		goto out;
	}
	receiver(bind_fd);

	state.sending = 0;
	pthread_join(th_sender, NULL);

	free(state.segments);
	close(fd);
	close(bind_fd);
	return 0;

out:
	if (state.sending) {
		state.sending = 0;
		pthread_join(th_sender, NULL);
	}

	pthread_mutex_destroy(&lock);
	free(state.segments);
	close(fd);
	close(bind_fd);
	return -1;

usage:
	fprintf(stderr, "Usage: %s bindaddr port session threshold interval bpf_map segment1 segment2 segment3 ...\n", av[0]);
	return -1;
}
