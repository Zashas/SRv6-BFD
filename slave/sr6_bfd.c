#include "bpf_seg6/all.h"
#include "libseg6.c"

#define NB_TIMERS 100
#define NB_MAX_SEGS 5

#define SR6_TLV_BFD 142

struct bfd_entry {
	uint64_t timestamp;
	uint16_t seq;
	uint16_t ack;
};

struct bpf_elf_map __section_maps sr6_bfd_assoc = {
	.type           =       BPF_MAP_TYPE_HASH,
	.id             =       1,
	.size_key	=       16 * NB_MAX_SEGS,
	.size_value     =       sizeof(uint32_t),
	.max_elem       =       NB_TIMERS,
	.pinning	=	PIN_GLOBAL_NS,
};

struct bpf_elf_map __section_maps sr6_bfd_timers = {
	.type           =       BPF_MAP_TYPE_ARRAY,
	.id             =       2,
	.size_key	=       sizeof(uint32_t),
	.size_value     =       sizeof(struct bfd_entry),
	.max_elem       =       NB_TIMERS,
	.pinning	=	PIN_GLOBAL_NS,
};

struct sr6_tlv_bfd {
	__u8 type;
	__u8 len;
	__u16 session;
	__u16 seq;
	__u16 ack;
	__u32 max_master_interval;
	__u32 min_slave_interval;
} BPF_PACKET_HEADER;

__section("sr6_bfd")
int sr6_bfd_fn(struct __sk_buff *skb)
{
	struct ip6_addr_t hash_blk[NB_MAX_SEGS+1];
	uint64_t ts = ktime_get_ns();

	uint8_t *ipver;
	void *data_end = (void *)(long)skb->data_end;
	void *cursor   = (void *)(long)skb->data;
	ipver = (uint8_t*) cursor;
	
	if ((void *)ipver + sizeof(*ipver) > data_end)
		return BPF_OK;

	if ((*ipver >> 4) != 6) // We only care about IPv6 packets
		return BPF_OK;

	struct ip6_t *ip;
	ip = cursor_advance(cursor, sizeof(*ip));
	if ((void *)ip + sizeof(*ip) > data_end) 
		return BPF_OK;

	if (ip->next_header != 43)
		return BPF_OK;

	struct ip6_srh_t *srh;
	srh = cursor_advance(cursor, sizeof(*srh));
	if ((void *)srh + sizeof(*srh) > data_end)
		return BPF_OK;

	if (srh->type != 4)
		return BPF_OK;

	struct sr6_tlv_bfd tlv;
	int tlv_pos = seg6_find_tlv(skb, srh, SR6_TLV_BFD, sizeof(struct sr6_tlv_bfd));
	if (tlv_pos < 0) // no BFD TLV found
		return BPF_OK;
	if (bpf_skb_load_bytes(skb, tlv_pos, &tlv, sizeof(tlv)) < 0)
		return BPF_OK; // error when reading

	memset(hash_blk, 0, sizeof(hash_blk));
	memcpy(&hash_blk[0], &ip->src_hi, sizeof(struct ip6_addr_t));

	#pragma clang loop unroll(full)
	for (int i=0; i < NB_MAX_SEGS; i++) {
		struct ip6_addr_t *seg = cursor_advance(cursor, sizeof(struct ip6_addr_t));
		if ((void *)seg + sizeof(struct ip6_addr_t) > data_end)
			return BPF_DROP;

		memcpy(&hash_blk[i+1], seg, sizeof(struct ip6_addr_t));
		if (i == srh->first_segment)
			break;
	}

	uint32_t *entry_id = map_lookup_elem(&sr6_bfd_assoc, hash_blk);
	if (!entry_id)
		return BPF_OK; // [src, segments] does not match an installed FRR policy

	struct bfd_entry *entry = map_lookup_elem(&sr6_bfd_timers, entry_id);
	if (!entry) {
		printt("[SRv6 BFD] Error: entry %d supposed to exist but not found\n", *entry_id);
		return BPF_OK;
	}

	if (ntohs(tlv.seq) == 0 && ntohs(tlv.ack) == 0) {
		entry->seq = 0;
		entry->ack = 65535;
		entry->timestamp = 0; // session has been reset by master
		printt("[SRv6 BFD] Session reset by master\n");
	} else if (!(entry->seq >= entry->ack && ntohs(tlv.ack) > entry->ack) &&
		 !(entry->seq < entry->ack && (ntohs(tlv.ack) > entry->ack || ntohs(tlv.ack) <= entry->seq)) ) {
		return BPF_DROP; // invalid seq/ack pair
	} else {
		entry->seq = ntohs(tlv.seq);
		entry->ack = ntohs(tlv.ack);
		entry->timestamp = ts;
	}

	map_update_elem(&sr6_bfd_timers, entry_id, entry, BPF_EXIST);
        return BPF_OK;
}

char __license[] __section("license") = "GPL";
