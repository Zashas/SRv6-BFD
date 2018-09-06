#!/bin/bash

cleanup()
{
	if [ "$?" = "0" ]; then
		echo "Simulation [PASS]";
	else
		echo "Simulation [FAILED]";
	fi

	set +e
	ip netns del ns1 2> /dev/null
	ip netns del ns2 2> /dev/null
	ip netns del ns3 2> /dev/null
	ip netns del ns4 2> /dev/null
	ip netns del ns5 2> /dev/null
}

#set -x
set -e
trap cleanup 0 2 3 6 9

ip netns add ns1
ip netns add ns2
ip netns add ns3
ip netns add ns4
ip netns add ns5

ip link add veth1 type veth peer name veth2
ip link add veth3 type veth peer name veth4
ip link add veth5 type veth peer name veth6
ip link add veth7 type veth peer name veth8
ip link add veth9 type veth peer name veth10

ip link set veth1 netns ns1
ip link set veth2 netns ns2
ip link set veth3 netns ns2
ip link set veth4 netns ns3
ip link set veth5 netns ns2
ip link set veth6 netns ns4
ip link set veth7 netns ns4
ip link set veth8 netns ns3
ip link set veth9 netns ns3
ip link set veth10 netns ns5

ip netns exec ns1 ip link set dev veth1 up
ip netns exec ns2 ip link set dev veth2 up
ip netns exec ns2 ip link set dev veth3 up
ip netns exec ns3 ip link set dev veth4 up
ip netns exec ns2 ip link set dev veth5 up
ip netns exec ns4 ip link set dev veth6 up
ip netns exec ns4 ip link set dev veth7 up
ip netns exec ns3 ip link set dev veth8 up
ip netns exec ns3 ip link set dev veth9 up
ip netns exec ns5 ip link set dev veth10 up
ip netns exec ns1 ip link set dev lo up
ip netns exec ns2 ip link set dev lo up
ip netns exec ns3 ip link set dev lo up
ip netns exec ns4 ip link set dev lo up
ip netns exec ns5 ip link set dev lo up

ip netns exec ns2 sysctl net.ipv6.conf.all.forwarding=1
ip netns exec ns2 sysctl net.ipv6.conf.veth2.forwarding=1
ip netns exec ns2 sysctl net.ipv6.conf.veth3.forwarding=1
ip netns exec ns2 sysctl net.ipv6.conf.veth5.forwarding=1
ip netns exec ns2 sysctl net.ipv6.conf.all.seg6_enabled=1
ip netns exec ns2 sysctl net.ipv6.conf.veth2.seg6_enabled=1
ip netns exec ns2 sysctl net.ipv6.conf.veth3.seg6_enabled=1
ip netns exec ns2 sysctl net.ipv6.conf.veth5.seg6_enabled=1

ip netns exec ns3 sysctl net.ipv6.conf.all.forwarding=1
ip netns exec ns3 sysctl net.ipv6.conf.veth4.forwarding=1
ip netns exec ns3 sysctl net.ipv6.conf.veth8.forwarding=1
ip netns exec ns3 sysctl net.ipv6.conf.all.seg6_enabled=1
ip netns exec ns3 sysctl net.ipv6.conf.veth4.seg6_enabled=1
ip netns exec ns3 sysctl net.ipv6.conf.veth8.seg6_enabled=1

ip netns exec ns4 sysctl net.ipv6.conf.all.forwarding=1
ip netns exec ns4 sysctl net.ipv6.conf.veth6.forwarding=1
ip netns exec ns4 sysctl net.ipv6.conf.veth7.forwarding=1
ip netns exec ns4 sysctl net.ipv6.conf.all.seg6_enabled=1
ip netns exec ns4 sysctl net.ipv6.conf.veth6.seg6_enabled=1
ip netns exec ns4 sysctl net.ipv6.conf.veth7.seg6_enabled=1

# All link scope addresses and routes required between veths
ip netns exec ns1 ip -6 addr add fe80::12/16 dev veth1
ip netns exec ns1 ip -6 route add fe80::21 dev veth1
ip netns exec ns2 ip -6 addr add fe80::21/16 dev veth2
ip netns exec ns2 ip -6 route add fe80::12 dev veth2
ip netns exec ns2 ip -6 addr add fe80::23/16 dev veth3
ip netns exec ns2 ip -6 route add fe80::32 dev veth3
ip netns exec ns2 ip -6 addr add fe80::24/16 dev veth5
ip netns exec ns2 ip -6 route add fe80::42 dev veth5
ip netns exec ns3 ip -6 addr add fe80::32/16 dev veth4
ip netns exec ns3 ip -6 route add fe80::23 dev veth4
ip netns exec ns3 ip -6 addr add fe80::34/16 dev veth8
ip netns exec ns3 ip -6 route add fe80::43 dev veth8
ip netns exec ns3 ip -6 addr add fe80::35/16 dev veth9
ip netns exec ns3 ip -6 route add fe80::53 dev veth9
ip netns exec ns4 ip -6 addr add fe80::43/16 dev veth7
ip netns exec ns4 ip -6 route add fe80::34 dev veth7
ip netns exec ns4 ip -6 addr add fe80::42/16 dev veth6
ip netns exec ns4 ip -6 route add fe80::24 dev veth6
ip netns exec ns5 ip -6 addr add fe80::53/16 dev veth10
ip netns exec ns5 ip -6 route add fe80::35 dev veth10

ip netns exec ns1 ip -6 addr add fb00::1:0 dev lo
ip netns exec ns2 ip -6 addr add fb00::2:0 dev lo
ip netns exec ns3 ip -6 addr add fb00::3:0 dev lo
ip netns exec ns4 ip -6 addr add fb00::4:0 dev lo
ip netns exec ns5 ip -6 addr add fb00::5:0 dev lo

simulation/netns.py ns3 ip -6 route add fb00::3:100 encap seg6local action End.BPF endpoint obj slave/sr6_bfd.o sec sr6_bfd dev veth4
simulation/netns.py ns3 slave/frr fb00::1:0/112 fe80::23 veth4 fb00::4:0,fb00::2:0 1 fb00::2:0,fb00::3:100,fb00::2:0 3000000

ip netns exec ns2 ip sr tunsrc set fb00::2:0
ip netns exec ns3 ip sr tunsrc set fb00::3:0

ip netns exec ns1 ip -6 route add fb00::/16 via fe80::21 dev veth1
ip netns exec ns2 ip -6 route add fb00::1:0/112 via fe80::12 dev veth2
ip netns exec ns2 ip -6 route add fb00::3:0/112 via fe80::32 dev veth3
ip netns exec ns2 ip -6 route add fb00::4:0/112 via fe80::42 dev veth5
ip netns exec ns3 ip -6 route add fb00::2:0/112 via fe80::23 dev veth4
ip netns exec ns3 ip -6 route add fb00::4:0/112 via fe80::43 dev veth8
ip netns exec ns3 ip -6 route add fb00::5:0/112 via fe80::53 dev veth9
ip netns exec ns4 ip -6 route add fb00::/16 via fe80::24 dev veth6
ip netns exec ns4 ip -6 route add fb00::3:0/112 via fe80::34 dev veth7
ip netns exec ns5 ip -6 route add fb00::/16 via fe80::35 dev veth10

#ip netns exec ns3 ping -I fb00::3:0 fb00::5:0
ip netns exec ns2 bash -c "mount -t bpf none /sys/fs/bpf && master/frr.py simulation/config-master.json"

exit 1
