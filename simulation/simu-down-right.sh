#!/bin/bash

ip netns exec ns2 ip6tables -A FORWARD -o veth3 -j DROP
ip netns exec ns2 ip6tables -A OUTPUT -o veth3 -j DROP
