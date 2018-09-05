#!/bin/bash

ip netns exec ns2 ip6tables -A FORWARD -i veth3 -j DROP
ip netns exec ns2 ip6tables -A INPUT -i veth3 -j DROP
