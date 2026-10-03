#ifndef __NET_SCOUTER_FLOW_H
#define __NET_SCOUTER_FLOW_H

#include "vmlinux.h"

#define FLOW_INGRESS 1
#define FLOW_EGRESS  2
#define FLOW_FAMILY_IPV4 2
#define FLOW_FAMILY_IPV6 10

struct flow_key {
    __u8 family;
    __u8 protocol;
    __u8 direction;
    __u8 pad;
    __u8 src_addr[16];
    __u8 dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
};

struct flow_value {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 packets;
    __u64 bytes;
    __u64 connections;
};

struct host_addr_key {
    __u8 family;
    __u8 addr[16];
};

_Static_assert(sizeof(struct flow_key) == 40, "flow_key ABI size changed");
_Static_assert(sizeof(struct flow_value) == 40, "flow_value ABI size changed");
_Static_assert(sizeof(struct host_addr_key) == 17, "host_addr_key ABI size changed");

#endif
