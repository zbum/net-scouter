#ifndef __NET_SCOUTER_FLOW_H
#define __NET_SCOUTER_FLOW_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

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

_Static_assert(sizeof(struct flow_key) == 40, "flow_key ABI size changed");
_Static_assert(sizeof(struct flow_value) == 40, "flow_value ABI size changed");

#endif
