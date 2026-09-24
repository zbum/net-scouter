// SPDX-License-Identifier: GPL-2.0
#include "flow.h"

#ifdef NET_SCOUTER_BPF_HOST_TEST
#define SEC(name) __attribute__((used))
#else
#define SEC(name) __attribute__((section(name), used))
#endif
#define __always_inline inline __attribute__((always_inline))
#define TC_ACT_OK 0
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_HASH 1
#define BPF_NOEXIST 1
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88a8
#define IPPROTO_HOPOPTS 0
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_AH 51
#define IPPROTO_DSTOPTS 60
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3
#define TCP_NEW_SYN_RECV 12

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
};

struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct eth_hdr { __u8 dst[6]; __u8 src[6]; __u16 protocol; };
struct vlan_hdr { __u16 tci; __u16 protocol; };
struct ipv4_hdr {
    __u8 version_ihl;
    __u8 tos;
    __u16 total_length;
    __u16 id;
    __u16 fragment_offset;
    __u8 ttl;
    __u8 protocol;
    __u16 checksum;
    __u8 src[4];
    __u8 dst[4];
};
struct ipv6_hdr {
    __u32 version_class_flow;
    __u16 payload_length;
    __u8 next_header;
    __u8 hop_limit;
    __u8 src[16];
    __u8 dst[16];
};
struct ipv6_ext_hdr { __u8 next_header; __u8 length; };
struct ipv6_fragment_hdr {
    __u8 next_header;
    __u8 reserved;
    __u16 fragment_offset;
    __u32 identification;
};
struct ports_hdr { __u16 src; __u16 dst; };

/* Linux v4.18 uses an 8-bit protocol field (address offset 31). */
struct inet_sock_set_state_v4_18 {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __u32 common_pid;
    __u64 skaddr;
    __u32 oldstate;
    __u32 newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

/* Linux v5.15 uses a 16-bit protocol field (address offset 32). */
struct inet_sock_set_state_v5_15 {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __u32 common_pid;
    __u64 skaddr;
    __u32 oldstate;
    __u32 newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct socket_transition {
    __u32 oldstate;
    __u32 newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[16];
    __u8 daddr[16];
};

_Static_assert(__builtin_offsetof(struct inet_sock_set_state_v4_18,
                                  oldstate) == 16,
               "unexpected v4.18 oldstate offset");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_v4_18,
                                  protocol) == 30,
               "unexpected v4.18 protocol offset");
_Static_assert(sizeof(((struct inet_sock_set_state_v4_18 *)0)->protocol) == 1,
               "unexpected v4.18 protocol size");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_v4_18,
                                  saddr) == 31,
               "unexpected v4.18 address offset");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_v4_18,
                                  daddr_v6) == 55,
               "unexpected v4.18 IPv6 address offset");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_v5_15,
                                  oldstate) == 16,
               "unexpected v5.15 oldstate offset");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_v5_15,
                                  protocol) == 30,
               "unexpected v5.15 protocol offset");
_Static_assert(sizeof(((struct inet_sock_set_state_v5_15 *)0)->protocol) == 2,
               "unexpected v5.15 protocol size");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_v5_15,
                                  saddr) == 32,
               "unexpected v5.15 address offset");
_Static_assert(__builtin_offsetof(struct inet_sock_set_state_v5_15,
                                  daddr_v6) == 56,
               "unexpected v5.15 IPv6 address offset");

struct bpf_map_def SEC("maps") flows = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct flow_key),
    .value_size = sizeof(struct flow_value),
    .max_entries = 65536,
};

struct capture_cfg {
    __u8 ipv4;
    __u8 ipv6;
    __u8 tcp;
    __u8 udp;
};

struct bpf_map_def SEC("maps") capture_cfg = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct capture_cfg),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") host_addrs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct host_addr_key),
    .value_size = sizeof(__u8),
    .max_entries = 256,
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;

static __always_inline __u16 ntohs(__u16 value)
{
    return __builtin_bswap16(value);
}

static __always_inline void copy_addr(__u8 *dst, const __u8 *src, __u32 length)
{
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < 16; i++)
        dst[i] = i < length ? src[i] : 0;
}

/* Ephemeral source ports are not an ACL identity. */
static __always_inline void drop_ephemeral_source_port(struct flow_key *key)
{
    if (key->protocol == IPPROTO_TCP || key->protocol == IPPROTO_UDP)
        key->src_port = 0;
}

/* A low source port answering a high destination port is the service
 * sending back to a client. ACL does not track that direction. */
static __always_inline int reply_to_client(const struct flow_key *key)
{
    if (key->src_port == 0 || key->src_port >= 1024 || key->dst_port < 32768)
        return 0;
    return 1;
}

static __always_inline int parse_ports(void *cursor, void *packet_end,
                                       void *data_end,
                                       struct flow_key *key)
{
    struct ports_hdr *ports = cursor;

    if ((void *)(ports + 1) > packet_end ||
        (void *)(ports + 1) > data_end)
        return 0;
    key->src_port = ntohs(ports->src);
    key->dst_port = ntohs(ports->dst);
    return 1;
}

static __always_inline int parse_ipv4(void *cursor, void *data_end,
                                      struct flow_key *key)
{
    struct ipv4_hdr *ip = cursor;
    __u32 header_length;
    __u32 total_length;
    void *packet_end;

    if ((void *)(ip + 1) > data_end || (ip->version_ihl >> 4) != 4)
        return 0;
    header_length = (ip->version_ihl & 0x0f) * 4;
    total_length = ntohs(ip->total_length);
    if (header_length < sizeof(*ip) ||
        total_length < header_length + sizeof(struct ports_hdr) ||
        cursor + total_length > data_end)
        return 0;
    packet_end = cursor + total_length;
    /* Non-initial fragments do not carry transport ports. */
    if (ntohs(ip->fragment_offset) & 0x1fff)
        return 0;
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return 0;

    key->family = FLOW_FAMILY_IPV4;
    key->protocol = ip->protocol;
    copy_addr(key->src_addr, ip->src, 4);
    copy_addr(key->dst_addr, ip->dst, 4);
    return parse_ports(cursor + header_length, packet_end, data_end, key);
}

static __always_inline int parse_ipv6(void *cursor, void *data_end,
                                      struct flow_key *key)
{
    struct ipv6_hdr *ip = cursor;
    __u8 next_header;
    __u32 payload_length;
    void *packet_end;

    if ((void *)(ip + 1) > data_end ||
        (__builtin_bswap32(ip->version_class_flow) >> 28) != 6)
        return 0;
    payload_length = ntohs(ip->payload_length);
    /* IPv6 jumbograms require hop-by-hop option parsing that is not supported. */
    if (payload_length == 0 || (void *)(ip + 1) + payload_length > data_end)
        return 0;
    packet_end = (void *)(ip + 1) + payload_length;

    key->family = FLOW_FAMILY_IPV6;
    copy_addr(key->src_addr, ip->src, 16);
    copy_addr(key->dst_addr, ip->dst, 16);
    next_header = ip->next_header;
    cursor = ip + 1;

#pragma clang loop unroll(full)
    for (int i = 0; i < 6; i++) {
        struct ipv6_ext_hdr *ext;
        __u32 length;

        if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP) {
            key->protocol = next_header;
            return parse_ports(cursor, packet_end, data_end, key);
        }
        if (next_header == IPPROTO_FRAGMENT) {
            struct ipv6_fragment_hdr *fragment = cursor;

            if ((void *)(fragment + 1) > packet_end ||
                (void *)(fragment + 1) > data_end)
                return 0;
            if (ntohs(fragment->fragment_offset) & 0xfff8)
                return 0;
            next_header = fragment->next_header;
            cursor = fragment + 1;
            continue;
        }
        if (next_header != IPPROTO_HOPOPTS && next_header != IPPROTO_ROUTING &&
            next_header != IPPROTO_DSTOPTS && next_header != IPPROTO_AH)
            return 0;

        ext = cursor;
        if ((void *)(ext + 1) > packet_end ||
            (void *)(ext + 1) > data_end)
            return 0;
        length = next_header == IPPROTO_AH ? ((__u32)ext->length + 2) * 4
                                           : ((__u32)ext->length + 1) * 8;
        if (length < sizeof(*ext) || cursor + length > packet_end ||
            cursor + length > data_end)
            return 0;
        next_header = ext->next_header;
        cursor += length;
    }
    return 0;
}

static __always_inline void update_flow(struct flow_value *value, __u64 now,
                                        __u64 bytes)
{
    /* Best effort: concurrent CPUs may publish timestamps out of order. */
    value->last_seen_ns = now;
    __sync_fetch_and_add(&value->packets, 1);
    __sync_fetch_and_add(&value->bytes, bytes);
}

static __always_inline int capture_allowed(__u8 family, __u8 protocol)
{
    __u32 index = 0;
    struct capture_cfg *cfg = bpf_map_lookup_elem(&capture_cfg, &index);

    /* A missing config keeps observation working. The loader writes it before attach. */
    if (!cfg)
        return 1;
    if (family == FLOW_FAMILY_IPV4 && !cfg->ipv4)
        return 0;
    if (family == FLOW_FAMILY_IPV6 && !cfg->ipv6)
        return 0;
    if (protocol == IPPROTO_TCP && !cfg->tcp)
        return 0;
    if (protocol == IPPROTO_UDP && !cfg->udp)
        return 0;
    return 1;
}

static __always_inline int host_address_allowed(const struct flow_key *key)
{
    struct host_addr_key local = {.family = key->family};
    const __u8 *address;

    if (key->direction == FLOW_EGRESS)
        address = key->src_addr;
    else if (key->direction == FLOW_INGRESS)
        address = key->dst_addr;
    else
        return 0;
    copy_addr(local.addr, address, 16);
    return bpf_map_lookup_elem(&host_addrs, &local) != 0;
}

static __always_inline int ipv4_mapped(const __u8 *address)
{
#pragma clang loop unroll(full)
    for (int i = 0; i < 10; i++) {
        if (address[i] != 0)
            return 0;
    }
    return address[10] == 0xff && address[11] == 0xff;
}

static __always_inline int set_connection_addresses(struct flow_key *key,
                                                     const struct socket_transition *event)
{
    const __u8 *source = event->saddr;
    const __u8 *destination = event->daddr;
    __u32 length;

    if (event->family == FLOW_FAMILY_IPV4) {
        key->family = FLOW_FAMILY_IPV4;
        length = 4;
    } else if (event->family == FLOW_FAMILY_IPV6) {
        int source_mapped = ipv4_mapped(source);
        int destination_mapped = ipv4_mapped(destination);

        /* Mixed mapped/native endpoints do not define a canonical IPv4 tuple. */
        if (source_mapped != destination_mapped)
            return 0;
        if (source_mapped) {
            key->family = FLOW_FAMILY_IPV4;
            source += 12;
            destination += 12;
            length = 4;
        } else {
            key->family = FLOW_FAMILY_IPV6;
            length = 16;
        }
    } else {
        return 0;
    }

    if (key->direction == FLOW_EGRESS) {
        copy_addr(key->src_addr, source, length);
        copy_addr(key->dst_addr, destination, length);
        key->src_port = event->sport;
        key->dst_port = event->dport;
    } else if (key->direction == FLOW_INGRESS) {
        copy_addr(key->src_addr, destination, length);
        copy_addr(key->dst_addr, source, length);
        key->src_port = event->dport;
        key->dst_port = event->sport;
    } else {
        return 0;
    }
    return 1;
}

static __always_inline void aggregate(const struct flow_key *key, __u64 bytes)
{
    struct flow_value *current;
    __u64 now = bpf_ktime_get_ns();

    current = bpf_map_lookup_elem(&flows, key);
    if (current) {
        update_flow(current, now, bytes);
        return;
    }

    struct flow_value initial = {
        .first_seen_ns = now,
        .last_seen_ns = now,
        .packets = 1,
        .bytes = bytes,
    };
    if (bpf_map_update_elem(&flows, key, &initial, BPF_NOEXIST) == 0)
        return;

    /* Another CPU won BPF_NOEXIST; account for this packet in its entry. */
    current = bpf_map_lookup_elem(&flows, key);
    if (current)
        update_flow(current, now, bytes);
}

static __always_inline void aggregate_connection(const struct flow_key *key)
{
    struct flow_value *current;
    __u64 now = bpf_ktime_get_ns();

    current = bpf_map_lookup_elem(&flows, key);
    if (current) {
        current->last_seen_ns = now;
        __sync_fetch_and_add(&current->connections, 1);
        return;
    }

    /* Preserve a completed connection even if its packet entry was evicted. */
    struct flow_value initial = {
        .first_seen_ns = now,
        .last_seen_ns = now,
        .connections = 1,
    };
    if (bpf_map_update_elem(&flows, key, &initial, BPF_NOEXIST) == 0)
        return;

    current = bpf_map_lookup_elem(&flows, key);
    if (current) {
        current->last_seen_ns = now;
        __sync_fetch_and_add(&current->connections, 1);
    }
}

static __always_inline int count_tcp_connection(struct socket_transition *event)
{
    struct flow_key key = {};

    if (event->protocol != IPPROTO_TCP || event->newstate != TCP_ESTABLISHED)
        return 0;

    key.protocol = IPPROTO_TCP;
    if (event->oldstate == TCP_SYN_SENT) {
        key.direction = FLOW_EGRESS;
    } else if (event->oldstate == TCP_SYN_RECV ||
               event->oldstate == TCP_NEW_SYN_RECV) {
        key.direction = FLOW_INGRESS;
    } else {
        return 0;
    }

    if (!set_connection_addresses(&key, event)) {
        return 0;
    }

    if (!capture_allowed(key.family, key.protocol) ||
        !host_address_allowed(&key))
        return 0;
    drop_ephemeral_source_port(&key);
    aggregate_connection(&key);
    return 0;
}

/*
 * Both ABI variants are loadable but must never be attached together. The
 * future loader selects exactly one after reading tracefs' event format:
 * protocol size 1/saddr offset 31 selects tcp_conn_u8; size 2/offset 32
 * selects tcp_conn_u16, then explicitly attaches it to
 * sock:inet_sock_set_state. An unknown format disables connection counting.
 */
/* Unique ELF sections keep both entry programs independently selectable. */
SEC("tracepoint/sock/inet_sock_set_state_u8")
int tcp_conn_u8(struct inet_sock_set_state_v4_18 *event)
{
    struct socket_transition transition = {
        .oldstate = event->oldstate,
        .newstate = event->newstate,
        .sport = event->sport,
        .dport = event->dport,
        .family = event->family,
        .protocol = event->protocol,
    };

    if (event->family == FLOW_FAMILY_IPV4) {
        copy_addr(transition.saddr, event->saddr, 4);
        copy_addr(transition.daddr, event->daddr, 4);
    } else if (event->family == FLOW_FAMILY_IPV6) {
        copy_addr(transition.saddr, event->saddr_v6, 16);
        copy_addr(transition.daddr, event->daddr_v6, 16);
    }
    return count_tcp_connection(&transition);
}

SEC("tracepoint/sock/inet_sock_set_state_u16")
int tcp_conn_u16(struct inet_sock_set_state_v5_15 *event)
{
    struct socket_transition transition = {
        .oldstate = event->oldstate,
        .newstate = event->newstate,
        .sport = event->sport,
        .dport = event->dport,
        .family = event->family,
        .protocol = event->protocol,
    };

    if (event->family == FLOW_FAMILY_IPV4) {
        copy_addr(transition.saddr, event->saddr, 4);
        copy_addr(transition.daddr, event->daddr, 4);
    } else if (event->family == FLOW_FAMILY_IPV6) {
        copy_addr(transition.saddr, event->saddr_v6, 16);
        copy_addr(transition.daddr, event->daddr_v6, 16);
    }
    return count_tcp_connection(&transition);
}

static __always_inline int observe(struct __sk_buff *skb, __u8 direction)
{
    void *data = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;
    struct eth_hdr *eth = data;
    struct flow_key key = {};
    __u16 protocol;
    void *cursor;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    protocol = ntohs(eth->protocol);
    cursor = eth + 1;

#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        struct vlan_hdr *vlan;

        if (protocol != ETH_P_8021Q && protocol != ETH_P_8021AD)
            break;
        vlan = cursor;
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        protocol = ntohs(vlan->protocol);
        cursor = vlan + 1;
    }

    key.direction = direction;
    if ((protocol == ETH_P_IP && parse_ipv4(cursor, data_end, &key)) ||
        (protocol == ETH_P_IPV6 && parse_ipv6(cursor, data_end, &key))) {
        if (capture_allowed(key.family, key.protocol) &&
            host_address_allowed(&key) && !reply_to_client(&key)) {
            drop_ephemeral_source_port(&key);
            aggregate(&key, skb->len);
        }
    }
    return TC_ACT_OK;
}

SEC("classifier/ingress")
int observe_ingress(struct __sk_buff *skb)
{
    return observe(skb, FLOW_INGRESS);
}

SEC("classifier/egress")
int observe_egress(struct __sk_buff *skb)
{
    return observe(skb, FLOW_EGRESS);
}

char LICENSE[] SEC("license") = "GPL";
