// SPDX-License-Identifier: GPL-2.0
#define NET_SCOUTER_BPF_HOST_TEST 1
#include "../bpf/flow.bpf.c"

static __u8 test_packet[256];
static __u32 test_packet_length;

static long load_test_packet(const struct __sk_buff *skb, __u32 offset,
                             void *destination, __u32 length)
{
    __u8 *output = destination;

    (void)skb;
    if (offset > test_packet_length || length > test_packet_length - offset)
        return -1;
    for (__u32 i = 0; i < length; i++)
        output[i] = test_packet[offset + i];
    return 0;
}

static void clear_test_packet(void)
{
    for (__u32 i = 0; i < sizeof(test_packet); i++)
        test_packet[i] = 0;
}

static void mapped_address(__u8 *address, __u8 a, __u8 b, __u8 c, __u8 d)
{
    address[10] = 0xff;
    address[11] = 0xff;
    address[12] = a;
    address[13] = b;
    address[14] = c;
    address[15] = d;
}

int main(void)
{
    struct socket_transition event = {
        .family = FLOW_FAMILY_IPV6,
        .sport = 41000,
        .dport = 443,
    };
    struct flow_key key = {.direction = FLOW_EGRESS};

    mapped_address(event.saddr, 192, 0, 2, 10);
    mapped_address(event.daddr, 198, 51, 100, 20);
    if (!set_connection_addresses(&key, &event) ||
        key.family != FLOW_FAMILY_IPV4 || key.src_addr[0] != 192 ||
        key.src_addr[3] != 10 || key.dst_addr[0] != 198 ||
        key.dst_addr[3] != 20 || key.src_addr[4] != 0 ||
        key.src_port != 41000 || key.dst_port != 443)
        return 1;

    key = (struct flow_key){.direction = FLOW_INGRESS};
    if (!set_connection_addresses(&key, &event) ||
        key.family != FLOW_FAMILY_IPV4 || key.src_addr[0] != 198 ||
        key.dst_addr[0] != 192 || key.src_port != 443 ||
        key.dst_port != 41000)
        return 2;

    event.daddr[10] = 0;
    key = (struct flow_key){.direction = FLOW_EGRESS};
    if (set_connection_addresses(&key, &event))
        return 3;

    event.saddr[10] = 0;
    event.saddr[0] = 0x20;
    event.saddr[1] = 0x01;
    event.daddr[0] = 0x20;
    event.daddr[1] = 0x01;
    if (!set_connection_addresses(&key, &event) ||
        key.family != FLOW_FAMILY_IPV6 || key.src_addr[0] != 0x20 ||
        key.dst_addr[0] != 0x20 || key.src_addr[15] != 10)
        return 4;

    event.family = FLOW_FAMILY_IPV4;
    event.saddr[0] = 192;
    event.saddr[1] = 0;
    event.saddr[2] = 2;
    event.saddr[3] = 10;
    event.daddr[0] = 198;
    event.daddr[1] = 51;
    event.daddr[2] = 100;
    event.daddr[3] = 20;
    if (!set_connection_addresses(&key, &event) ||
        key.family != FLOW_FAMILY_IPV4 || key.src_addr[0] != 192 ||
        key.dst_addr[0] != 198 || key.src_addr[4] != 0)
        return 5;

    bpf_skb_load_bytes = load_test_packet;
    struct __sk_buff skb = {};
    struct ipv4_hdr *ipv4 = (struct ipv4_hdr *)(test_packet + 14);
    struct ports_hdr *ports = (struct ports_hdr *)(test_packet + 34);

    clear_test_packet();
    test_packet_length = 38;
    skb.len = test_packet_length;
    ipv4->version_ihl = 0x45;
    ipv4->total_length = ntohs(24);
    ipv4->protocol = IPPROTO_TCP;
    ipv4->src[0] = 192;
    ipv4->dst[0] = 198;
    ports->src = ntohs(41000);
    ports->dst = ntohs(443);
    key = (struct flow_key){};
    if (!parse_ipv4(&skb, ipv4, 14, test_packet + test_packet_length, &key) ||
        key.family != FLOW_FAMILY_IPV4 || key.protocol != IPPROTO_TCP ||
        key.src_port != 41000 || key.dst_port != 443)
        return 6;

    test_packet_length = 37;
    skb.len = test_packet_length;
    if (parse_ipv4(&skb, ipv4, 14, test_packet + test_packet_length, &key))
        return 7;

    clear_test_packet();
    test_packet_length = 66;
    skb.len = test_packet_length;
    struct ipv6_hdr *ipv6 = (struct ipv6_hdr *)(test_packet + 14);
    struct ipv6_ext_hdr *extension =
        (struct ipv6_ext_hdr *)(test_packet + 54);
    ports = (struct ports_hdr *)(test_packet + 62);
    ipv6->version_class_flow = __builtin_bswap32(6U << 28);
    ipv6->payload_length = ntohs(12);
    ipv6->next_header = IPPROTO_HOPOPTS;
    extension->next_header = IPPROTO_UDP;
    extension->length = 0;
    ports->src = ntohs(5353);
    ports->dst = ntohs(53);
    key = (struct flow_key){};
    if (!parse_ipv6(&skb, ipv6, 14, test_packet + test_packet_length, &key) ||
        key.family != FLOW_FAMILY_IPV6 || key.protocol != IPPROTO_UDP ||
        key.src_port != 5353 || key.dst_port != 53)
        return 8;

    ipv6->payload_length = ntohs(8);
    if (parse_ipv6(&skb, ipv6, 14, test_packet + test_packet_length, &key))
        return 9;
    ipv6->payload_length = ntohs(13);
    if (parse_ipv6(&skb, ipv6, 14, test_packet + test_packet_length, &key))
        return 10;
    return 0;
}
