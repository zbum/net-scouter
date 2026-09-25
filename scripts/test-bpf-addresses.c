// SPDX-License-Identifier: GPL-2.0
#define NET_SCOUTER_BPF_HOST_TEST 1
#include "../bpf/flow.bpf.c"

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
    return 0;
}
