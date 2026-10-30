#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stddef.h>

int net_send_l3(int fd, const char *ifname, const uint8_t *pkt, size_t len,
                uint32_t dst);
int net_send_l3_v6(int fd, const char *ifname, const uint8_t *pkt, size_t len,
                   const uint8_t dst[16]);
int net_sniff_xid(const char *ifname, uint32_t *xid_out, uint32_t *client_ip);

#endif
