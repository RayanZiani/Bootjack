#ifndef UART_H
#define UART_H

#include <stdint.h>
#include <stddef.h>
#include <termios.h>

/* Host-side serial used for both directions: the transmitter watches the
 * firmware console, the receiver collects the dump.  The name is historical;
 * the device may be a socket or a file. */
int  uart_open(const char *path, int baud);

int  raw_send_l3(int fd, const char *ifname, const uint8_t *pkt, size_t len,
                 uint32_t dst, uint32_t src);
int  raw_send_l3_v6(int fd, const char *ifname, const uint8_t *pkt, size_t len,
                    const uint8_t dst[16]);
int  sniff_xid(const char *ifname, uint32_t *xid_out, uint32_t *client_ip_out);

#endif
