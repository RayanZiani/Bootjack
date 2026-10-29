/* uart.c - raw ICMP transport, no kernel ICMP stack involved.
 *
 * Two reasons not to use a SOCK_RAW ICMP socket:
 *   1. the kernel rewrites/normalises the ICMP header for ICMP errors,
 *   2. we need a source address that is not ours (the PXE client's gateway).
 * So we build the whole IP datagram and send it with IP_HDRINCL, or send the
 * bare ICMP message over a raw socket on platforms that allow it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <linux/if_packet.h>
#include <net/ethernet.h>
#endif

#include "uart.h"

int uart_open(const char *path, int baud)
{
  struct termios tio;
  int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
  if (fd < 0) {
    perror(path);
    return -1;
  }
  if (tcgetattr(fd, &tio) < 0) { close(fd); return -1; }
  cfmakeraw(&tio);
  tio.c_cflag |= CLOCAL | CREAD;
  tio.c_cflag &= ~CRTSCTS;
  tio.c_cc[VMIN]  = 0;
  tio.c_cc[VTIME] = 1;
  cfsetispeed(&tio, baud);
  cfsetospeed(&tio, baud);
  if (tcsetattr(fd, TCSANOW, &tio) < 0) { close(fd); return -1; }
  tcflush(fd, TCIOFLUSH);
  return fd;
}

/* Send a fully-formed L3 datagram (IP header included) with a spoofed source.
 * Requires CAP_NET_RAW.  We bind to the egress interface so the kernel picks
 * the right route and does not emit an ICMP redirect for the spoofed source. */
int raw_send_l3(int fd, const char *ifname, const uint8_t *pkt, size_t len,
                uint32_t dst, uint32_t src)
{
  struct sockaddr_in sin;
  int one = 1;

  (void)src;
  if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("IP_HDRINCL");
    return -1;
  }
  if (ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
      perror("SO_BINDTODEVICE");   /* non fatal: route still works */
  }
  memset(&sin, 0, sizeof(sin));
  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = dst;
  return sendto(fd, pkt, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0
             ? -1 : 0;
}

int raw_send_l3_v6(int fd, const char *ifname, const uint8_t *pkt, size_t len,
                   const uint8_t dst[16])
{
  struct sockaddr_in6 sin6;
  int one = 1;
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one)) < 0) {
    perror("IPV6_HDRINCL");
    return -1;
  }
  if (ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
  }
  memset(&sin6, 0, sizeof(sin6));
  sin6.sin6_family = AF_INET6;
  memcpy(&sin6.sin6_addr, dst, 16);
  return sendto(fd, pkt, len, 0, (struct sockaddr *)&sin6, sizeof(sin6)) < 0
             ? -1 : 0;
}

/* PXE client's in-flight DHCP transaction id, needed to make the ICMP error
 * match the driver's armed receive token.  sniffer.c fills this in from a
 * passive capture of the DHCPDISCOVER/REQUEST on the same segment. */
int sniff_xid(const char *ifname, uint32_t *xid_out, uint32_t *client_ip_out)
{
#ifdef __linux__
  int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
  struct sockaddr_ll sll;
  uint8_t buf[2048];
  time_t deadline = time(NULL) + 30;

  if (fd < 0) { perror("AF_PACKET"); return -1; }
  memset(&sll, 0, sizeof(sll));
  sll.sll_family   = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_IP);
  sll.sll_ifindex  = (int)if_nametoindex(ifname);
  if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind"); close(fd); return -1;
  }

  while (time(NULL) < deadline) {
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n < 42) { usleep(20000); continue; }
    /* buf[0..] is the IPv4 header for SOCK_DGRAM on AF_PACKET */
    uint8_t  proto = buf[9];
    size_t   ihl   = (size_t)(buf[0] & 0x0f) * 4;
    if (proto != 17 || (size_t)n < ihl + 8 + 8) continue;
    const uint8_t *udp = buf + ihl;
    uint16_t sport = (uint16_t)(udp[0] << 8 | udp[1]);
    uint16_t dport = (uint16_t)(udp[2] << 8 | udp[3]);
    if (dport != 67 && sport != 67) continue;
    const uint8_t *bootp = udp + 8;
    if ((size_t)(bootp - buf) + 8 > (size_t)n) continue;
    *xid_out = (uint32_t)bootp[4] << 24 | (uint32_t)bootp[5] << 16 |
               (uint32_t)bootp[6] << 8  | (uint32_t)bootp[7];
    if (client_ip_out) {
      memcpy(client_ip_out, buf + 12, 4);   /* fall back to src */
    }
    close(fd);
    return 0;
  }
  close(fd);
  return -1;
#else
  (void)ifname; (void)xid_out; (void)client_ip_out;
  return -1;
#endif
}
