#ifndef GRAFT_H
#define GRAFT_H

#include <stdint.h>
#include <stddef.h>

#define GRAFT_EVENT_LEN 0x48
#define PB_LEN          0x50
#define PB_MAGIC        0x504d4b4f312d4445ULL   /* "ED-1OKMP" */

typedef struct {
  uint64_t signal_link_fwd;
  uint64_t signal_link_bwd;
  uint64_t notify_tpl;
  uint64_t notify_fn;
  uint64_t notify_ctx;
} graft_args_t;

size_t build_event_graft(uint8_t *out, size_t cap, const graft_args_t *a);

typedef struct {
  uint64_t graft;        /* &IEVENT  (== IcmpError + GRAFT_EVENT_OFF) */
  uint64_t event;        /* same address, kept separate for the banner */
  uint64_t shadow;       /* 0x48-byte pristine copy of the IEVENT */
  uint64_t uart;         /* MMIO base, 0 to disable */
  uint64_t uart_stride;  /* 1 for 16550 */
  uint64_t out_buf;      /* RAM sink, 0 to disable */
  uint64_t out_cap;
  uint64_t ranges;       /* array of {u64 start; u64 end;} */
  uint64_t range_n;
} param_block_t;

size_t build_param_block(uint8_t *out, size_t cap, const param_block_t *pb);

#endif
