.syntax unified
.thumb

# TH-D75 V1.03 closed-loop radio automation overlay.
#
# This overlay is applied to the exact, hardware-qualified V18 USB-storage
# recovery firmware.  It preserves both that firmware and the existing GM
# memory reader, then adds:
#
#   GM A000000\r   query the ABI and invalidate any guarded-input lease
#   GM SSSSSSS\r   capture one stable LCD frame (S + six-hex host sequence)
#   GM KHH,PSS\r   dispatch key HH, phase P, with two-hex host sequence
#   GM GHH,PSS\r   dispatch only if the live LCD still matches the snapshot
#   GM RDDD,SS\r   start-guarded atomic three-decimal-digit numeric route
#
# Each automation reply echoes the first ten request bytes, appends uppercase
# hexadecimal status/data bytes, and terminates with CR.  Ordinary thirteen-
# byte GM memory reads are forwarded byte-for-byte to the existing handler.
#
# Published snapshot apertures:
#
#   GM F00000,..\r   metadata, 0x100 bytes
#   GM F00100,..\r   stable 240x180 RGB565LE pixels, 0x15180 bytes
#   GM F15300,..\r   optional count:u8 + RGB565LE RLE records
#
# The apertures are backed by otherwise-FF loaded-image caves.  They do not
# expose the live framebuffer directly: the capture command copies the live
# framebuffer twice, requires both copies to compare equal, computes CRC-32
# over the raw copy, and only then marks the capture successful.  Snapshot B
# is reused after the comparison to publish bounded three-byte RLE records.

.extern svc_9r_read_handler
.extern cat_parse_hex_param
.extern cat_reply_hex_echo
.extern cat_error_reply
.extern memcpy_n
.extern input_dispatch

# "D75A" little-endian.
.equ AUTOMATION_MAGIC,              0x41353744
.equ AUTOMATION_ABI_VERSION,        3
.equ AUTOMATION_FEATURES,           0x0000007F
.equ AUTOMATION_MAX_KEY,            0x18
.equ AUTOMATION_MAX_PHASE,          2

.equ AUTOMATION_META,               0xC01A0000
.equ AUTOMATION_SNAPSHOT_A,         0xC01A0100
.equ AUTOMATION_SNAPSHOT_B,         0xC01B5300
.equ AUTOMATION_VIRTUAL_RAW_BASE,   0xC0F00000
.equ AUTOMATION_VIRTUAL_RAW_END,    0xC0F15280
.equ AUTOMATION_VIRTUAL_RLE_BASE,   0xC0F15300
.equ AUTOMATION_VIRTUAL_RLE_END,    0xC0F2A480
.equ AUTOMATION_RLE_OFFSET,         0x00015300
# "RLE3" little-endian: count:u8, pixel_lo:u8, pixel_hi:u8.
.equ AUTOMATION_RLE_MAGIC,          0x33454C52

.equ FRAMEBUFFER,                   0xC2349A40
.equ FRAME_WIDTH,                   240
.equ FRAME_HEIGHT,                  180
.equ FRAME_STRIDE,                  480
.equ FRAME_BYTES,                   0x15180
.equ FRAME_WORDS,                   0x5460
# "R565" little-endian.
.equ PIXEL_FORMAT_RGB565LE,         0x35363552
.equ MAX_CAPTURE_ATTEMPTS,          3

# Export the layout constants consumed by linker assertions and the build
# auditor.  They remain absolute symbols and allocate no image bytes.
.global FRAME_WIDTH
.global FRAME_HEIGHT
.global FRAME_STRIDE
.global FRAME_BYTES
.global FRAME_WORDS
.global AUTOMATION_META
.global AUTOMATION_SNAPSHOT_A
.global AUTOMATION_SNAPSHOT_B
.global AUTOMATION_RLE_OFFSET
.global AUTOMATION_VIRTUAL_RAW_BASE
.global AUTOMATION_VIRTUAL_RAW_END
.global AUTOMATION_VIRTUAL_RLE_BASE
.global AUTOMATION_VIRTUAL_RLE_END

# Metadata offsets.  The complete record is exactly 0x100 bytes.
.equ META_MAGIC,                    0x00
.equ META_ABI_VERSION,              0x04
.equ META_SEQUENCE,                 0x08
.equ META_FEATURES,                 0x0C
.equ META_WIDTH,                    0x10
.equ META_HEIGHT,                   0x14
.equ META_STRIDE,                   0x18
.equ META_PIXEL_FORMAT,             0x1C
.equ META_PIXEL_LENGTH,             0x20
.equ META_PIXEL_OFFSET,             0x24
.equ META_GENERATION,               0x28
.equ META_CAPTURE_RESULT,           0x2C
.equ META_CRC32,                    0x30
.equ META_CAPTURE_ATTEMPTS,         0x34
.equ META_COMMAND_COUNT,            0x38
.equ META_LAST_COMMAND,             0x3C
.equ META_LAST_HOST_SEQUENCE,       0x40
.equ META_LAST_KEY,                 0x44
.equ META_LAST_PHASE,               0x48
.equ META_LAST_KEY_RESULT,          0x4C
.equ META_FRAMEBUFFER_ADDRESS,      0x50
.equ META_SNAPSHOT_ADDRESS,         0x54
.equ META_LIMITS,                   0x58
.equ META_RLE_MAGIC,                0x5C
.equ META_RLE_OFFSET,               0x60
.equ META_RLE_LENGTH,               0x64
.equ META_ROUTE_DIGITS,             0x68
.equ META_ROUTE_GUARD_ATTEMPTS,     0x6C
.equ META_ROUTE_COMPLETED_TAPS,     0x70
.equ META_ROUTE_EVENT_MASK,         0x74
.equ META_TRAILING_MAGIC,           0xFC

.equ COMMAND_QUERY,                 0
.equ COMMAND_SNAPSHOT,              1
.equ COMMAND_KEY,                   2
.equ COMMAND_GUARDED_KEY,           3
.equ COMMAND_GUARDED_ROUTE,         4
.equ RESULT_OK,                     0
.equ RESULT_UNSTABLE,               1
.equ RESULT_CONTEXT_CHANGED,        2
.equ RESULT_BUSY,                   0xFFFFFFFF

# Retarget only the BL inside the already-qualified fourteen-byte GM adapter.
# The adapter itself still retains R2, writes dispatcher status 2, and returns.
.section .gm_adapter_call, "ax", %progbits
.balign 2
.global gm_adapter_call
gm_adapter_call:
    bl      automation_dispatch

# Replace only the existing memcpy call in the widened DDR reader.  The
# original argument setup and reply construction remain untouched.
.section .gm_read_call, "ax", %progbits
.balign 2
.global gm_read_call
gm_read_call:
    bl      automation_memory_copy

.section .automation_runtime, "ax", %progbits
.balign 4

# R0=request, R1=request length.  R2 remains the outer adapter's completion
# pointer but is deliberately not used here; the adapter retained it in R4.
.global automation_dispatch
.thumb_func
automation_dispatch:
    push    {r3-r7, lr}
    sub     sp, #16
    movs    r4, r0
    movs    r5, r1

    # Preserve the exact existing GM memory-reader grammar.
    cmp     r5, #13
    beq     automation_forward_memory_read

    # Every automation command is exactly eleven bytes.
    cmp     r5, #11
    bne     automation_header_invalid
    ldrb    r0, [r4, #2]
    cmp     r0, #0x20
    bne     automation_header_invalid
    ldrb    r0, [r4, #10]
    cmp     r0, #0x0D
    bne     automation_header_invalid
    ldrb    r0, [r4, #3]
    # 'A'
    cmp     r0, #0x41
    beq     automation_query
    # 'S'
    cmp     r0, #0x53
    beq     automation_snapshot_command
    # 'K'
    cmp     r0, #0x4B
    beq     automation_key_command
    # 'G'
    cmp     r0, #0x47
    beq     automation_guarded_key_command
    # 'R'
    cmp     r0, #0x52
    beq     automation_guarded_route_command
    b       automation_invalid

automation_header_invalid:
    b       automation_invalid

automation_forward_memory_read:
    movs    r0, r4
    movs    r1, r5
    bl      svc_9r_read_handler
    b       automation_dispatch_return

automation_query:
    # The query grammar is deliberately one exact string.
    movs    r1, #4
automation_query_zero_loop:
    ldrb    r0, [r4, r1]
    # '0'
    cmp     r0, #0x30
    bne     automation_invalid
    adds    r1, #1
    cmp     r1, #10
    bne     automation_query_zero_loop
    # Qualification is a fail-closed session boundary.  Invalidate any
    # previously published guarded-input context before returning the ABI so
    # a repeated qualifier can never inherit an old snapshot lease.
    bl      automation_query_invalidate
    movs    r0, r4
    adr     r1, automation_info
    movs    r2, #8
    bl      cat_reply_hex_echo
    b       automation_dispatch_return

automation_snapshot_command:
    # Parse and retain all six sequence digits.  The stock parser is strict
    # hexadecimal; the exact command length and CR were checked above.
    add     r0, sp, #4
    movs    r1, r4
    adds    r1, #4
    movs    r2, #6
    bl      cat_parse_hex_param
    cmp     r0, #1
    bne     automation_invalid
    ldr     r0, [sp, #4]
    bl      automation_capture
    movs    r6, r0
    mov     r1, sp
    strb    r6, [r1]
    movs    r0, r4
    mov     r1, sp
    movs    r2, #1
    bl      cat_reply_hex_echo
    b       automation_dispatch_return

automation_key_command:
    movs    r0, #0
    str     r0, [sp, #12]
    b       automation_key_parse

automation_guarded_key_command:
    movs    r0, #1
    str     r0, [sp, #12]

automation_key_parse:
    ldrb    r0, [r4, #6]
    # ','
    cmp     r0, #0x2C
    bne     automation_invalid

    # HH: bounded raw key identifier.
    add     r0, sp, #4
    movs    r1, r4
    adds    r1, #4
    movs    r2, #2
    bl      cat_parse_hex_param
    cmp     r0, #1
    bne     automation_invalid
    ldr     r6, [sp, #4]
    cmp     r6, #AUTOMATION_MAX_KEY
    bhi     automation_invalid

    # P: explicit press/release/repeat phase.
    ldrb    r7, [r4, #7]
    subs    r7, #0x30
    cmp     r7, #AUTOMATION_MAX_PHASE
    bhi     automation_invalid

    # SS: host sequence, echoed by the reply and recorded in metadata.
    add     r0, sp, #8
    movs    r1, r4
    adds    r1, #8
    movs    r2, #2
    bl      cat_parse_hex_param
    cmp     r0, #1
    bne     automation_invalid

    movs    r0, r6
    movs    r1, r7
    ldr     r2, [sp, #8]
    ldr     r0, [sp, #12]
    cmp     r0, #0
    beq     automation_key_dispatch_unconditional
    movs    r0, r6
    bl      automation_guarded_key_event
    b       automation_key_dispatch_done
automation_key_dispatch_unconditional:
    movs    r0, r6
    bl      automation_key_event
automation_key_dispatch_done:
    movs    r6, r0
    mov     r1, sp
    strb    r6, [r1]
    movs    r0, r4
    mov     r1, sp
    movs    r2, #1
    bl      cat_reply_hex_echo
    b       automation_dispatch_return

automation_guarded_route_command:
    # DDD is strictly decimal.  Retain the raw ASCII bytes, packed little-
    # endian, so the seqlocked receipt authenticates the exact route prefix.
    ldrb    r6, [r4, #4]
    movs    r0, r6
    subs    r0, #0x30
    cmp     r0, #9
    bhi     automation_invalid
    ldrb    r0, [r4, #5]
    movs    r1, r0
    subs    r1, #0x30
    cmp     r1, #9
    bhi     automation_invalid
    lsls    r0, r0, #8
    orrs    r6, r0
    ldrb    r0, [r4, #6]
    movs    r1, r0
    subs    r1, #0x30
    cmp     r1, #9
    bhi     automation_invalid
    lsls    r0, r0, #16
    orrs    r6, r0
    ldrb    r0, [r4, #7]
    # ','
    cmp     r0, #0x2C
    bne     automation_invalid

    # SS is the same strict two-hex host sequence used by key commands.
    add     r0, sp, #8
    movs    r1, r4
    adds    r1, #8
    movs    r2, #2
    bl      cat_parse_hex_param
    cmp     r0, #1
    bne     automation_invalid

    movs    r0, r6
    ldr     r1, [sp, #8]
    bl      automation_guarded_route
    movs    r6, r0
    mov     r1, sp
    strb    r6, [r1]
    movs    r0, r4
    mov     r1, sp
    movs    r2, #1
    bl      cat_reply_hex_echo
    b       automation_dispatch_return

automation_invalid:
    bl      cat_error_reply

automation_dispatch_return:
    add     sp, #16
    pop     {r3-r7, pc}

.balign 4
automation_info:
    # "D75A"
    .byte   0x44, 0x37, 0x35, 0x41
    .byte   AUTOMATION_ABI_VERSION
    .byte   AUTOMATION_FEATURES
    .byte   AUTOMATION_MAX_KEY
    .byte   AUTOMATION_MAX_PHASE

# Initialize the metadata record once per boot.  Its trailing magic catches a
# partial/overlapping writer rather than accepting only the first word.
.global automation_metadata_prepare
.thumb_func
automation_metadata_prepare:
    push    {r4-r7, lr}
    sub     sp, #4
    ldr     r4, =AUTOMATION_META
    ldr     r5, =AUTOMATION_MAGIC
    ldr     r0, [r4, #META_MAGIC]
    cmp     r0, r5
    bne     automation_metadata_clear
    movs    r0, r4
    adds    r0, #META_TRAILING_MAGIC
    ldr     r0, [r0]
    cmp     r0, r5
    bne     automation_metadata_clear
    ldr     r0, [r4, #META_ABI_VERSION]
    cmp     r0, #AUTOMATION_ABI_VERSION
    bne     automation_metadata_clear
    ldr     r0, [r4, #META_FEATURES]
    cmp     r0, #AUTOMATION_FEATURES
    bne     automation_metadata_clear
    ldr     r0, [r4, #META_RLE_MAGIC]
    ldr     r1, =AUTOMATION_RLE_MAGIC
    cmp     r0, r1
    bne     automation_metadata_clear
    ldr     r0, [r4, #META_RLE_OFFSET]
    ldr     r1, =AUTOMATION_RLE_OFFSET
    cmp     r0, r1
    beq     automation_metadata_ready

automation_metadata_clear:
    movs    r0, #0
    movs    r1, #0x40
    movs    r2, r4
automation_metadata_clear_loop:
    str     r0, [r2]
    adds    r2, #4
    subs    r1, #1
    bne     automation_metadata_clear_loop

    str     r5, [r4, #META_MAGIC]
    movs    r0, #AUTOMATION_ABI_VERSION
    str     r0, [r4, #META_ABI_VERSION]
    movs    r0, #AUTOMATION_FEATURES
    str     r0, [r4, #META_FEATURES]
    movs    r0, #FRAME_WIDTH
    str     r0, [r4, #META_WIDTH]
    movs    r0, #FRAME_HEIGHT
    str     r0, [r4, #META_HEIGHT]
    ldr     r0, =FRAME_STRIDE
    str     r0, [r4, #META_STRIDE]
    ldr     r0, =PIXEL_FORMAT_RGB565LE
    str     r0, [r4, #META_PIXEL_FORMAT]
    ldr     r0, =FRAME_BYTES
    str     r0, [r4, #META_PIXEL_LENGTH]
    movs    r0, #1
    lsls    r0, r0, #8
    str     r0, [r4, #META_PIXEL_OFFSET]
    ldr     r0, =FRAMEBUFFER
    str     r0, [r4, #META_FRAMEBUFFER_ADDRESS]
    ldr     r0, =AUTOMATION_SNAPSHOT_A
    str     r0, [r4, #META_SNAPSHOT_ADDRESS]
    movs    r0, #AUTOMATION_MAX_KEY
    movs    r1, #AUTOMATION_MAX_PHASE
    lsls    r1, r1, #8
    orrs    r0, r1
    str     r0, [r4, #META_LIMITS]
    ldr     r0, =AUTOMATION_RLE_MAGIC
    str     r0, [r4, #META_RLE_MAGIC]
    ldr     r0, =AUTOMATION_RLE_OFFSET
    str     r0, [r4, #META_RLE_OFFSET]
    # A zero RLE length always means "read the raw snapshot".  Likewise, an
    # initialized-but-never-captured record must not claim RESULT_OK.
    movs    r0, #0
    str     r0, [r4, #META_RLE_LENGTH]
    movs    r0, #RESULT_UNSTABLE
    str     r0, [r4, #META_CAPTURE_RESULT]
    movs    r0, r4
    adds    r0, #META_TRAILING_MAGIC
    str     r5, [r0]

automation_metadata_ready:
    add     sp, #4
    pop     {r4-r7, pc}

# Begin/end the record's seqlock.  The exclusive host issues automation
# requests sequentially; the seqlock protects it from stale or partial reads.
.global automation_metadata_begin
.thumb_func
automation_metadata_begin:
    ldr     r0, =AUTOMATION_META
    ldr     r1, [r0, #META_SEQUENCE]
    adds    r1, #1
    movs    r2, #1
    orrs    r1, r2
    str     r1, [r0, #META_SEQUENCE]
    ldr     r1, [r0, #META_COMMAND_COUNT]
    adds    r1, #1
    str     r1, [r0, #META_COMMAND_COUNT]
    # Route receipts never leak into another accepted S/K/G/R command.
    movs    r1, #0
    str     r1, [r0, #META_ROUTE_DIGITS]
    str     r1, [r0, #META_ROUTE_GUARD_ATTEMPTS]
    str     r1, [r0, #META_ROUTE_COMPLETED_TAPS]
    str     r1, [r0, #META_ROUTE_EVENT_MASK]
    bx      lr

.global automation_metadata_end
.thumb_func
automation_metadata_end:
    ldr     r0, =AUTOMATION_META
    ldr     r1, [r0, #META_SEQUENCE]
    adds    r1, #1
    str     r1, [r0, #META_SEQUENCE]
    bx      lr

# Invalidate guarded-input context for the exact ABI query.  The prior raw
# bytes and generation may remain for forensic continuity, but capture result,
# CRC, and RLE length make them unusable.  All observable metadata changes are
# one seqlocked command record; this routine never samples the framebuffer or
# calls the stock input dispatcher.
.global automation_query_invalidate
.thumb_func
automation_query_invalidate:
    push    {r4, lr}
    bl      automation_metadata_prepare
    bl      automation_metadata_begin
    ldr     r4, =AUTOMATION_META
    movs    r0, #RESULT_UNSTABLE
    str     r0, [r4, #META_CAPTURE_RESULT]
    movs    r0, #0
    str     r0, [r4, #META_CRC32]
    str     r0, [r4, #META_CAPTURE_ATTEMPTS]
    str     r0, [r4, #META_LAST_COMMAND]
    str     r0, [r4, #META_LAST_HOST_SEQUENCE]
    str     r0, [r4, #META_LAST_KEY]
    str     r0, [r4, #META_LAST_PHASE]
    str     r0, [r4, #META_LAST_KEY_RESULT]
    str     r0, [r4, #META_RLE_LENGTH]
    bl      automation_metadata_end
    pop     {r4, pc}

# R0=key, R1=phase, R2=host sequence.  Return RESULT_OK after the stock
# dispatcher returns.  Whether the active UI accepted the event is established
# independently from the subsequent screen snapshot, never inferred here.
.global automation_key_event
.thumb_func
automation_key_event:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    bl      automation_metadata_prepare
    bl      automation_metadata_begin
    ldr     r7, =AUTOMATION_META
    movs    r0, #COMMAND_KEY
    str     r0, [r7, #META_LAST_COMMAND]
    str     r6, [r7, #META_LAST_HOST_SEQUENCE]
    str     r4, [r7, #META_LAST_KEY]
    str     r5, [r7, #META_LAST_PHASE]
    ldr     r0, =RESULT_BUSY
    str     r0, [r7, #META_LAST_KEY_RESULT]
    movs    r0, r4
    movs    r1, r5
    bl      input_dispatch
    movs    r0, #RESULT_OK
    str     r0, [r7, #META_LAST_KEY_RESULT]
    bl      automation_metadata_end
    movs    r0, #RESULT_OK
    pop     {r3-r7, pc}

# R0=key, R1=phase, R2=host sequence.  A guarded key is dispatched only when
# the live framebuffer still exactly matches the last successful stable
# snapshot.  Sampling, offline comparison, and input_dispatch are sequential
# in one CAT handler, not atomic against a preemptive framebuffer writer.  A
# changed, absent, or unstable sample returns RESULT_CONTEXT_CHANGED without
# calling the stock input dispatcher.
.global automation_guarded_key_event
.thumb_func
automation_guarded_key_event:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    bl      automation_metadata_prepare
    bl      automation_metadata_begin
    ldr     r7, =AUTOMATION_META
    movs    r0, #COMMAND_GUARDED_KEY
    str     r0, [r7, #META_LAST_COMMAND]
    str     r6, [r7, #META_LAST_HOST_SEQUENCE]
    str     r4, [r7, #META_LAST_KEY]
    str     r5, [r7, #META_LAST_PHASE]
    ldr     r0, =RESULT_BUSY
    str     r0, [r7, #META_LAST_KEY_RESULT]

    # Snapshot B is scratch for the live comparison, so its former RLE view
    # is invalid from this point onward.  Raw snapshot A remains published.
    movs    r0, #0
    str     r0, [r7, #META_RLE_LENGTH]
    bl      automation_guard_snapshot
    cmp     r0, #RESULT_OK
    bne     automation_guarded_key_refuse

    movs    r0, r4
    movs    r1, r5
    bl      input_dispatch
    movs    r0, #RESULT_OK
    str     r0, [r7, #META_LAST_KEY_RESULT]
    bl      automation_metadata_end
    movs    r0, #RESULT_OK
    pop     {r3-r7, pc}

automation_guarded_key_refuse:
    movs    r0, #RESULT_CONTEXT_CHANGED
    str     r0, [r7, #META_LAST_KEY_RESULT]
    bl      automation_metadata_end
    movs    r0, #RESULT_CONTEXT_CHANGED
    pop     {r3-r7, pc}

# Sample the complete live framebuffer into snapshot B and compare that offline
# copy with the last successful raw snapshot A.  R0 returns RESULT_OK only for
# exact equality.  The copy, comparison, and caller's subsequent synchronous
# dispatch are sequential, but a preemptive framebuffer writer can still run
# between them; callers must not describe this as an atomic framebuffer guard.
.global automation_guard_snapshot
.thumb_func
automation_guard_snapshot:
    push    {r3-r7, lr}
    ldr     r4, =AUTOMATION_META
    ldr     r0, [r4, #META_CAPTURE_RESULT]
    cmp     r0, #RESULT_OK
    bne     automation_guard_snapshot_changed
    ldr     r0, =AUTOMATION_SNAPSHOT_B
    ldr     r1, =FRAMEBUFFER
    ldr     r2, =FRAME_BYTES
    bl      memcpy_n
    ldr     r4, =AUTOMATION_SNAPSHOT_A
    ldr     r5, =AUTOMATION_SNAPSHOT_B
    ldr     r6, =FRAME_WORDS
automation_guard_snapshot_compare:
    ldr     r0, [r4]
    ldr     r1, [r5]
    cmp     r0, r1
    bne     automation_guard_snapshot_changed
    adds    r4, #4
    adds    r5, #4
    subs    r6, #1
    bne     automation_guard_snapshot_compare
    movs    r0, #RESULT_OK
    pop     {r3-r7, pc}
automation_guard_snapshot_changed:
    movs    r0, #RESULT_CONTEXT_CHANGED
    pop     {r3-r7, pc}

# R0=packed ASCII D0|D1<<8|D2<<16, R1=host sequence.  Compare one complete
# guard sample before the first digit, then synchronously dispatch all three
# press/release pairs with no host turn between them.  The radio redraws its
# numeric-entry state after the first digit, so comparing later digits with the
# original top-level Menu snapshot would reject that intended transition.  A
# refusal therefore always has an empty prefix; success is all six events.
.global automation_guarded_route
.thumb_func
automation_guarded_route:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    bl      automation_metadata_prepare
    bl      automation_metadata_begin
    ldr     r7, =AUTOMATION_META
    movs    r0, #COMMAND_GUARDED_ROUTE
    str     r0, [r7, #META_LAST_COMMAND]
    str     r5, [r7, #META_LAST_HOST_SEQUENCE]
    str     r4, [r7, #META_ROUTE_DIGITS]
    ldr     r0, =RESULT_BUSY
    str     r0, [r7, #META_LAST_KEY_RESULT]
    # Every guard sample reuses snapshot B, invalidating its former RLE view.
    movs    r0, #0
    str     r0, [r7, #META_RLE_LENGTH]
    movs    r6, #3

automation_guarded_route_digit:
    # Publish the current digit before its synchronous press/release pair.
    movs    r0, r4
    lsls    r0, r0, #24
    lsrs    r0, r0, #24
    subs    r0, #0x30
    adds    r0, #0x0A
    str     r0, [r7, #META_LAST_KEY]
    movs    r1, #0
    str     r1, [r7, #META_LAST_PHASE]

    # Only the first iteration compares the authenticated start context.  A
    # refusal therefore names digit zero and proves that no input ran.
    cmp     r6, #3
    bne     automation_guarded_route_dispatch
    movs    r1, #1
    str     r1, [r7, #META_ROUTE_GUARD_ATTEMPTS]
    bl      automation_guard_snapshot
    cmp     r0, #RESULT_OK
    bne     automation_guarded_route_refuse

automation_guarded_route_dispatch:
    ldr     r0, [r7, #META_LAST_KEY]
    movs    r1, #0
    bl      input_dispatch
    # Since events are strictly sequential, (mask << 1) | 1 sets the next
    # press/release bit: bit 2*i is press and bit 2*i+1 is release.
    ldr     r0, [r7, #META_ROUTE_EVENT_MASK]
    lsls    r0, r0, #1
    adds    r0, #1
    str     r0, [r7, #META_ROUTE_EVENT_MASK]

    ldr     r0, [r7, #META_LAST_KEY]
    movs    r1, #1
    str     r1, [r7, #META_LAST_PHASE]
    bl      input_dispatch
    ldr     r0, [r7, #META_ROUTE_EVENT_MASK]
    lsls    r0, r0, #1
    adds    r0, #1
    str     r0, [r7, #META_ROUTE_EVENT_MASK]
    ldr     r0, [r7, #META_ROUTE_COMPLETED_TAPS]
    adds    r0, #1
    str     r0, [r7, #META_ROUTE_COMPLETED_TAPS]
    lsrs    r4, r4, #8
    subs    r6, #1
    bne     automation_guarded_route_digit

    movs    r0, #RESULT_OK
    str     r0, [r7, #META_LAST_KEY_RESULT]
    bl      automation_metadata_end
    movs    r0, #RESULT_OK
    pop     {r3-r7, pc}

automation_guarded_route_refuse:
    movs    r0, #RESULT_CONTEXT_CHANGED
    str     r0, [r7, #META_LAST_KEY_RESULT]
    bl      automation_metadata_end
    movs    r0, #RESULT_CONTEXT_CHANGED
    pop     {r3-r7, pc}

# R0=host sequence.  Return RESULT_OK only after two consecutive full-frame
# copies compare equal.  Three bounded attempts prevent an animated or actively
# redrawing screen from monopolizing the CAT task.
.global automation_capture
.thumb_func
automation_capture:
    push    {r3-r7, lr}
    movs    r4, r0
    bl      automation_metadata_prepare
    bl      automation_metadata_begin
    ldr     r5, =AUTOMATION_META
    movs    r0, #COMMAND_SNAPSHOT
    str     r0, [r5, #META_LAST_COMMAND]
    str     r4, [r5, #META_LAST_HOST_SEQUENCE]
    ldr     r0, =RESULT_BUSY
    str     r0, [r5, #META_CAPTURE_RESULT]
    movs    r0, #0
    str     r0, [r5, #META_CAPTURE_ATTEMPTS]
    str     r0, [r5, #META_RLE_LENGTH]
    movs    r7, #MAX_CAPTURE_ATTEMPTS

automation_capture_attempt:
    ldr     r0, [r5, #META_CAPTURE_ATTEMPTS]
    adds    r0, #1
    str     r0, [r5, #META_CAPTURE_ATTEMPTS]

    ldr     r0, =AUTOMATION_SNAPSHOT_A
    ldr     r1, =FRAMEBUFFER
    ldr     r2, =FRAME_BYTES
    bl      memcpy_n
    ldr     r0, =AUTOMATION_SNAPSHOT_B
    ldr     r1, =FRAMEBUFFER
    ldr     r2, =FRAME_BYTES
    bl      memcpy_n

    ldr     r3, =AUTOMATION_SNAPSHOT_A
    ldr     r4, =AUTOMATION_SNAPSHOT_B
    ldr     r6, =FRAME_WORDS
automation_capture_compare:
    ldr     r0, [r3]
    ldr     r1, [r4]
    cmp     r0, r1
    bne     automation_capture_mismatch
    adds    r3, #4
    adds    r4, #4
    subs    r6, #1
    bne     automation_capture_compare
    b       automation_capture_stable

automation_capture_mismatch:
    subs    r7, #1
    bne     automation_capture_attempt
    movs    r0, #RESULT_UNSTABLE
    str     r0, [r5, #META_CAPTURE_RESULT]
    movs    r0, #0
    str     r0, [r5, #META_CRC32]
    bl      automation_metadata_end
    movs    r0, #RESULT_UNSTABLE
    pop     {r3-r7, pc}

automation_capture_stable:
    # Snapshot B is no longer needed for comparison after equality succeeds.
    # Encode from stable raw A into B.  The encoder returns zero instead of
    # crossing B's exact FRAME_BYTES capacity, preserving the raw fallback.
    bl      automation_rle_encode
    str     r0, [r5, #META_RLE_LENGTH]
    ldr     r0, =AUTOMATION_SNAPSHOT_A
    ldr     r1, =FRAME_BYTES
    bl      automation_crc32
    str     r0, [r5, #META_CRC32]
    ldr     r0, [r5, #META_GENERATION]
    adds    r0, #1
    str     r0, [r5, #META_GENERATION]
    movs    r0, #RESULT_OK
    str     r0, [r5, #META_CAPTURE_RESULT]
    bl      automation_metadata_end
    movs    r0, #RESULT_OK
    pop     {r3-r7, pc}

# Standard reflected CRC-32 (IEEE polynomial), R0=data, R1=length, R0=result.
.global automation_crc32
.thumb_func
automation_crc32:
    push    {r3-r7, lr}
    movs    r4, #0
    mvns    r4, r4
    movs    r5, r0
    movs    r6, r1
    ldr     r7, =0xEDB88320
automation_crc32_byte:
    cmp     r6, #0
    beq     automation_crc32_done
    ldrb    r0, [r5]
    eors    r4, r0
    movs    r1, #8
automation_crc32_bit:
    lsrs    r4, r4, #1
    bcc     automation_crc32_no_xor
    eors    r4, r7
automation_crc32_no_xor:
    subs    r1, #1
    bne     automation_crc32_bit
    adds    r5, #1
    subs    r6, #1
    b       automation_crc32_byte
automation_crc32_done:
    movs    r0, r4
    mvns    r0, r0
    pop     {r3-r7, pc}

# Encode stable raw snapshot A into snapshot B.
#
# Each record is exactly count:u8 + RGB565LE:u16.  Counts are 1..255.
# R0 returns the encoded byte length, or zero if another complete record would
# exceed B's exact FRAME_BYTES capacity.  No metadata is touched here.
.global automation_rle_encode
.thumb_func
automation_rle_encode:
    push    {r3-r7, lr}
    ldr     r4, =AUTOMATION_SNAPSHOT_A
    ldr     r5, =AUTOMATION_SNAPSHOT_A + FRAME_BYTES
    ldr     r6, =AUTOMATION_SNAPSHOT_B
    ldr     r7, =AUTOMATION_SNAPSHOT_B + FRAME_BYTES

automation_rle_next:
    cmp     r4, r5
    beq     automation_rle_done
    movs    r0, r6
    adds    r0, #3
    cmp     r0, r7
    bhi     automation_rle_overflow

    ldrh    r1, [r4]
    adds    r4, #2
    movs    r2, #1

automation_rle_run:
    cmp     r4, r5
    beq     automation_rle_emit
    cmp     r2, #255
    beq     automation_rle_emit
    ldrh    r3, [r4]
    cmp     r3, r1
    bne     automation_rle_emit
    adds    r4, #2
    adds    r2, #1
    b       automation_rle_run

automation_rle_emit:
    strb    r2, [r6]
    strb    r1, [r6, #1]
    lsrs    r1, r1, #8
    strb    r1, [r6, #2]
    adds    r6, #3
    b       automation_rle_next

automation_rle_done:
    ldr     r0, =AUTOMATION_SNAPSHOT_B
    subs    r0, r6, r0
    pop     {r3-r7, pc}

automation_rle_overflow:
    movs    r0, #0
    pop     {r3-r7, pc}

# Drop-in replacement for memcpy_n at C006F8AC.
#
# R0=destination, R1=CPU source, R2=length.  Reads wholly inside either exact
# virtual automation aperture are translated to stable raw or RLE storage.
# Every other request retains the exact existing DDR-reader behavior.
.global automation_memory_copy
.thumb_func
automation_memory_copy:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    ldr     r7, =AUTOMATION_VIRTUAL_RAW_BASE
    cmp     r5, r7
    bcc     automation_memory_copy_rle
    movs    r3, r5
    adds    r3, r3, r6
    bcs     automation_memory_copy_rle
    ldr     r0, =AUTOMATION_VIRTUAL_RAW_END
    cmp     r3, r0
    bhi     automation_memory_copy_rle
    subs    r1, r5, r7
    ldr     r0, =AUTOMATION_META
    adds    r1, r1, r0
    movs    r0, r4
    movs    r2, r6
    bl      memcpy_n
    pop     {r3-r7, pc}

automation_memory_copy_rle:
    ldr     r7, =AUTOMATION_VIRTUAL_RLE_BASE
    cmp     r5, r7
    bcc     automation_memory_copy_normal
    movs    r3, r5
    adds    r3, r3, r6
    bcs     automation_memory_copy_normal
    ldr     r0, =AUTOMATION_VIRTUAL_RLE_END
    cmp     r3, r0
    bhi     automation_memory_copy_normal
    subs    r1, r5, r7
    ldr     r0, =AUTOMATION_SNAPSHOT_B
    adds    r1, r1, r0
    movs    r0, r4
    movs    r2, r6
    bl      memcpy_n
    pop     {r3-r7, pc}

automation_memory_copy_normal:
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    bl      memcpy_n
    pop     {r3-r7, pc}

.ltorg
