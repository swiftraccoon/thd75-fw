.syntax unified
.thumb

.extern menu_usb_apply
.extern usb_mode_event
.extern storage_set_desired
.extern storage_unmount
.extern storage_cleanup
.extern storage_notify
.extern storage_lease_control
.extern storage_driver_control
.extern storage_irq_control
.extern storage_shutdown_notify
.extern msc_readiness_probe
.extern msc_partition_read
.extern msc_worker_startup
.extern media_status_dispatch
.extern physical_read
.extern physical_command
.extern physical_count
.extern msc_send_data
.extern storage_power_control
.extern usb_phy_reset
.extern command_sem_wait
.extern phase2_skip

.section .trigger, "ax", %progbits
.balign 2
.global trigger
.thumb_func
trigger:
    push    {r3-r5, lr}
    movs    r5, r2
    movs    r4, #2
    cmp     r1, #5
    bne     trigger_complete
    ldrb    r3, [r0, #2]
    cmp     r3, #0x20
    bne     trigger_complete
    ldrb    r3, [r0, #3]
    cmp     r3, #0x32
    bne     trigger_complete
    ldrb    r3, [r0, #4]
    cmp     r3, #0x0d
    bne     trigger_complete
    movs    r0, #2
    bl      menu_usb_apply
trigger_complete:
    strb    r4, [r5]
    pop     {r0, r4, r5, pc}

.global attach_result_wrapper
.thumb_func
attach_result_wrapper:
    cmp     r2, #0
    bne     attach_failed
    movs    r1, #2
    push    {r3, lr}
    bl      usb_mode_event
    pop     {r3, pc}
attach_failed:
    bx      lr

.global stock_storage_path
.thumb_func
stock_storage_path:
    movs    r0, #0x5f
    bl      storage_set_desired
    pop     {r1, r4, r5, pc}
    .hword  0x46c0

.section .gw_entry, "ax", %progbits
.balign 2
.global gw_entry
.thumb_func
gw_entry:
    # Fixed 16-bit B to C002EC0E.
    .hword  0xe451

.section .storage_helper, "ax", %progbits
.balign 2
.global storage_helper
.thumb_func
storage_helper:
    push    {r3-r5, lr}
    # PC-aligned C002F370 + 0xDE*4 = C002F6E8 (USB-state pointer).
    .hword  0x4CDE
    ldrb    r0, [r4]
    # C23E5C68 - 0xFF - 0x35 = storage-state base C23E5B34.
    subs    r4, #0xff
    subs    r4, #0x35
    ldrb    r1, [r4, #5]
    # Normalize the only two handoff states: 2 -> 0, 3 -> 1. State 4 fails;
    # states 0, 1, and 5 retain their stock raw/no-media recovery behavior.
    subs    r1, #2
    beq     storage_transition
    cmp     r1, #2
    beq     storage_failed
    bhi     storage_stock
    # State 3 with no active USB class still needs a live LBA-0 probe. Class 1
    # is an in-progress/incompatible handoff and fails closed; class 2 is the
    # already-constructed MSC replug path and remains stock-idempotent.
    subs    r0, #1
    beq     storage_failed
    bcc     storage_apply
storage_stock:
    # Fixed 16-bit B to C002EC42.
    .hword  0xe45d

storage_transition:
    # A real state-2 handoff must start before any USB class is active.
    cmp     r0, #0
    bne     storage_failed
    strb    r0, [r4, #4]
storage_apply:
    movs    r0, #0x5f
    # Arm the one handoff-specific shutdown token before the corrected
    # state-3 publisher can notify its asynchronous listeners.
    bl      storage_set_desired_handoff
    # The enclosing storage task powers group 0 off immediately after this
    # helper returns.  A readiness probe here would therefore qualify hardware
    # state that is guaranteed to be invalidated before MSC phase 2.  Preserve
    # the exact section footprint and return the unmount result unchanged; the
    # one definitive probe now runs after the final phase-2 power/reset work.
    b       storage_return
    .hword  0x46c0
    .hword  0x46c0
    .hword  0x46c0
storage_return:
    pop     {r1, r4, r5, pc}
storage_failed:
    movs    r0, #1
    b       storage_return
    .hword  0x46c0

.section .storage_set_desired, "ax", %progbits
.balign 2
.global storage_set_desired_fixed
.thumb_func
storage_set_desired_fixed:
    push    {r3-r5, lr}
    # Retain the stock 16-bit literal load from C008D832. It resolves to the
    # untouched storage-state pointer literal at C008D8C8.
    .hword  0x4C25
    bl      storage_unmount
    movs    r5, r0
    bl      storage_cleanup
    orrs    r5, r0
    beq     storage_success
    movs    r0, #4
    movs    r5, #1
    b       storage_publish
storage_success:
    movs    r0, #3
    movs    r5, #0
storage_publish:
    strb    r0, [r4, #5]
    # Convert a handoff-pending marker into the one-shot shutdown token at the
    # last synchronous point before the exact state-3 broadcast.
    bl      storage_notify_handoff
    movs    r0, r5
    pop     {r1, r4, r5, pc}
    .hword  0x46c0

.section .storage_call, "ax", %progbits
.balign 2
.global storage_call
.thumb_func
storage_call:
    ldrh    r0, [r5]
    bl      storage_helper

.section .attach_call, "ax", %progbits
.balign 2
.global attach_call
.thumb_func
attach_call:
    ldrb    r2, [r0, #0x0c]
    movs    r0, #9
    bl      attach_result_wrapper

.section .phase2_gate, "ax", %progbits
.balign 2
.global phase2_gate
.thumb_func
phase2_gate:
    # Replace C017D99E..C017D9A5.  The wrapper performs the original USB reset
    # and returns the untouched C017250C constructor arguments only after it
    # has armed the stock tMscSmp startup-readiness path.
    bl      phase2_storage_requalify
    cmp     r0, #0
    # Fixed 16-bit BEQ to C017D9B0.
    .hword  0xd004

.section .storage_lease_call, "ax", %progbits
.balign 2
.global storage_lease_call
.thumb_func
storage_lease_call:
    # Replace C017D992's raw group-0 request with a counted lifetime lease.
    # If phase 2 preempts the enclosing storage task this changes 1 -> 2; if
    # that task already released, it changes 0 -> 1 and performs the same
    # physical power-on as stock.
    bl      phase2_storage_acquire

.section .teardown_call, "ax", %progbits
.balign 2
.global teardown_call
.thumb_func
teardown_call:
    # C017D956 is the common group-4 power-off call after any class-specific
    # teardown.  Preserve it, then release V14's checked group-0 lease.
    bl      usb_group4_off_and_release_lease

.section .gw_literal, "a", %progbits
.balign 4
.global usb_state_pointer
usb_state_pointer:
    .word   0xC23E5C68

.section .msc_probe, "ax", %progbits
.balign 4
.global msc_host_readiness_probe
.thumb_func
msc_host_readiness_probe:
    push    {r3, lr}
    bl      msc_readiness_probe
    cmp     r0, #0
    bne     msc_host_readiness_return
    ldr     r2, msc_buffer
    movs    r0, #0
    movs    r1, #1
    bl      msc_partition_read
msc_host_readiness_return:
    pop     {r3, pc}
    .hword  0x46c0
.balign 4
msc_buffer:
    .word   0xC3E70000

.section .media_status_guard, "ax", %progbits
.balign 2
.global media_status_guard
.thumb_func
media_status_guard:
    # Stock branches from C0171B5C to C0171B64 when the backend media-status
    # callback itself fails.  That path erases the geometry which the
    # fail-closed preflight just populated, and the MSC command dispatcher
    # ignores this helper's error return.  Preserve the known-good geometry by
    # returning at C0171B6C instead.  The separate, successful media-change
    # path still reaches C0171B64 and retains stock card-removal handling.
    .hword  0xD106

.section .gm_ddr_base, "ax", %progbits
.balign 2
.global gm_ddr_base
.thumb_func
gm_ddr_base:
    # Temporarily restore the hardware-qualified GM reader's DDR base so the
    # diagnostic record at C019D000 can be retrieved over Bluetooth while MSC
    # owns USB.  This remains a read-only command.
    movs    r6, #0xc0

.section .media_status_call, "ax", %progbits
.balign 2
.global media_status_call
.thumb_func
media_status_call:
    bl      media_status_telemetry

.section .read10_backend_call, "ax", %progbits
.balign 2
.global read10_backend_call
.thumb_func
read10_backend_call:
    bl      read10_worker_lease_telemetry

.section .worker_startup_call, "ax", %progbits
.balign 2
.global worker_startup_call
.thumb_func
worker_startup_call:
    bl      worker_startup_telemetry

.section .physical_read_call, "ax", %progbits
.balign 2
.global physical_read_call
.thumb_func
physical_read_call:
    bl      physical_read

.section .capacity_count_fix, "ax", %progbits
.balign 2
.global capacity_count_fix
.thumb_func
capacity_count_fix:
    # C0101174 loads the MBR partition-size field, which is already a sector
    # count.  Stock then adds one before publishing it at backend +0x14,
    # causing READ CAPACITY to expose one nonexistent terminal LBA.  Preserve
    # the parsed count verbatim.  This also remains correct after every stock
    # geometry refresh, unlike a later cache clamp.
    .hword  0x46c0

.section .shutdown_gate, "ax", %progbits
.balign 2
.global shutdown_gate
.thumb_func
shutdown_gate:
    # C00D95CE begins the delayed state-3 storage shutdown.  Consume the
    # one-shot handoff token and bypass its hardware-off tail.  The token is
    # created only at the last synchronous point before the successful USB
    # state-3 broadcast, so this is independent of which task runs first.  A
    # return of one falls through to the untouched stock IRQ/power teardown;
    # zero branches to the stock logical-state clear.
    bl      storage_shutdown_guard
    cmp     r0, #0
    # Fixed 16-bit BEQ to C00D95EC.
    .hword  0xd00a

.section .physical_command_single_call, "ax", %progbits
.balign 2
.global physical_command_single_call
.thumb_func
physical_command_single_call:
    bl      physical_command_telemetry

.section .physical_count_single_call, "ax", %progbits
.balign 2
.global physical_count_single_call
.thumb_func
physical_count_single_call:
    bl      physical_count_telemetry

.section .physical_command_multi_call, "ax", %progbits
.balign 2
.global physical_command_multi_call
.thumb_func
physical_command_multi_call:
    bl      physical_command

.section .physical_count_multi_call, "ax", %progbits
.balign 2
.global physical_count_multi_call
.thumb_func
physical_count_multi_call:
    bl      physical_count_multi_telemetry

.section .read10_send_call, "ax", %progbits
.balign 2
.global read10_send_call
.thumb_func
read10_send_call:
    bl      read10_send_telemetry

.section .runtime_telemetry, "ax", %progbits
.balign 4

# Initialize the 0x100-byte diagnostic record exactly once after boot.  The
# record lives in an otherwise-FF, loaded DDR cave and is never used as USB
# transfer storage.
.global telemetry_prepare
.thumb_func
telemetry_prepare:
    ldr     r0, =0xC019D000
    ldr     r1, [r0]
    # "V16T" in little endian.
    ldr     r2, =0x54363156
    cmp     r1, r2
    beq     telemetry_prepare_done
    movs    r1, #0
    # 0x100 / sizeof(uint32_t).
    movs    r3, #0x40
telemetry_clear_loop:
    str     r1, [r0]
    adds    r0, #4
    subs    r3, #1
    bne     telemetry_clear_loop
    ldr     r0, =0xC019D000
    str     r2, [r0]
telemetry_prepare_done:
    bx      lr

# C0171B56 originally calls C017271E(backend).  Preserve its exact return and
# record the callback result plus the backend state consumed by C0171B40.
.global media_status_telemetry
.thumb_func
media_status_telemetry:
    push    {r3-r5, lr}
    movs    r4, r0
    bl      telemetry_prepare
    ldr     r0, =0xC019D0FC
    ldr     r0, [r0]
    cmp     r0, #0
    bne     media_status_passthrough
    ldr     r3, =0xC019D000
    ldr     r0, [r3, #0x04]
    adds    r0, #1
    str     r0, [r3, #0x04]
    movs    r0, r4
    bl      media_status_dispatch
    movs    r5, r0
    ldr     r3, =0xC019D000
    str     r4, [r3, #0x08]
    str     r5, [r3, #0x0c]
    cmp     r4, #0
    beq     media_status_no_backend
    ldr     r0, [r4, #0x30]
    str     r0, [r3, #0x10]
    ldr     r0, [r4, #0x44]
    str     r0, [r3, #0x14]
    ldr     r0, [r4, #0x38]
    str     r0, [r3, #0x18]
media_status_no_backend:
    ldr     r0, =0xC23E5E20
    ldr     r0, [r0]
    str     r0, [r3, #0x1c]
    movs    r0, r5
    pop     {r3-r5, pc}
media_status_passthrough:
    movs    r0, r4
    bl      media_status_dispatch
    pop     {r3-r5, pc}

# C017205A originally calls C0171BAC(lba, count, buffer).  The nested physical
# wrapper below records the actual raw-device call.  This wrapper also records
# cached geometry before/after and the backend state after the call.
.global partition_read_telemetry
.thumb_func
partition_read_telemetry:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    bl      telemetry_prepare
    ldr     r0, =0xC019D0FC
    ldr     r0, [r0]
    cmp     r0, #0
    bne     partition_read_passthrough
    ldr     r7, =0xC019D020
    ldr     r0, [r7, #0x00]
    adds    r0, #1
    str     r0, [r7, #0x00]
    movs    r0, #1
    str     r0, [r7, #0x04]
    str     r4, [r7, #0x08]
    str     r5, [r7, #0x0c]
    str     r6, [r7, #0x10]
    ldr     r3, =0xC2213F60
    ldr     r0, [r3, #0x14]
    str     r0, [r7, #0x14]
    ldr     r0, [r3, #0x18]
    str     r0, [r7, #0x18]
    ldr     r0, [r3, #0x1c]
    str     r0, [r7, #0x1c]
    ldr     r0, [r3, #0x20]
    str     r0, [r7, #0x20]
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    bl      msc_partition_read
    movs    r4, r0
    str     r4, [r7, #0x24]
    movs    r0, #4
    str     r0, [r7, #0x04]
    ldr     r3, =0xC2213F60
    ldr     r0, [r3, #0x14]
    str     r0, [r7, #0x28]
    ldr     r0, [r3, #0x18]
    str     r0, [r7, #0x2c]
    ldr     r0, [r3, #0x1c]
    str     r0, [r7, #0x30]
    ldr     r0, [r3, #0x20]
    str     r0, [r7, #0x34]
    ldr     r0, =0xC23E5C2C
    ldr     r0, [r0]
    str     r0, [r7, #0x38]
    cmp     r0, #0
    beq     partition_read_no_backend
    ldr     r1, [r0, #0x30]
    str     r1, [r7, #0x3c]
    ldr     r1, [r0, #0x44]
    str     r1, [r7, #0x40]
    ldr     r1, [r0, #0x38]
    str     r1, [r7, #0x44]
partition_read_no_backend:
    ldr     r0, =0xC23E5E20
    ldr     r0, [r0]
    str     r0, [r7, #0x48]
    movs    r0, r4
    pop     {r3-r7, pc}
partition_read_passthrough:
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    bl      msc_partition_read
    pop     {r3-r7, pc}

# C01011E8 originally calls C00FE524 with a fifth byte-count argument at
# [sp].  The six-word push preserves 8-byte alignment; its saved-r3 word is
# deliberately reused as the outgoing fifth argument for the nested call.
.global physical_read_telemetry
.thumb_func
physical_read_telemetry:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    movs    r7, r3
    bl      telemetry_prepare
    ldr     r0, =0xC019D0FC
    ldr     r0, [r0]
    cmp     r0, #0
    bne     physical_read_passthrough
    # Only the READ10 partition wrapper sets stage 1.  The boot preflight also
    # reaches this shared physical call site, but must not populate a record
    # that could be mistaken for a host transaction which failed above it.
    ldr     r0, =0xC019D000
    ldr     r1, [r0, #0x24]
    cmp     r1, #1
    bne     physical_read_passthrough
    ldr     r3, =0xC019D070
    ldr     r0, [r3, #0x00]
    adds    r0, #1
    str     r0, [r3, #0x00]
    str     r4, [r3, #0x04]
    str     r5, [r3, #0x08]
    str     r6, [r3, #0x0c]
    str     r7, [r3, #0x10]
    ldr     r0, [sp, #0x18]
    str     r0, [r3, #0x14]
    movs    r0, #0
    str     r0, [r3, #0x18]
    str     r0, [r3, #0x1c]
    str     r0, [r3, #0x20]
    str     r0, [r3, #0x24]
    str     r0, [r3, #0x28]
    str     r0, [r3, #0x2c]
    str     r0, [r3, #0x30]
    str     r0, [r3, #0x34]
    str     r0, [r3, #0x38]
    ldr     r0, =0xC019D000
    movs    r1, #2
    str     r1, [r0, #0x24]
    ldr     r3, =0xC019D070
    ldr     r0, =0xC23E4AD4
    ldr     r1, [r0, #0x14]
    str     r1, [r3, #0x1c]
    cmp     r1, #0
    beq     physical_read_call_original
    ldr     r2, [r0, #0x28]
    str     r2, [r3, #0x20]
    cmp     r4, #0
    bmi     physical_read_call_original
    cmp     r4, r2
    bge     physical_read_call_original
    lsls    r1, r4, #2
    adds    r0, r0, r1
    ldr     r1, [r0, #0x18]
    str     r1, [r3, #0x24]
    ldr     r2, [r0, #0x20]
    str     r2, [r3, #0x28]
    cmp     r1, #0
    beq     physical_read_call_original
    ldr     r0, [r1, #0x0c]
    str     r0, [r3, #0x2c]
    ldrb    r0, [r1, #0x10]
    str     r0, [r3, #0x30]
    ldr     r0, [r1, #0x40]
    str     r0, [r3, #0x34]
    ldr     r0, [r1, #0x50]
    str     r0, [r3, #0x38]
physical_read_call_original:
    ldr     r3, [sp, #0x18]
    str     r3, [sp, #0x00]
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    movs    r3, r7
    bl      physical_read
    movs    r4, r0
    ldr     r1, =0xC019D070
    str     r4, [r1, #0x18]
    ldr     r1, =0xC019D000
    movs    r0, #3
    str     r0, [r1, #0x24]
    movs    r0, r4
    pop     {r3-r7, pc}
physical_read_passthrough:
    ldr     r3, [sp, #0x18]
    str     r3, [sp, #0x00]
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    movs    r3, r7
    bl      physical_read
    pop     {r3-r7, pc}

# C00FE5AA calls C00FE11C with four register arguments and three stack
# arguments.  This forwarding wrapper remains ABI-identical, but V17 now uses
# it only for the single-block CMD17 site.  Count and snapshot a command only
# while a host request owns an odd V17R sequence and the low-level context is
# host READ (2); the reinitialization probe deliberately changes that context
# to zero around its own LBA-0 CMD17.
.global physical_command_telemetry
.thumb_func
physical_command_telemetry:
    push    {r4-r7, lr}
    sub     sp, #0x0c
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    movs    r7, r3
    ldr     r0, =0xC019D000
    ldr     r1, [r0, #0x48]
    cmp     r1, #2
    bne     physical_command_call_original
    ldr     r0, =0xC019D1C0
    ldr     r1, [r0, #0x04]
    lsls    r1, r1, #31
    bpl     physical_command_call_original
    ldr     r1, [r0, #0x08]
    lsls    r1, r1, #31
    bpl     physical_command_call_original
    ldr     r1, [r0, #0x28]
    adds    r1, #1
    str     r1, [r0, #0x28]
physical_command_call_original:
    ldr     r0, [sp, #0x20]
    str     r0, [sp, #0x00]
    ldr     r0, [sp, #0x24]
    str     r0, [sp, #0x04]
    ldr     r0, [sp, #0x28]
    str     r0, [sp, #0x08]
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    movs    r3, r7
    bl      physical_command
    movs    r4, r0
    ldr     r0, =0xC019D000
    ldr     r1, [r0, #0x48]
    cmp     r1, #2
    bne     physical_command_return
    ldr     r0, =0xC019D1C0
    ldr     r1, [r0, #0x04]
    lsls    r1, r1, #31
    bpl     physical_command_return
    ldr     r1, [r0, #0x08]
    lsls    r1, r1, #31
    bpl     physical_command_return
    str     r4, [r0, #0x78]
    cmp     r7, #0
    beq     physical_command_return
    ldr     r1, [r7]
    str     r1, [r0, #0x7c]
physical_command_return:
    movs    r0, r4
    add     sp, #0x0c
    pop     {r4-r7, pc}

# C00FE5CA queries the completed byte count for CMD17.  Preserve its exact
# result and publish it only for the active host-read sequence.
.global physical_count_telemetry
.thumb_func
physical_count_telemetry:
    push    {r3-r5, lr}
    movs    r4, r0
    movs    r5, r1
physical_count_call_original:
    movs    r0, r4
    movs    r1, r5
    bl      physical_count
    movs    r4, r0
    ldr     r0, =0xC019D000
    ldr     r1, [r0, #0x48]
    cmp     r1, #2
    bne     physical_count_return
    ldr     r0, =0xC019D1C0
    ldr     r1, [r0, #0x04]
    lsls    r1, r1, #31
    bpl     physical_count_return
    ldr     r1, [r0, #0x08]
    lsls    r1, r1, #31
    bpl     physical_count_return
    adds    r0, #0x80
    str     r4, [r0, #0x00]
physical_count_return:
    movs    r0, r4
    pop     {r3-r5, pc}

# C01720A4 originally calls C0172D30(ctx, cbw, data, bytes, &csw_status).
# Record both its signed residue/error return and the output CSW status.  As
# above, the saved-r3 word becomes the nested call's fifth stack argument.
.global read10_send_telemetry
.thumb_func
read10_send_telemetry:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    movs    r7, r3
    bl      telemetry_prepare
    ldr     r0, =0xC019D0FC
    ldr     r0, [r0]
    cmp     r0, #0
    bne     read10_send_passthrough
    ldr     r3, =0xC019D0B0
    ldr     r0, [r3, #0x00]
    adds    r0, #1
    str     r0, [r3, #0x00]
    str     r4, [r3, #0x04]
    str     r5, [r3, #0x08]
    str     r6, [r3, #0x0c]
    str     r7, [r3, #0x10]
    cmp     r5, #0
    beq     read10_send_no_cbw
    ldr     r0, [r5, #0x08]
    str     r0, [r3, #0x14]
    ldrb    r0, [r5, #0x0c]
    str     r0, [r3, #0x18]
read10_send_no_cbw:
    ldr     r0, [sp, #0x18]
    str     r0, [r3, #0x1c]
    ldr     r0, =0xC019D000
    movs    r1, #5
    str     r1, [r0, #0x24]
    ldr     r3, [sp, #0x18]
    str     r3, [sp, #0x00]
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    movs    r3, r7
    bl      msc_send_data
    movs    r4, r0
    ldr     r3, =0xC019D0B0
    str     r4, [r3, #0x20]
    ldr     r1, [sp, #0x18]
    cmp     r1, #0
    beq     read10_send_no_status
    ldrb    r0, [r1]
    str     r0, [r3, #0x24]
read10_send_no_status:
    ldr     r0, =0xC0DEF00D
    str     r0, [r3, #0x28]
    ldr     r1, =0xC019D000
    movs    r0, #6
    str     r0, [r1, #0x24]
    ldr     r1, =0xC019D0FC
    movs    r0, #1
    str     r0, [r1]
    movs    r0, r4
    pop     {r3-r7, pc}
read10_send_passthrough:
    ldr     r3, [sp, #0x18]
    str     r3, [sp, #0x00]
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    movs    r3, r7
    bl      msc_send_data
    pop     {r3-r7, pc}

.ltorg

.section .phase2_runtime, "ax", %progbits
.balign 4

# C017D99E originally calls the USB PHY reset directly after phase 2 has
# acquired V14's counted storage lease and enabled USB group 4.  Preserve that
# ordering, then arm backend+0x30 so the stock tMscSmp entry calls C0171B78
# before its CBW loop.
# C01010B8 performs the full controller/card initialization and reads/parses
# LBA 0 itself; doing that work here as well created the redundant lifecycle
# that V11 proved can fail on its second pass.  A missing backend or readiness
# callback unwinds both power groups and prevents MSC construction.
.global phase2_storage_requalify
.thumb_func
phase2_storage_requalify:
    push    {r3-r5, lr}
    bl      telemetry_prepare
    bl      guard_state_prepare
    ldr     r0, =0xC019D100
    movs    r1, #1
    str     r1, [r0, #0x20]
    bl      usb_phy_reset
    ldr     r0, =0xC23E5C2C
    ldr     r0, [r0]
    cmp     r0, #0
    beq     phase2_storage_failed
    ldr     r1, [r0, #0x0c]
    cmp     r1, #0
    beq     phase2_storage_failed
    movs    r1, #1
    str     r1, [r0, #0x30]
    ldr     r2, =0xC019D000
    movs    r3, #0
    str     r3, [r2, #0x6c]
    ldr     r0, =0x000F0001
    movs    r1, #0
    pop     {r3-r5, pc}

phase2_storage_failed:
    ldr     r2, =0xC019D000
    movs    r3, #0
    mvns    r3, r3
    str     r3, [r2, #0x6c]
    bl      phase2_failure_cleanup
    movs    r1, #0
    movs    r0, #0
    pop     {r3-r5, pc}

.ltorg

.section .fifo_hook, "ax", %progbits
.balign 2
.global fifo_hook
.thumb_func
fifo_hook:
    # Replace C0101D5A's unique FIFOEMP timeout decision.  The shim branches
    # directly to the original success/failure continuations.
    bl      mmc_fifo_timeout_decision

.section .sem_hook, "ax", %progbits
.balign 2
.global sem_hook
.thumb_func
sem_hook:
    # Replace only C0101ECC's completion-semaphore wait call.
    bl      mmc_command_wait_telemetry

.section .worker_runtime, "ax", %progbits
.balign 4

# C0171DFA is the stock one-time readiness call at entry to tMscSmp, before
# its receive loop and before any CBW or READ buffer is active.  Phase 2
# deliberately re-arms backend+0x30 so C0171BF8 reaches C0171B78 here.
.global worker_startup_telemetry
.thumb_func
worker_startup_telemetry:
    push    {r3-r5, lr}
    bl      telemetry_prepare
    ldr     r4, =0xC019D000
    ldr     r5, =0xC23E5C2C
    ldr     r5, [r5]
    str     r5, [r4, #0x4c]
    cmp     r5, #0
    beq     worker_startup_no_backend_before
    ldr     r0, [r5, #0x30]
    str     r0, [r4, #0x50]
    ldr     r0, [r5, #0x44]
    str     r0, [r4, #0x58]
worker_startup_no_backend_before:
    movs    r0, #1
    str     r0, [r4, #0x3c]
    str     r0, [r4, #0x48]
    bl      msc_worker_startup
    movs    r5, r0
    str     r5, [r4, #0x34]
    movs    r0, #0
    str     r0, [r4, #0x48]
    ldr     r0, =0xC23E5C2C
    ldr     r0, [r0]
    cmp     r0, #0
    beq     worker_startup_no_backend_after
    ldr     r1, [r0, #0x30]
    str     r1, [r4, #0x54]
    ldr     r1, [r0, #0x44]
    str     r1, [r4, #0x5c]
worker_startup_no_backend_after:
    movs    r0, #3
    cmp     r5, #0
    bne     worker_startup_store_state
    movs    r0, #2
worker_startup_store_state:
    str     r0, [r4, #0x3c]
    movs    r0, r5
    pop     {r3-r5, pc}

# C017205A is the READ(10)-only call site for C0171BAC(lba, count, buffer).
# The stock startup refresh above now owns reinitialization.  Keep this wrapper
# observational: snapshot the first/most-recent request and call the original
# backend directly with exact arguments on every READ.
.global read10_worker_telemetry
.thumb_func
read10_worker_telemetry:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    bl      telemetry_prepare
    ldr     r7, =0xC019D000
    ldr     r0, [r7, #0x20]
    adds    r0, #1
    str     r0, [r7, #0x20]
    str     r4, [r7, #0x28]
    str     r5, [r7, #0x2c]
    str     r6, [r7, #0x30]
    ldr     r0, =0xC2213BE0
    ldr     r0, [r0]
    cmp     r0, #0
    beq     worker_read_snapshot_done
    ldr     r2, [r0, #0x04]
    str     r2, [r7, #0x40]
    ldr     r2, [r0, #0x0c]
    str     r2, [r7, #0x44]
worker_read_snapshot_done:
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    bl      cmd17_request_begin
    movs    r0, #2
    str     r0, [r7, #0x48]
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    bl      msc_partition_read_with_recovery
    movs    r4, r0
    bl      cmd17_request_end
    str     r4, [r7, #0x38]
    movs    r0, #0
    str     r0, [r7, #0x48]
    movs    r0, r4
    pop     {r3-r7, pc}

# C0101D5A follows a 100-iteration poll of MMCST1.FIFOEMP.  Equality is the
# timeout path; inequality is the untouched command-issue continuation.  V15
# snapshots the first timeout but never clears the FIFO or continues inline:
# doing so could resume an unfinished CMD18 into the next command's buffer.
.global mmc_fifo_timeout_decision
.thumb_func
mmc_fifo_timeout_decision:
    cmp     r0, #0x64
    bne     mmc_fifo_ready
    bl      mmc_fifo_timeout_diagnose
mmc_fifo_timeout_return:
    ldr     r1, =0xC0101D5F
    bx      r1
mmc_fifo_ready:
    # This hook runs before the command register write and before IRQs are
    # restored.  Arm the ISR-status sentinel here so a fast completion cannot
    # be overwritten later by the semaphore-wait telemetry wrapper.
    bl      mmc_command_arm_sentinel
    ldr     r1, =0xC0101D65
    bx      r1

# Preserve C0101ECC's wait exactly once.  A nonzero wait result is a semaphore
# timeout/OS failure.  On a zero result the ISR has already finalized
# device+0x34; READ(10)'s command requires the exact success value 4.
.global mmc_command_wait_telemetry
.thumb_func
mmc_command_wait_telemetry:
    b       mmc_command_wait_telemetry_extended

.section .fifo_recovery_runtime, "ax", %progbits
.balign 4
.global mmc_command_wait_telemetry_extended
.thumb_func
mmc_command_wait_telemetry_extended:
    push    {r3-r7, lr}
    movs    r5, r0
    movs    r6, r1
    movs    r7, r2
    movs    r0, r5
    movs    r1, r6
    movs    r2, r7
    bl      command_sem_wait
    movs    r5, r0
    ldr     r1, =0xC019D000
    ldr     r2, [r1, #0x48]
    cmp     r2, #1
    beq     mmc_wait_filter_selector
    cmp     r2, #2
    bne     mmc_wait_done
mmc_wait_filter_selector:
    ldr     r3, [r4, #0x28]
    ldr     r2, =0x00010311
    cmp     r3, r2
    beq     mmc_wait_filter_first
    adds    r2, #1
    cmp     r3, r2
    bne     mmc_wait_done
mmc_wait_filter_first:
    ldr     r2, [r1, #0x70]
    cmp     r2, #0
    bne     mmc_wait_done
    cmp     r5, #0
    bne     mmc_wait_failed
    ldr     r2, [r4, #0x34]
    cmp     r2, #4
    beq     mmc_wait_done
    movs    r3, #3
    str     r3, [r1, #0x70]
    str     r2, [r1, #0x74]
    b       mmc_wait_snapshot
mmc_wait_failed:
    movs    r2, #2
    str     r2, [r1, #0x70]
    str     r5, [r1, #0x74]
mmc_wait_snapshot:
    movs    r0, #0
    bl      mmc_failure_snapshot
    bl      mmc_extended_failure_snapshot
mmc_wait_done:
    movs    r0, r5
    pop     {r3-r7, pc}

.section .worker_runtime, "ax", %progbits
.balign 4

# Snapshot the state that discriminates a powered-off controller, a missing or
# nonqualifying IRQ, a failed semaphore wake, and a finalized card error.
# Do not read MMCST0 in task context: it is clear-on-read and consuming a late
# status could steal it from the ISR.  The MMCST0 slot is set to 0xFFFFFFFF;
# device+0xE4 retains the ISR-latched status or the pre-command sentinel.
# r1 = record pointer, r4 = low-level device context, r0 = FIFO loop count (or
# zero for completion paths).  The worker-context word is copied before clear.
.global mmc_failure_snapshot
.thumb_func
mmc_failure_snapshot:
    ldr     r2, [r1, #0x48]
    str     r2, [r1, #0x78]
    ldr     r2, [r1, #0x70]
    cmp     r2, #1
    bne     mmc_failure_non_fifo_site
    ldr     r2, =0xC0101D5A
    b       mmc_failure_store_site
mmc_failure_non_fifo_site:
    cmp     r2, #4
    bne     mmc_failure_wait_site
    ldr     r2, =0xC00FE62E
    b       mmc_failure_store_site
mmc_failure_wait_site:
    ldr     r2, =0xC0101ECC
mmc_failure_store_site:
    str     r2, [r1, #0x7c]
    adds    r1, #0x70
    ldr     r2, [r4]
    ldr     r3, [r2, #0x04]
    str     r3, [r1, #0x10]
    movs    r3, #0
    mvns    r3, r3
    str     r3, [r1, #0x14]
    ldr     r3, [r2, #0x0c]
    str     r3, [r1, #0x18]
    ldr     r3, [r2, #0x10]
    str     r3, [r1, #0x1c]
    ldr     r3, [r2, #0x30]
    str     r3, [r1, #0x20]
    ldr     r2, [r4, #0x34]
    str     r2, [r1, #0x24]
    movs    r2, #0xe4
    ldr     r3, [r4, r2]
    str     r3, [r1, #0x28]
    ldr     r2, [r4, #0x24]
    str     r2, [r1, #0x2c]
    cmp     r2, #0
    beq     mmc_failure_no_sem
    ldr     r3, [r2]
    str     r3, [r1, #0x30]
mmc_failure_no_sem:
    ldr     r2, [r4, #0x28]
    str     r2, [r1, #0x34]
    ldr     r2, [r4, #0x30]
    str     r2, [r1, #0x38]
    bx      lr

.ltorg

.section .shutdown_runtime, "ax", %progbits
.balign 4

# V16's guard record is separate from the frozen 0x100-byte READ telemetry:
#   +00 magic "V16G"
#   +04 pending marker
#   +08 one-shot shutdown token
#   +0C token-arm count
#   +10 shutdown-guard calls
#   +14 suppressed hardware shutdowns
#   +18 stock hardware shutdowns
#   +1C failed/stale handoff clears
#   +20 phase-2-started marker
#   +24 last guard action (1 suppressed, 2 stock)
#   +28 last snapshot: class | manager<<8 | group0<<16 | storage<<24
#   +2C last published storage state
#   +30 durable storage lease held
#   +34 lease-acquire count
#   +38 lease-release count
#   +3C phase-2 refcount before acquire
#   +40 phase-2 group-0 state before acquire
#   +44 phase-2 refcount after acquire
#   +48 phase-2 group-0 state after acquire
#   +4C most-recent READ refcount
#   +50 most-recent READ group-0 state
#   +54 most-recent READ driver-enable state
#   +58 release refcount before
#   +5C release refcount after
#   +60 recovery attempts
#   +64 failed READ result before recovery
#   +68 full readiness/reinitialization result
#   +6C one-shot retry result
#   +70 successful recoveries
#   +74 primary-failure latch
#   +78 primary low-level context (startup=1, host READ=2)
#   +7C primary selector
#   +80 primary command flags
#   +84 primary device result
#   +88 primary ISR status/sentinel
#   +8C primary MMCCTL
#   +90 primary MMCCLK
#   +94 primary MMCST0 (not sampled; 0xFFFFFFFF)
#   +98 primary MMCST1
#   +9C primary MMCIM
#   +A0 primary MMCNBLK
#   +A4 primary MMCNBLC
#   +A8 primary MMCCMD
#   +AC primary MMCARGHL
#   +B0 primary MMCFIFOCTL
#   +B4 AINTC global enable
#   +B8 AINTC system-interrupt raw status 1
#   +BC AINTC system-interrupt enable set 1

.global guard_state_prepare
.thumb_func
guard_state_prepare:
    ldr     r0, =0xC019D100
    ldr     r1, [r0]
    # "V16G" in little endian.
    ldr     r2, =0x47363156
    cmp     r1, r2
    beq     guard_state_prepare_done
    movs    r1, #0
    # 0xC0 / sizeof(uint32_t).
    movs    r3, #0x30
guard_state_clear_loop:
    str     r1, [r0]
    adds    r0, #4
    subs    r3, #1
    bne     guard_state_clear_loop
    ldr     r0, =0xC019D100
    str     r2, [r0]
guard_state_prepare_done:
    bx      lr

# Only the state-aware USB storage helper calls this wrapper.  Set PENDING
# before C008D830 can broadcast state 3.  Preserve an already-armed TOKEN
# across a duplicate desired-mode request: its dedup path publishes nothing,
# and clearing the live token there would reopen the shutdown race.  A failed
# transition is fail-closed and clears all markers before returning its exact
# normalized result.
.global storage_set_desired_handoff
.thumb_func
storage_set_desired_handoff:
    push    {r3-r5, lr}
    movs    r4, r0
    bl      guard_state_prepare
    ldr     r5, =0xC019D100
    movs    r0, #0
    str     r0, [r5, #0x04]
    ldr     r0, =0x47363156
    str     r0, [r5, #0x04]
    movs    r0, r4
    bl      storage_set_desired
    movs    r4, r0
    # The notifier normally consumes PENDING synchronously.  A successful
    # desired-mode dedup performs no publication, so clear it here as well;
    # TOKEN, if the notifier armed it, remains untouched.
    movs    r0, #0
    str     r0, [r5, #0x04]
    cmp     r4, #0
    beq     storage_set_desired_handoff_return
    str     r0, [r5, #0x04]
    str     r0, [r5, #0x08]
    str     r0, [r5, #0x20]
    str     r0, [r5, #0x24]
    ldr     r0, [r5, #0x1c]
    adds    r0, #1
    str     r0, [r5, #0x1c]
storage_set_desired_handoff_return:
    movs    r0, r4
    pop     {r3-r5, pc}

# This remains a transparent C008E120 wrapper for every shared caller.  It
# arms TOKEN only when the USB-specific PENDING marker accompanies a successful
# state-3 publication, immediately before the stock asynchronous broadcast.
.global storage_notify_handoff
.thumb_func
storage_notify_handoff:
    push    {r3-r5, lr}
    movs    r4, r0
    bl      guard_state_prepare
    ldr     r5, =0xC019D100
    str     r4, [r5, #0x2c]
    ldr     r1, [r5, #0x04]
    movs    r0, #0
    str     r0, [r5, #0x04]
    ldr     r2, =0x47363156
    cmp     r1, r2
    bne     storage_notify_handoff_call
    cmp     r4, #3
    bne     storage_notify_handoff_failed
    str     r2, [r5, #0x08]
    str     r0, [r5, #0x20]
    str     r0, [r5, #0x24]
    ldr     r0, [r5, #0x0c]
    adds    r0, #1
    str     r0, [r5, #0x0c]
    b       storage_notify_handoff_call
storage_notify_handoff_failed:
    str     r0, [r5, #0x08]
    ldr     r0, [r5, #0x1c]
    adds    r0, #1
    str     r0, [r5, #0x1c]
storage_notify_handoff_call:
    movs    r0, r4
    bl      storage_notify
    pop     {r3-r5, pc}

# C00D95A0 reaches this only for a logical storage-disable transition.  Always
# consume TOKEN first.  If phase 2 has not started, execute the original first
# hardware-disable call and return one so the caller completes the stock IRQ,
# notification, and group-0 power-off tail.  An exact token unconditionally
# identifies this handoff's queued shutdown, so retain driver/IRQ/power state,
# perform the stock non-hardware notification here, and return zero so the
# patched caller reaches only its logical-state clear.  This deliberately does
# not depend on task scheduling or the phase-2-started diagnostic marker.
.global storage_shutdown_guard
.thumb_func
storage_shutdown_guard:
    push    {r3-r5, lr}
    bl      guard_state_prepare
    ldr     r4, =0xC019D100
    ldr     r0, [r4, #0x10]
    adds    r0, #1
    str     r0, [r4, #0x10]
    ldr     r5, [r4, #0x08]
    movs    r0, #0
    str     r0, [r4, #0x08]
    ldr     r0, =0xC23E5C68
    ldrb    r1, [r0]
    ldr     r0, =0xC23E5C28
    ldrb    r2, [r0, #1]
    lsls    r2, r2, #8
    orrs    r1, r2
    ldr     r0, =0xC23E5C30
    ldrb    r2, [r0]
    lsls    r2, r2, #16
    orrs    r1, r2
    ldr     r0, =0xC23E5B34
    ldrb    r2, [r0, #5]
    lsls    r2, r2, #24
    orrs    r1, r2
    str     r1, [r4, #0x28]
    ldr     r0, =0x47363156
    cmp     r5, r0
    bne     storage_shutdown_guard_stock
    ldr     r0, [r4, #0x14]
    adds    r0, #1
    str     r0, [r4, #0x14]
    movs    r0, #1
    str     r0, [r4, #0x24]
    movs    r0, #0x5f
    bl      storage_shutdown_notify
    movs    r0, #0
    pop     {r3-r5, pc}
storage_shutdown_guard_stock:
    ldr     r0, [r4, #0x18]
    adds    r0, #1
    str     r0, [r4, #0x18]
    movs    r0, #2
    str     r0, [r4, #0x24]
    movs    r1, #1
    movs    r0, #0
    bl      storage_driver_control
    movs    r0, #1
    pop     {r3-r5, pc}

# Complete the fail-closed phase-2 unwind outside the smaller C019C67C cave.
# Clear the high-level manager byte before touching hardware so the already
# queued shutdown becomes an idempotent logical no-op.  Preserve its
# notification exactly once by consulting this attempt's reset action word.
.global phase2_failure_cleanup
.thumb_func
phase2_failure_cleanup:
    push    {r3-r5, lr}
    ldr     r4, =0xC019D100
    ldr     r5, [r4, #0x24]
    movs    r3, #0
    str     r3, [r4, #0x04]
    str     r3, [r4, #0x08]
    str     r3, [r4, #0x20]
    ldr     r0, =0xC23E5C28
    strb    r3, [r0, #0x01]
    movs    r1, #1
    movs    r0, #0
    bl      storage_driver_control
    movs    r1, #0
    movs    r0, #5
    bl      storage_irq_control
    cmp     r5, #0
    bne     phase2_failure_cleanup_notified
    movs    r0, #0x5f
    bl      storage_shutdown_notify
phase2_failure_cleanup_notified:
    movs    r1, #0
    movs    r0, #4
    bl      storage_power_control
    bl      phase2_storage_release
    .hword  0x46c0
    .hword  0x46c0
    pop     {r3-r5, pc}

.ltorg

.section .lease_runtime, "ax", %progbits
.balign 4

# Replace phase 2's raw group-0 request with ownership of one C008E330
# reference.  The held marker makes duplicate phase-2 events idempotent.
.global phase2_storage_acquire
.thumb_func
phase2_storage_acquire:
    push    {r3-r5, lr}
    bl      guard_state_prepare
    ldr     r4, =0xC019D100
    ldr     r5, =0xC23E5B34
    ldrb    r0, [r5, #0x06]
    str     r0, [r4, #0x3c]
    ldr     r5, =0xC23E5C30
    ldrb    r0, [r5]
    str     r0, [r4, #0x40]
    ldr     r0, [r4, #0x30]
    cmp     r0, #0
    bne     phase2_storage_acquire_snapshot
    movs    r0, #1
    bl      storage_lease_control
    movs    r0, #1
    str     r0, [r4, #0x30]
    ldr     r0, [r4, #0x34]
    adds    r0, #1
    str     r0, [r4, #0x34]
phase2_storage_acquire_snapshot:
    ldr     r5, =0xC23E5B34
    ldrb    r0, [r5, #0x06]
    str     r0, [r4, #0x44]
    ldr     r5, =0xC23E5C30
    ldrb    r0, [r5]
    str     r0, [r4, #0x48]
    pop     {r3-r5, pc}

# Release the counted group-0 lease at most once.  Do not initialize a guard
# record from a class-0/1 teardown: only a matching V16 handoff can own it.
.global phase2_storage_release
.thumb_func
phase2_storage_release:
    push    {r3-r5, lr}
    ldr     r4, =0xC019D100
    ldr     r1, [r4]
    ldr     r0, =0x47363156
    cmp     r1, r0
    bne     phase2_storage_release_return
    ldr     r0, [r4, #0x30]
    cmp     r0, #0
    beq     phase2_storage_release_clear
    ldr     r5, =0xC23E5B34
    ldrb    r0, [r5, #0x06]
    str     r0, [r4, #0x58]
    movs    r0, #0
    str     r0, [r4, #0x30]
    bl      storage_lease_control
    ldr     r0, [r4, #0x38]
    adds    r0, #1
    str     r0, [r4, #0x38]
    ldrb    r0, [r5, #0x06]
    str     r0, [r4, #0x5c]
phase2_storage_release_clear:
    movs    r0, #0
    str     r0, [r4, #0x04]
    str     r0, [r4, #0x08]
    str     r0, [r4, #0x20]
phase2_storage_release_return:
    pop     {r3-r5, pc}

# Preserve stock USB group-4 power-off first, then drop the checked storage
# lease in reverse acquisition order.
.global usb_group4_off_and_release_lease
.thumb_func
usb_group4_off_and_release_lease:
    push    {r3-r5, lr}
    bl      storage_power_control
    bl      phase2_storage_release
    pop     {r3-r5, pc}

# Add the refcount/group/driver snapshot missing from V13 without growing the
# tightly packed worker cave.  Preserve the READ arguments and exact result.
.global read10_worker_lease_telemetry
.thumb_func
read10_worker_lease_telemetry:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    bl      guard_state_prepare
    ldr     r7, =0xC019D100
    ldr     r0, =0xC23E5B34
    ldrb    r0, [r0, #0x06]
    str     r0, [r7, #0x4c]
    ldr     r0, =0xC23E5C30
    ldrb    r0, [r0]
    str     r0, [r7, #0x50]
    ldr     r0, =0xC2213BDC
    ldr     r0, [r0]
    str     r0, [r7, #0x54]
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    bl      read10_worker_telemetry
    movs    r4, r0
    movs    r0, r4
    pop     {r3-r7, pc}

.ltorg

.section .fifo_recovery_runtime, "ax", %progbits
.balign 4

# Arm device+0xE4 before the MMC command is issued.  The ISR overwrites this
# word with the latched MMCST0/IRQ status; leaving SENT intact means no qualifying
# completion interrupt ran.  Entry is the FIFO-ready path with r4 = device
# context.  Preserve every register visible to the stock continuation.
.global mmc_command_arm_sentinel
.thumb_func
mmc_command_arm_sentinel:
    push    {r0-r3, r5, lr}
    ldr     r0, =0xC019D000
    ldr     r1, [r0, #0x48]
    cmp     r1, #1
    beq     mmc_command_arm_filter
    cmp     r1, #2
    bne     mmc_command_arm_done
mmc_command_arm_filter:
    ldr     r1, [r4, #0x28]
    ldr     r2, =0x00010311
    cmp     r1, r2
    beq     mmc_command_arm_store
    adds    r2, #1
    cmp     r1, r2
    bne     mmc_command_arm_done
mmc_command_arm_store:
    ldr     r1, =0x53454E54
    movs    r2, #0xe4
    str     r1, [r4, r2]
mmc_command_arm_done:
    pop     {r0-r3, r5, pc}

# Preserve the first FIFO timeout without mutating the controller.  Entry:
# r0 = timed-out FIFOEMP poll count, r4 = low-level MMC device context.
.global mmc_fifo_timeout_diagnose
.thumb_func
mmc_fifo_timeout_diagnose:
    push    {r3-r7, lr}
    movs    r7, r0
    ldr     r5, =0xC019D000
    ldr     r0, [r5, #0x48]
    cmp     r0, #1
    beq     mmc_fifo_recovery_filter
    cmp     r0, #2
    bne     mmc_fifo_diagnose_done
mmc_fifo_recovery_filter:
    ldr     r3, [r4, #0x28]
    ldr     r2, =0x00010311
    cmp     r3, r2
    beq     mmc_fifo_diagnose_first
    adds    r2, #1
    cmp     r3, r2
    bne     mmc_fifo_diagnose_done
mmc_fifo_diagnose_first:
    ldr     r2, [r5, #0x70]
    cmp     r2, #0
    bne     mmc_fifo_diagnose_done
    movs    r2, #1
    str     r2, [r5, #0x70]
    str     r7, [r5, #0x74]
    movs    r0, r7
    movs    r1, r5
    bl      mmc_failure_snapshot
    bl      mmc_extended_failure_snapshot
mmc_fifo_diagnose_done:
    pop     {r3-r7, pc}

# Capture the primary failure once in the durable guard record.  The MMCST0
# field copies the explicit 0xFFFFFFFF "not sampled" marker from the base
# snapshot; the ISR-latched device+0xE4 word is captured separately.
.global mmc_extended_failure_snapshot
.thumb_func
mmc_extended_failure_snapshot:
    push    {r3-r7, lr}
    bl      guard_state_prepare
    ldr     r5, =0xC019D100
    ldr     r0, [r5, #0x74]
    cmp     r0, #0
    bne     mmc_extended_snapshot_done
    movs    r0, #1
    str     r0, [r5, #0x74]
    ldr     r6, =0xC019D000
    ldr     r0, [r6, #0x48]
    str     r0, [r5, #0x78]
    ldr     r0, [r4, #0x28]
    str     r0, [r5, #0x7c]
    adds    r5, #0x80
    ldr     r0, [r4, #0x30]
    str     r0, [r5, #0x00]
    ldr     r0, [r4, #0x34]
    str     r0, [r5, #0x04]
    movs    r0, #0xe4
    ldr     r0, [r4, r0]
    str     r0, [r5, #0x08]
    ldr     r7, [r4]
    ldr     r0, [r7, #0x00]
    str     r0, [r5, #0x0c]
    adds    r6, #0x80
    ldr     r0, [r6, #0x00]
    str     r0, [r5, #0x10]
    ldr     r0, [r6, #0x04]
    str     r0, [r5, #0x14]
    ldr     r0, [r6, #0x08]
    str     r0, [r5, #0x18]
    ldr     r0, [r6, #0x0c]
    str     r0, [r5, #0x1c]
    ldr     r0, [r7, #0x20]
    str     r0, [r5, #0x20]
    ldr     r0, [r7, #0x24]
    str     r0, [r5, #0x24]
    ldr     r0, [r6, #0x10]
    str     r0, [r5, #0x28]
    ldr     r0, [r7, #0x34]
    str     r0, [r5, #0x2c]
    ldr     r0, [r7, #0x74]
    str     r0, [r5, #0x30]
    ldr     r0, =0xFFFEE010
    ldr     r0, [r0]
    str     r0, [r5, #0x34]
    ldr     r0, =0xFFFEE200
    ldr     r0, [r0]
    str     r0, [r5, #0x38]
    ldr     r0, =0xFFFEE300
    ldr     r0, [r0]
    str     r0, [r5, #0x3c]
mmc_extended_snapshot_done:
    pop     {r3-r7, pc}

# C00FE62E is the CMD18 data/count completion.  Freeze a failed or short
# result if the command phase itself succeeded, then let stock unwind.
.global physical_count_multi_telemetry
.thumb_func
physical_count_multi_telemetry:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    bl      physical_count
    movs    r6, r0
    cmp     r5, #0x12
    bne     physical_count_multi_return
    ldr     r7, =0xC23E4AD4
    ldr     r0, [r7, #0x14]
    cmp     r0, #0
    beq     physical_count_multi_return
    cmp     r4, #0
    bmi     physical_count_multi_return
    ldr     r0, [r7, #0x28]
    cmp     r4, r0
    bge     physical_count_multi_return
    lsls    r0, r4, #2
    adds    r0, r7, r0
    ldr     r4, [r0, #0x18]
    cmp     r4, #0
    beq     physical_count_multi_return
    ldr     r0, [r4, #0x44]
    cmp     r6, r0
    beq     physical_count_multi_return
    ldr     r1, =0xC019D000
    ldr     r0, [r1, #0x48]
    cmp     r0, #1
    beq     physical_count_multi_first
    cmp     r0, #2
    bne     physical_count_multi_return
physical_count_multi_first:
    ldr     r0, [r1, #0x70]
    cmp     r0, #0
    bne     physical_count_multi_return
    movs    r0, #4
    str     r0, [r1, #0x70]
    str     r6, [r1, #0x74]
    movs    r0, #0
    bl      mmc_failure_snapshot
    bl      mmc_extended_failure_snapshot
physical_count_multi_return:
    movs    r0, r6
    pop     {r3-r7, pc}

# Service one host READ as repeated stock single-sector partition reads.
# This deliberately keeps every physical transfer on the CMD17 branch:
# V15 proved that its readiness-time CMD17 succeeds, while each CMD18 attempt
# completed only 0x600 of the requested 0x4000 bytes before a normal CMD12
# cleanup.  A zero transfer count is normalized to one exactly as C01726F0
# does.  Advance the destination by the cached logical block size that the
# same readiness path publishes to the host.
.global msc_partition_read_single_loop
.thumb_func
msc_partition_read_single_loop:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    cmp     r5, #0
    bne     msc_partition_single_geometry
    adds    r5, #1
msc_partition_single_geometry:
    ldr     r7, =0xC2213F60
    ldr     r7, [r7, #0x18]
    cmp     r7, #0
    beq     msc_partition_single_no_geometry
msc_partition_single_next:
    movs    r0, r4
    movs    r1, r6
    bl      cmd17_sector_begin
    movs    r0, r4
    movs    r1, #1
    movs    r2, r6
    bl      msc_partition_read
    bl      cmd17_sector_end
    cmp     r0, #0
    bne     msc_partition_single_return
    subs    r5, #1
    beq     msc_partition_single_return
    adds    r4, #1
    adds    r6, r6, r7
    b       msc_partition_single_next
msc_partition_single_no_geometry:
    movs    r0, r4
    movs    r1, r6
    bl      cmd17_geometry_failure
    movs    r0, #0
    mvns    r0, r0
msc_partition_single_return:
    pop     {r3-r7, pc}

# After a failed single-sector loop has unwound out of the low-level command,
# use the stock readiness path once.  It resets command/data logic,
# re-identifies the card, and validates LBA0 before one retry of the complete
# host request through the same CMD17-only loop.
.global msc_partition_read_with_recovery
.thumb_func
msc_partition_read_with_recovery:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    movs    r0, #0
    bl      cmd17_attempt_begin
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    bl      msc_partition_read_single_loop
    movs    r7, r0
    cmp     r7, #0
    beq     msc_partition_recovery_return
    bl      guard_state_prepare
    ldr     r3, =0xC019D100
    ldr     r0, [r3, #0x60]
    cmp     r0, #0
    beq     msc_partition_recovery_allowed
    movs    r0, r7
    bl      cmd17_recovery_suppressed
    b       msc_partition_recovery_return
msc_partition_recovery_allowed:
    movs    r0, r7
    bl      cmd17_recovery_attempt
    ldr     r3, =0xC019D100
    ldr     r0, [r3, #0x60]
    adds    r0, #1
    str     r0, [r3, #0x60]
    str     r7, [r3, #0x64]
    ldr     r0, =0xC019D000
    movs    r1, #0
    str     r1, [r0, #0x48]
    bl      msc_readiness_probe
    movs    r7, r0
    bl      cmd17_reinit_result
    ldr     r3, =0xC019D100
    str     r7, [r3, #0x68]
    ldr     r0, =0xC019D000
    movs    r1, #2
    str     r1, [r0, #0x48]
    cmp     r7, #0
    bne     msc_partition_recovery_return
    bl      cmd17_retry_begin
    movs    r0, r4
    movs    r1, r5
    movs    r2, r6
    bl      msc_partition_read_single_loop
    movs    r7, r0
    bl      cmd17_retry_result
    ldr     r3, =0xC019D100
    str     r7, [r3, #0x6c]
    cmp     r7, #0
    bne     msc_partition_recovery_return
    ldr     r0, [r3, #0x70]
    adds    r0, #1
    str     r0, [r3, #0x70]
msc_partition_recovery_return:
    movs    r0, r7
    pop     {r3-r7, pc}

.ltorg

.balign 4

# V17R is an aggregate, seqlocked CMD17-loop record at
# C019D1C0..C019D27F.  The older V16T and V16G records remain byte-for-byte
# compatible at C019D000 and C019D100.
#
#   +00 magic "V17R"
#   +04 outer host-request sequence (odd while mutating, even when stable)
#   +08 flags:
#         bit 0 active host request
#         bit 1 first high-level sector failure latched
#         bit 2 zero-count request observed
#         bit 3 missing/zero block geometry observed
#         bit 4 recovery attempted
#         bit 5 full reinitialization succeeded
#         bit 6 retry attempted
#         bit 7 final host-request failure observed
#   +0C host requests started
#   +10 host requests succeeded
#   +14 host requests failed
#   +18 effective sectors requested
#   +1C sectors in successfully completed host requests
#   +20 maximum effective sectors in one host request
#   +24 high-level single-sector calls attempted
#   +28 actual host-context CMD17 commands issued
#   +2C successful high-level single-sector calls (includes retry replay)
#   +30 latest request start LBA
#   +34 latest request raw sector count
#   +38 latest request effective sector count
#   +3C latest request start buffer
#   +40 latest pass (0 initial, 1 retry)
#   +44 current/last sector LBA
#   +48 current/last zero-based sector index
#   +4C current/last sector buffer
#   +50 successful sectors in the current/latest pass
#   +54 latest final host-request result
#   +58 first failing high-level result
#   +5C first failing LBA
#   +60 first failing zero-based sector index
#   +64 first failing buffer
#   +68 first failing pass
#   +6C first failing host-request ordinal
#   +70 first failing high-level call ordinal
#   +74 CMD17 ordinal at first failure
#   +78 latest low command result
#   +7C latest low response word 0
#   +80 latest physical byte-count result
#   +84 low command result copied at first high-level failure
#   +88 low response copied at first high-level failure
#   +8C physical byte count copied at first high-level failure
#   +90 cached sector count
#   +94 cached logical block size
#   +98 recovery attempts
#   +9C last full-reinitialization result
#   +A0 retry attempts
#   +A4 last retry result
#   +A8 successful recoveries
#   +AC zero-count requests
#   +B0 geometry failures
#   +B4 initial result that entered the last recovery
#   +B8 failures suppressed by the global one-recovery circuit breaker
#   +BC trailing "V17R" completeness marker

.global cmd17_record_prepare
.thumb_func
cmd17_record_prepare:
    ldr     r0, =0xC019D1C0
    ldr     r1, [r0, #0x00]
    ldr     r2, =0x52373156
    cmp     r1, r2
    bne     cmd17_record_prepare_clear
    movs    r1, r0
    adds    r1, #0x80
    ldr     r1, [r1, #0x3c]
    cmp     r1, r2
    beq     cmd17_record_prepare_done
cmd17_record_prepare_clear:
    movs    r1, #0
    movs    r3, #0x30
cmd17_record_clear_loop:
    str     r1, [r0, #0x00]
    adds    r0, #4
    subs    r3, #1
    bne     cmd17_record_clear_loop
    ldr     r0, =0xC019D1C0
    movs    r1, r0
    adds    r1, #0x80
    str     r2, [r1, #0x3c]
    str     r2, [r0, #0x00]
cmd17_record_prepare_done:
    bx      lr

# r0=LBA, r1=raw sector count, r2=buffer.  Start the outer seqlock before
# touching any aggregate/current-request field.
.global cmd17_request_begin
.thumb_func
cmd17_request_begin:
    push    {r3-r7, lr}
    movs    r4, r0
    movs    r5, r1
    movs    r6, r2
    bl      cmd17_record_prepare
    ldr     r7, =0xC019D1C0
    ldr     r0, [r7, #0x04]
    adds    r0, #1
    str     r0, [r7, #0x04]
    ldr     r0, [r7, #0x08]
    movs    r1, #1
    orrs    r0, r1
    str     r0, [r7, #0x08]
    ldr     r0, [r7, #0x0c]
    adds    r0, #1
    str     r0, [r7, #0x0c]
    movs    r3, r5
    cmp     r3, #0
    bne     cmd17_request_effective_ready
    movs    r3, #1
    ldr     r0, [r7, #0x08]
    movs    r1, #4
    orrs    r0, r1
    str     r0, [r7, #0x08]
    movs    r0, r7
    adds    r0, #0x80
    ldr     r1, [r0, #0x2c]
    adds    r1, #1
    str     r1, [r0, #0x2c]
cmd17_request_effective_ready:
    ldr     r0, [r7, #0x18]
    adds    r0, r0, r3
    str     r0, [r7, #0x18]
    ldr     r0, [r7, #0x20]
    cmp     r0, r3
    bcs     cmd17_request_max_ready
    str     r3, [r7, #0x20]
cmd17_request_max_ready:
    str     r4, [r7, #0x30]
    str     r5, [r7, #0x34]
    str     r3, [r7, #0x38]
    str     r6, [r7, #0x3c]
    movs    r0, #0
    mvns    r0, r0
    str     r0, [r7, #0x54]
    str     r0, [r7, #0x78]
    str     r0, [r7, #0x7c]
    movs    r1, r7
    adds    r1, #0x80
    str     r0, [r1, #0x00]
    ldr     r2, =0xC2213F60
    ldr     r0, [r2, #0x14]
    str     r0, [r1, #0x10]
    ldr     r0, [r2, #0x18]
    str     r0, [r1, #0x14]
    pop     {r3-r7, pc}

# r0=final host-request result.  Publish every terminal field before making
# the sequence even.  Return the exact original result.
.global cmd17_request_end
.thumb_func
cmd17_request_end:
    push    {r3-r5, lr}
    movs    r4, r0
    ldr     r5, =0xC019D1C0
    str     r4, [r5, #0x54]
    cmp     r4, #0
    bne     cmd17_request_end_failed
    ldr     r0, [r5, #0x10]
    adds    r0, #1
    str     r0, [r5, #0x10]
    ldr     r0, [r5, #0x1c]
    ldr     r1, [r5, #0x38]
    adds    r0, r0, r1
    str     r0, [r5, #0x1c]
    b       cmd17_request_end_flags
cmd17_request_end_failed:
    ldr     r0, [r5, #0x14]
    adds    r0, #1
    str     r0, [r5, #0x14]
    ldr     r0, [r5, #0x08]
    movs    r1, #0x80
    orrs    r0, r1
    str     r0, [r5, #0x08]
cmd17_request_end_flags:
    ldr     r0, [r5, #0x08]
    movs    r1, #1
    bics    r0, r1
    str     r0, [r5, #0x08]
    ldr     r0, [r5, #0x04]
    adds    r0, #1
    str     r0, [r5, #0x04]
    movs    r0, r4
    pop     {r3-r5, pc}

# r0=pass (0 initial, 1 retry).
.global cmd17_attempt_begin
.thumb_func
cmd17_attempt_begin:
    ldr     r1, =0xC019D1C0
    str     r0, [r1, #0x40]
    ldr     r2, [r1, #0x30]
    str     r2, [r1, #0x44]
    movs    r2, #0
    str     r2, [r1, #0x48]
    ldr     r3, [r1, #0x3c]
    str     r3, [r1, #0x4c]
    str     r2, [r1, #0x50]
    bx      lr

.ltorg

# r0=current LBA, r1=current buffer.
.global cmd17_sector_begin
.thumb_func
cmd17_sector_begin:
    push    {r3-r5, lr}
    movs    r4, r0
    movs    r5, r1
    ldr     r3, =0xC019D1C0
    ldr     r0, [r3, #0x24]
    adds    r0, #1
    str     r0, [r3, #0x24]
    str     r4, [r3, #0x44]
    ldr     r0, [r3, #0x30]
    subs    r0, r4, r0
    str     r0, [r3, #0x48]
    str     r5, [r3, #0x4c]
    movs    r0, #0
    mvns    r0, r0
    str     r0, [r3, #0x78]
    str     r0, [r3, #0x7c]
    adds    r3, #0x80
    str     r0, [r3, #0x00]
    pop     {r3-r5, pc}

# r0=exact high-level single-sector result.  Freeze the first failure and the
# last low command/response/count that led to it; later failures cannot erase
# the evidence.
.global cmd17_sector_end
.thumb_func
cmd17_sector_end:
    push    {r3-r7, lr}
    movs    r4, r0
    ldr     r5, =0xC019D1C0
    cmp     r4, #0
    bne     cmd17_sector_failed
    ldr     r0, [r5, #0x2c]
    adds    r0, #1
    str     r0, [r5, #0x2c]
    ldr     r0, [r5, #0x50]
    adds    r0, #1
    str     r0, [r5, #0x50]
    b       cmd17_sector_end_return
cmd17_sector_failed:
    ldr     r0, [r5, #0x08]
    movs    r1, #2
    tst     r0, r1
    bne     cmd17_sector_end_return
    orrs    r0, r1
    str     r0, [r5, #0x08]
    str     r4, [r5, #0x58]
    ldr     r0, [r5, #0x44]
    str     r0, [r5, #0x5c]
    ldr     r0, [r5, #0x48]
    str     r0, [r5, #0x60]
    ldr     r0, [r5, #0x4c]
    str     r0, [r5, #0x64]
    ldr     r0, [r5, #0x40]
    str     r0, [r5, #0x68]
    ldr     r0, [r5, #0x0c]
    str     r0, [r5, #0x6c]
    ldr     r0, [r5, #0x24]
    str     r0, [r5, #0x70]
    ldr     r0, [r5, #0x28]
    str     r0, [r5, #0x74]
    movs    r6, r5
    adds    r6, #0x80
    ldr     r0, [r5, #0x78]
    str     r0, [r6, #0x04]
    ldr     r0, [r5, #0x7c]
    str     r0, [r6, #0x08]
    ldr     r0, [r6, #0x00]
    str     r0, [r6, #0x0c]
cmd17_sector_end_return:
    movs    r0, r4
    pop     {r3-r7, pc}

# Geometry failed before a stock partition-read call could issue CMD17.  Keep
# that distinct from the high-level call count, but feed the same immutable
# first-failure snapshot with exact LBA/index/buffer and sentinel low results.
.global cmd17_geometry_failure
.thumb_func
cmd17_geometry_failure:
    push    {r3-r5, lr}
    movs    r4, r0
    movs    r5, r1
    ldr     r3, =0xC019D1C0
    ldr     r0, [r3, #0x08]
    movs    r1, #8
    orrs    r0, r1
    str     r0, [r3, #0x08]
    str     r4, [r3, #0x44]
    ldr     r0, [r3, #0x30]
    subs    r0, r4, r0
    str     r0, [r3, #0x48]
    str     r5, [r3, #0x4c]
    movs    r0, #0
    mvns    r0, r0
    str     r0, [r3, #0x78]
    str     r0, [r3, #0x7c]
    adds    r3, #0x80
    str     r0, [r3, #0x00]
    ldr     r1, [r3, #0x30]
    adds    r1, #1
    str     r1, [r3, #0x30]
    bl      cmd17_sector_end
    pop     {r3-r5, pc}

# r0=initial failed result.  The stock guard record still enforces one recovery
# for the whole boot; V17R records that bounded attempt independently.
.global cmd17_recovery_attempt
.thumb_func
cmd17_recovery_attempt:
    push    {r3-r5, lr}
    movs    r4, r0
    ldr     r5, =0xC019D1C0
    ldr     r0, [r5, #0x08]
    movs    r1, #0x10
    orrs    r0, r1
    str     r0, [r5, #0x08]
    adds    r5, #0x80
    ldr     r0, [r5, #0x18]
    adds    r0, #1
    str     r0, [r5, #0x18]
    str     r4, [r5, #0x34]
    movs    r0, #0
    mvns    r0, r0
    str     r0, [r5, #0x1c]
    str     r0, [r5, #0x24]
    movs    r0, r4
    pop     {r3-r5, pc}

.global cmd17_recovery_suppressed
.thumb_func
cmd17_recovery_suppressed:
    push    {r3, r4, lr}
    movs    r4, r0
    ldr     r0, =0xC019D1C0
    adds    r0, #0x80
    ldr     r1, [r0, #0x38]
    adds    r1, #1
    str     r1, [r0, #0x38]
    movs    r0, r4
    pop     {r3, r4, pc}

# r0=full readiness/reinitialization result.
.global cmd17_reinit_result
.thumb_func
cmd17_reinit_result:
    push    {r3-r5, lr}
    movs    r4, r0
    ldr     r5, =0xC019D1C0
    movs    r0, r5
    adds    r0, #0x80
    str     r4, [r0, #0x1c]
    cmp     r4, #0
    bne     cmd17_reinit_result_return
    ldr     r0, [r5, #0x08]
    movs    r1, #0x20
    orrs    r0, r1
    str     r0, [r5, #0x08]
cmd17_reinit_result_return:
    movs    r0, r4
    pop     {r3-r5, pc}

# Record retry ownership, then tail into the common pass initializer.
.global cmd17_retry_begin
.thumb_func
cmd17_retry_begin:
    push    {r3-r5, lr}
    ldr     r5, =0xC019D1C0
    ldr     r0, [r5, #0x08]
    movs    r1, #0x40
    orrs    r0, r1
    str     r0, [r5, #0x08]
    adds    r5, #0x80
    ldr     r0, [r5, #0x20]
    adds    r0, #1
    str     r0, [r5, #0x20]
    movs    r0, #1
    bl      cmd17_attempt_begin
    pop     {r3-r5, pc}

# r0=one bounded retry result.
.global cmd17_retry_result
.thumb_func
cmd17_retry_result:
    push    {r3-r5, lr}
    movs    r4, r0
    ldr     r5, =0xC019D1C0
    adds    r5, #0x80
    str     r4, [r5, #0x24]
    cmp     r4, #0
    bne     cmd17_retry_result_return
    ldr     r0, [r5, #0x28]
    adds    r0, #1
    str     r0, [r5, #0x28]
cmd17_retry_result_return:
    movs    r0, r4
    pop     {r3-r5, pc}

.ltorg
