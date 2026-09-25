SECTIONS
{
  menu_usb_apply = 0xC004F659;
  usb_mode_event = 0xC00A2EA9;
  storage_set_desired = 0xC008D859;
  storage_unmount = 0xC008EFD9;
  storage_cleanup = 0xC00D17BB;
  storage_notify = 0xC008E121;
  storage_lease_control = 0xC008E331;
  storage_driver_control = 0xC0101A7F;
  storage_irq_control = 0xC0071F21;
  storage_shutdown_notify = 0xC00D9615;
  msc_readiness_probe = 0xC0171B79;
  msc_partition_read = 0xC0171BAD;
  msc_worker_startup = 0xC0171BF9;
  media_status_dispatch = 0xC017271F;
  physical_read = 0xC00FE525;
  physical_command = 0xC00FE11D;
  physical_count = 0xC00FE473;
  msc_send_data = 0xC0172D31;
  storage_power_control = 0xC00BEAA3;
  usb_phy_reset = 0xC017DAC9;
  command_sem_wait = 0xC011E0F7;
  phase2_skip = 0xC017D9B0;
  storage_shutdown_skip = 0xC00D95EC;

  .trigger 0xC002EC0E : { *(.trigger) }
  .gw_entry 0xC002F368 : { *(.gw_entry) }
  .storage_helper 0xC002F36A : { *(.storage_helper) }
  .gw_literal 0xC002F6E8 : { *(.gw_literal) }
  .gm_ddr_base 0xC006F8A0 : { *(.gm_ddr_base) }
  .storage_set_desired 0xC008D830 : { *(.storage_set_desired) }
  .storage_call 0xC008D9F8 : { *(.storage_call) }
  .shutdown_gate 0xC00D95CE : { *(.shutdown_gate) }
  .physical_command_single_call 0xC00FE5AA : { *(.physical_command_single_call) }
  .physical_count_single_call 0xC00FE5CA : { *(.physical_count_single_call) }
  .physical_command_multi_call 0xC00FE60E : { *(.physical_command_multi_call) }
  .physical_count_multi_call 0xC00FE62E : { *(.physical_count_multi_call) }
  .capacity_count_fix 0xC0101178 : { *(.capacity_count_fix) }
  .physical_read_call 0xC01011E8 : { *(.physical_read_call) }
  .fifo_hook 0xC0101D5A : { *(.fifo_hook) }
  .sem_hook 0xC0101ECC : { *(.sem_hook) }
  .media_status_call 0xC0171B56 : { *(.media_status_call) }
  .media_status_guard 0xC0171B5C : { *(.media_status_guard) }
  .worker_startup_call 0xC0171DFA : { *(.worker_startup_call) }
  .read10_backend_call 0xC017205A : { *(.read10_backend_call) }
  .read10_send_call 0xC01720A4 : { *(.read10_send_call) }
  .attach_call 0xC017D910 : { *(.attach_call) }
  .teardown_call 0xC017D956 : { *(.teardown_call) }
  .storage_lease_call 0xC017D992 : { *(.storage_lease_call) }
  .phase2_gate 0xC017D99E : { *(.phase2_gate) }
  .msc_probe 0xC019C360 : { *(.msc_probe) }
  .runtime_telemetry 0xC019C390 : { *(.runtime_telemetry) }
  .phase2_runtime 0xC019C67C : { *(.phase2_runtime) }
  .worker_runtime 0xC019C700 : { *(.worker_runtime) }
  .shutdown_runtime 0xC019C860 : { *(.shutdown_runtime) }
  .lease_runtime 0xC019CA00 : { *(.lease_runtime) }
  .fifo_recovery_runtime 0xC019CB00 : { *(.fifo_recovery_runtime) }

  ASSERT(SIZEOF(.runtime_telemetry) <= 0x2EC,
         "runtime telemetry exceeds the C019C390..C019C67B cave")
  ASSERT(SIZEOF(.phase2_runtime) <= 0x84,
         "phase-2 runtime exceeds the C019C67C..C019C6FF cave")
  ASSERT(SIZEOF(.worker_runtime) <= 0x160,
         "worker runtime exceeds the C019C700..C019C85F cave")
  ASSERT(SIZEOF(.shutdown_runtime) <= 0x1A0,
         "shutdown runtime exceeds the C019C860..C019C9FF cave")
  ASSERT(SIZEOF(.lease_runtime) <= 0x100,
         "lease runtime exceeds the C019CA00..C019CAFF cave")
  ASSERT(SIZEOF(.fifo_recovery_runtime) <= 0x500,
         "FIFO/CMD17 telemetry exceeds the audited C019CB00..C019CFFF cave")
}
