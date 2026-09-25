SECTIONS
{
  svc_9r_read_handler = 0xC006F827;
  cat_parse_hex_param = 0xC006DF39;
  cat_reply_hex_echo = 0xC006EE67;
  cat_error_reply = 0xC002FA05;
  memcpy_n = 0xC00113CB;
  input_dispatch = 0xC0056319;

  .gm_adapter_call 0xC002EC04 : { *(.gm_adapter_call) }
  .gm_read_call 0xC006F8AC : { *(.gm_read_call) }
  .automation_runtime 0xC019D280 : { *(.automation_runtime) }

  ASSERT(SIZEOF(.gm_adapter_call) == 4,
         "GM adapter hook must remain one Thumb BL")
  ASSERT(SIZEOF(.gm_read_call) == 4,
         "GM reader hook must remain one Thumb BL")
  ASSERT(SIZEOF(.automation_runtime) <= 0xD80,
         "automation runtime exceeds C019D280..C019DFFF")
  ASSERT(FRAME_WIDTH * 2 == FRAME_STRIDE,
         "RGB565 row width and framebuffer stride disagree")
  ASSERT(FRAME_STRIDE * FRAME_HEIGHT == FRAME_BYTES,
         "framebuffer geometry and byte length disagree")
  ASSERT(FRAME_WORDS * 4 == FRAME_BYTES,
         "framebuffer word count and byte length disagree")
  ASSERT(AUTOMATION_SNAPSHOT_A == AUTOMATION_META + 0x100,
         "raw snapshot must immediately follow 0x100-byte metadata")
  ASSERT(AUTOMATION_SNAPSHOT_A + FRAME_BYTES <= AUTOMATION_SNAPSHOT_B,
         "raw and RLE/comparison framebuffers overlap")
  ASSERT(AUTOMATION_SNAPSHOT_B - AUTOMATION_META == AUTOMATION_RLE_OFFSET,
         "RLE metadata offset does not map to snapshot B")
  ASSERT(AUTOMATION_SNAPSHOT_B + FRAME_BYTES == 0xC01CA480,
         "RLE/comparison framebuffer exceeds its reviewed cave")
  ASSERT(AUTOMATION_VIRTUAL_RAW_END - AUTOMATION_VIRTUAL_RAW_BASE ==
         0x100 + FRAME_BYTES,
         "raw virtual aperture has the wrong size")
  ASSERT(AUTOMATION_VIRTUAL_RLE_END - AUTOMATION_VIRTUAL_RLE_BASE ==
         FRAME_BYTES,
         "RLE virtual aperture has the wrong size")
}
