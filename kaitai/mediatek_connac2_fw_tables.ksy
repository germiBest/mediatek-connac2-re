meta:
  id: mediatek_connac2_fw_tables
  title: MediaTek connac2 WM firmware in-image dispatch tables (MT7961)
  endian: le
  license: CC0-1.0
doc: |
  Parses the firmware's internal {handler, id} dispatch tables out of the
  rodata region (region1, load addr 0x02015c00) of an MT7961 WM image. Each
  entry is { u4 handler_addr, u4 id }; a table runs until the handler is no
  longer a valid code pointer (region0 0x915000-0x96dc10 or IRAM region3).

  NOTE on the terminator: `repeat: until` evaluates its condition AFTER parsing
  each element, so the first non-code (stop) entry is itself included as the
  LAST element of every table array. Consumers should drop that final element;
  it is the terminator, not a real dispatch entry.

  Apply this to the EXTRACTED region1 payload (the region whose addr==0x02015c00;
  carve it with the container .ksy / extract_fw). The instance offsets below are
  the region1-relative file offsets for THIS MT7961 build
  (____010000 / 20260224110949); other builds/chips put the tables elsewhere -
  find them by the label strings that precede each table (e.g.
  "bssUniCmdBssInfoBasic" right before the BSS TLV table).
params:
  - id: code_lo
    type: u4
  - id: code_hi
    type: u4
instances:
  # MCU command dispatch, id == the UNI/EXT command cid the host sends.
  cmd_table:
    pos: 0xd0e0          # VA 0x02022ce0
    type: dispatch_entry
    repeat: until
    repeat-until: 'not _.handler_is_code or _.id >= 0x100'
  # BSS_INFO_UPDATE per-TLV handlers, id == UNI_BSS_INFO_* tag.
  bss_tlv_table:
    pos: 0x2520          # VA 0x02018120
    type: dispatch_entry
    repeat: until
    repeat-until: 'not _.handler_is_code or _.id >= 0x100'
  # STA_REC_UPDATE per-TLV handlers.
  sta_rec_tlv_table:
    pos: 0x22f0          # VA 0x02017ef0
    type: dispatch_entry
    repeat: until
    repeat-until: 'not _.handler_is_code or _.id >= 0x100'
  # DEV_INFO / second TLV table.
  dev_tlv_table:
    pos: 0x2380          # VA 0x02017f80
    type: dispatch_entry
    repeat: until
    repeat-until: 'not _.handler_is_code or _.id >= 0x100'
types:
  dispatch_entry:
    seq:
      - id: handler_addr
        type: u4
      - id: id
        type: u4
    instances:
      handler_is_code:
        value: '(handler_addr >= _root.code_lo and handler_addr < _root.code_hi) or (handler_addr >= 0xe0270000 and handler_addr < 0xe027cad0)'
