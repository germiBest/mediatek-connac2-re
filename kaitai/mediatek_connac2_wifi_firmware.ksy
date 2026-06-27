meta:
  id: mediatek_connac2_wifi_firmware
  title: MediaTek connac2 Wi-Fi MCU firmware (WIFI_RAM_CODE_*)
  file-extension: bin
  endian: le
  license: CC0-1.0
doc: |
  Container for MediaTek "connac2" Wi-Fi MCU firmware images, the
  WIFI_RAM_CODE_* blobs used by MT7921 / MT7922 / MT7961 / MT7915 (the mt76
  driver's `mt76_connac2_load_ram` path).

  Layout: region payloads are concatenated from the start of the file; a
  36-byte trailer sits at EOF, immediately preceded by `n_region` 40-byte
  region headers. The host (driver) scatter-loads each region to its `addr`
  and starts execution at the region flagged OVERRIDE_ADDR.

  Notes from reverse engineering:
   * The connac2 WM core is Tensilica Xtensa (LE, 32-bit) with custom
     vendor TIE opcodes.
   * The image is plaintext (not encrypted); integrity is a plain
     `zlib.crc32(file[:-4])` stored in the trailer.
doc-ref: 'https://github.com/openwrt/mt76 mt76_connac_mcu.h (mt76_connac2_fw_trailer / _fw_region)'
instances:
  trailer:
    pos: _io.size - 36
    type: trailer
  region_headers:
    pos: '_io.size - 36 - trailer.n_region * 40'
    type: region_header
    repeat: expr
    repeat-expr: trailer.n_region
types:
  trailer:
    seq:
      - id: chip_id
        type: u1
      - id: eco_code
        type: u1
      - id: n_region
        type: u1
      - id: format_ver
        type: u1
      - id: format_flag
        type: u1
      - id: reserved
        size: 2
      - id: fw_ver
        type: str
        size: 10
        encoding: ASCII
      - id: build_date
        type: str
        size: 15
        encoding: ASCII
      - id: crc
        type: u4
        doc: zlib.crc32 over the whole file except these last 4 bytes.
  region_header:
    seq:
      - id: decomp_crc
        type: u4
      - id: decomp_len
        type: u4
        doc: Uncompressed length; 0 means the region is stored raw (always 0 here).
      - id: decomp_blk_sz
        type: u4
      - id: reserved0
        size: 4
      - id: addr
        type: u4
        doc: Destination address the region is scatter-loaded to in MCU memory.
      - id: len
        type: u4
      - id: feature_set
        type: u1
      - id: region_type
        type: u1
      - id: reserved1
        size: 14
    instances:
      # mt76 FW_FEATURE_* bit decode. Region payload offsets are the running sum
      # of prior region lengths, left to tooling (Kaitai has no array running-sum).
      set_encrypt:
        value: '(feature_set & 0x01) != 0'
      key_index:
        value: '(feature_set >> 1) & 0x03'
      encrypt_mode:
        value: '(feature_set & 0x10) != 0'
      override_addr:
        value: '(feature_set & 0x20) != 0'
        doc: This region's addr is the firmware entry / start-override address.
      non_dl:
        value: '(feature_set & 0x40) != 0'
        doc: Region is not downloaded to the chip.
