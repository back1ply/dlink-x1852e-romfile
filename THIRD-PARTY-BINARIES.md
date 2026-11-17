# Third-party firmware binaries (not distributed)

The AES key/IV documented in this repo were read out of two D-Link/Airoha firmware
binaries. Those binaries are **not** included here — they are vendor copyright. They
live on the device at the paths below; pull them from your own unit if you want to
verify the findings.

| path on device | size (bytes) | SHA-256 |
|----------------|-------------:|---------|
| `/userfs/bin/azencrypt` | 18492 | `1737fe50e830c28b273203b2e2d7114facd69a38423bd05e8a695353894cb43c` |
| `/lib/libcfg_clisvc.so` | 606639 | `08e1ac29a45e69b5fc94b7cae52fa4a3cdd8654946f36a0cc07658302dd4720a` |

Firmware tested: `EG_1.00b15` (DSL-X1852E rev. A1).

To verify the key yourself: disassemble `azencrypt` and look at `main()` — it loads the
ASCII key string into the first argument of `aes_expand_key`, and a 16-byte `.data`
constant as the IV for `aes_cbc_decrypt_blocks`.
