# ARMv8 AES-128 key schedule via `AESE`

Replaces the bitsliced `sub_word` in liboqs' ARM AES key schedule with a two-instruction
`AESE`-based `SubWord`. Measured on Apple M1: AES-128 key setup drops from 327.5 ns to
58.5 ns, and SDitH3-L1-gf2-short signing drops from 33.7 ms to 22.2 ms (~1.5x).

## Why the current code is slow

`aes_keysched_no_bitslice` (`src/common/aes/aes_c.c`) calls `sub_word`, which
orthogonalises one word, runs the full BearSSL ct64 **bitsliced S-box**, then
de-orthogonalises — roughly a hundred operations to substitute four bytes, ten times per
AES-128 key. So liboqs' ARM backend uses `aese`/`aesmc` for *encryption* but a portable
software S-box for *key setup*.

The `no_bitslice` name refers to the round-key **storage format**, not the derivation:
the ct64 backend must store round keys orthogonalised (`aes128ctx` = `uint64_t
sk_exp[88]`), whereas `aese` wants plain 16-byte round keys, hence `aes128ctx_nobitslice`
= `uint32_t sk_exp[44]` (176 bytes). The derivation still went through the bitsliced
S-box only because `sub_word` happened to live in `aes_c.c`.

x86 has no such problem: AES-NI provides `AESKEYGENASSIST`, used at `aes128_ni.c:30`.
**ARMv8 deliberately has no key-schedule instruction** — the position was that `AESE`
with a zero round key gives you `ShiftRows(SubBytes(.))`, which suffices.

## The trick

`AESE Vd.16B, Vn.16B` computes `ShiftRows(SubBytes(Vd ^ Vn))` (AddRoundKey first, unlike
x86's `AESENC`). With a zero round key that is `ShiftRows(SubBytes(.))`. Broadcasting the
word into all four 32-bit lanes makes every AES row hold four equal bytes, and `ShiftRows`
only rotates *within* a row — so it becomes the identity, and every lane of the result is
`SubWord(x)`.

Still constant time: `aese` is data-independent in hardware and uses no tables, so this
keeps the property the bitsliced S-box was there to provide.

## Validation

`validate_and_bench.c` compares the round keys against
`OQS_AES128_ECB_load_schedule`/`_rekey` output and times both. Build against a liboqs
tree configured with `-DOQS_USE_AES_OPENSSL=OFF -DOQS_USE_ARM_AES_INSTRUCTIONS=ON`:

```
cc -O2 -mcpu=native -I<build>/include validate_and_bench.c -o ks <build>/lib/liboqs.a -lcrypto
```

Results on Apple M1 / clang / OpenSSL 3.6.4:

- 0 round-key mismatches over 200,000 random keys
- matches the FIPS-197 C.1 round-10 key (byte-reversed, per the little-endian word storage)
- `test_aes` passes; SDitH `kat_sig` output unchanged
- disassembly is `dup.4s` / `aese.16b` / `fmov`, no spills or staging buffers

## Scope and limits

- **AES-128 only.** AES-192/256 still use `aes_keysched_no_bitslice`. The same trick
  applies; AES-256 also exercises the `nk > 6 && j == 4` branch (a `SubWord` with no
  `RotWord`).
- **Headroom remains.** This version round-trips through a GPR each round
  (`dup` -> `aese` -> `fmov`); 58.5 ns is ~187 cycles, well above the ~10-deep `aese`
  latency chain. A fully vectorised schedule stays in NEON registers and chains words
  with `ext`/`eor`.
- **Only reached with `-DOQS_USE_AES_OPENSSL=OFF`.** `OQS_USE_AES_OPENSSL` defaults ON
  whenever OpenSSL is found and `OQS_USE_AES_INSTRUCTIONS` is off, and that condition
  excludes only `OQS_DIST_X86_64_BUILD` — so an ordinary arm64 build, dist included,
  uses the OpenSSL EVP backend.
- **Few beneficiaries beyond SDitH.** FrodoKEM-AES and friends set up one schedule and
  encrypt many blocks. SDitH's GGM trees are key-setup-bound, which is what exposes this.

With this change the ARM native backend becomes slightly *faster* than the OpenSSL EVP
backend (22.2 vs 22.6 ms sign, 20.4 vs 21.1 ms verify), which raises the question of
whether arm64 should still default to OpenSSL for AES.
