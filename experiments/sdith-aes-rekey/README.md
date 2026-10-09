# A/B experiment: is `OQS_AES128_ECB_rekey` measurable in SDitH?

This branch exists only to document the code changes behind the measurements of
db057513d ("Add AES rekey function for AES128 ECB"). It is **not** intended to be
merged.

## What the patch does

Two compile-time switches, both no-ops unless defined:

| Macro | File | Effect |
| --- | --- | --- |
| `SDITH_NO_AES_REKEY` | `src/sig/sdith/sdith_sdith_common_base/aes_glue.c` | **The no-rekey baseline.** `aes128_set_key_reuse_ref` frees the old schedule and calls `OQS_AES128_ECB_load_schedule` instead of `OQS_AES128_ECB_rekey` — i.e. what the glue would have to do if the rekey entry point did not exist. |
| `OQS_AES_OSSL_REKEY_FULL` | `src/common/aes/aes_ossl.c` | The OpenSSL `AES128_ECB_rekey` tears down and rebuilds the `EVP_CIPHER_CTX` instead of re-initialising the key in place. This is the uncommitted working-tree variant of `aes_ossl.c` as of 2026-10-09. |

`SDITH_COUNT_REKEY` additionally exposes `sdith_rekey_calls` / `sdith_loadsched_calls`
so the call counts can be read from a driver program.

## Builds

All seven builds come from this one tree; only the configure flags differ.
`-DOQS_MINIMAL_BUILD="SIG_sdith_sdith3_l1_gf2_short;SIG_sdith_sdith3_l1_gf2_fast"`
and `-DCMAKE_BUILD_TYPE=Release` throughout.

| Build | Extra configure flags | AES backend |
| --- | --- | --- |
| `ossl-rekey` | (none) | OpenSSL EVP |
| `ossl-norekey` | `-DCMAKE_C_FLAGS=-DSDITH_NO_AES_REKEY` | OpenSSL EVP |
| `ossl-fullrekey` | `-DCMAKE_C_FLAGS=-DOQS_AES_OSSL_REKEY_FULL` | OpenSSL EVP |
| `arm-rekey` | `-DOQS_USE_AES_OPENSSL=OFF -DOQS_USE_ARM_AES_INSTRUCTIONS=ON` | ARMv8 AES (`no_bitslice`) |
| `arm-norekey` | as above, plus `-DCMAKE_C_FLAGS=-DSDITH_NO_AES_REKEY` | ARMv8 AES |
| `c-rekey` | `-DOQS_USE_AES_OPENSSL=OFF` | bitsliced C (`ct64`) |
| `c-norekey` | as above, plus `-DCMAKE_C_FLAGS=-DSDITH_NO_AES_REKEY` | bitsliced C |

On Apple Silicon `OQS_USE_ARM_AES_INSTRUCTIONS` is not auto-detected (the probe in
`.CMake/gcc_clang_intrinsics.cmake` compiles without `+crypto`), so it is forced on
for the `arm-*` builds.

`OQS_USE_AES_OPENSSL` defaults to ON whenever OpenSSL is found and
`OQS_USE_AES_INSTRUCTIONS` is off, which is the case for an ordinary arm64 build —
so `ossl-*` is the default configuration on that platform, not an exotic one.

## Drivers

- `count_rekey.c` — prints `OQS_AES128_ECB_rekey` call counts for one sign and one
  verify. Needs a build with `-DSDITH_COUNT_REKEY -fvisibility=default`.
- `bench_sdith.c` — `./bench <alg> <sign|verify> <iters>`, prints
  `median min max` wall time in ms over `iters` calls.

```
cc -O2 -I<build>/include bench_sdith.c -o bench <build>/lib/liboqs.a -lcrypto
```

The reported numbers are the median over 5 rounds of per-call medians, with the
seven binaries run round-robin inside each round so that frequency and thermal
drift are shared across variants. 25 iterations per run for `-short`, 151 for
`-fast`. `results-raw.txt` has every round:
`round alg op variant median min max`.

## Results (Apple M1, macOS 27.0, clang, OpenSSL 3.6.4)

Call counts per operation:

| Algorithm | kappa | tau | rekeys per sign | per verify |
| --- | --- | --- | --- | --- |
| SDitH3-L1-gf2-short | 11 | 11 | 45177 | 45055 |
| SDitH3-L1-gf2-fast | 7 | 18 | 4746 | 4607 |

`SDitH3-L1-gf2-short`, sign (ms):

| Backend | rekey | no-rekey baseline | delta | speedup |
| --- | --- | --- | --- | --- |
| OpenSSL EVP | 22.699 | 29.155 | 6.456 | 1.284x |
| OpenSSL EVP, ctx rebuild | 27.723 | 29.155 | 1.432 | 1.052x |
| ARMv8 AES | 33.834 | 34.731 | 0.897 | 1.027x |
| bitsliced C | 34.004 | 34.619 | 0.615 | 1.018x |

`SDitH3-L1-gf2-fast`, sign (ms):

| Backend | rekey | no-rekey baseline | delta | speedup |
| --- | --- | --- | --- | --- |
| OpenSSL EVP | 17.250 | 17.907 | 0.657 | 1.038x |
| OpenSSL EVP, ctx rebuild | 17.777 | 17.907 | 0.130 | 1.007x |
| ARMv8 AES | 18.261 | 18.323 | 0.062 | 1.003x |
| bitsliced C | 18.247 | 18.294 | 0.047 | 1.003x |

Verify tracks sign closely; see `results-raw.txt`.

Per-call saving implied by `-short` sign: ~143 ns (OpenSSL), ~20 ns (ARMv8 AES),
~14 ns (bitsliced C).

## Scope caveat

The SDitH AVX2 variants set `extend_leaf_seed` to `extend_leaf_seed_cat1_aes128_avx2`
and `prepare_extseed_buf` to `extseed_buf_noop` (`vole_parameters_avx2.c`), so they
never enter the liboqs AES glue on this path and get no benefit at all. Cat3 and cat5
use Rijndael-256 and never call it either. The rekey path is reached only by
**cat1 (L1) `_ref`** builds.
