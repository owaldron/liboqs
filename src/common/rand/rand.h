/**
 * \file rand.h \brief Random number generator.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef OQS_RANDOM_H
#define OQS_RANDOM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <oqs/common.h>

#if defined(__cplusplus)
extern "C" {
#endif

/** Algorithm identifier for system PRNG. */
#define OQS_RAND_alg_system "system"
/** Algorithm identifier for using OpenSSL's PRNG. */
#define OQS_RAND_alg_openssl "OpenSSL"

/**
 * Switches `OQS_randombytes` AND `OQS_randombytes_soft_fail` to use the specified algorithm.
 *
 * @warning In case you have set a custom algorithm using `OQS_randombytes_custom_algorithm` before,
 * this function will overwrite it again. Hence, you have to set your custom algorithm again after
 * calling this function.
 *
 * @param[in] algorithm The name of the algorithm to use.
 * @return OQS_SUCCESS if `algorithm` is a supported algorithm name, OQS_ERROR otherwise.
 */
OQS_API OQS_STATUS OQS_randombytes_switch_algorithm(const char *algorithm);

/**
 * Switches `OQS_randombytes` to use the given function.
 *
 * @warning This does not update `OQS_randombytes_soft_fail`'s behaviour. To update this at the same
 * time, wrap the function in a no-exit wrapper and call
 * `OQS_randombytes_soft_fail_custom_algorithm` instead.
 *
 * This allows additional custom RNGs besides the provided ones. The provided RNG function must have
 * the same signature as `OQS_randombytes`.
 *
 * @param[in] algorithm_ptr Pointer to the RNG function to use.
 */
OQS_API void OQS_randombytes_custom_algorithm(void (*algorithm_ptr)(uint8_t *, size_t));

/**
 * Switches `OQS_randombytes_soft_fail` to use the given function. This also updates
 * `OQS_randombytes` (which exits when algorithm_ptr returns `OQS_ERROR`).
 *
 * This allows additional custom RNGs besides the provided ones. The provided RNG function must have
 * the same signature as `OQS_randombytes_soft_fail`.
 *
 * @param[in] algorithm_ptr Pointer to the RNG function to use.
 */
OQS_API void OQS_randombytes_soft_fail_custom_algorithm(OQS_STATUS (*algorithm_ptr)(uint8_t *, size_t));

/**
 * Fills the given memory with the requested number of (pseudo)random bytes.
 *
 * Internally, this calls `OQS_randombytes_soft_fail` and exits the program if it returns an error
 * unless overwritten by a custom algorithm. This implementation uses whichever algorithm has been
 * selected by OQS_randombytes_switch_algorithm. The default is OQS_RAND_alg_openssl, which uses
 * OpenSSL's PRNG. Otherwise, it is OQS_RAND_alg_system, which reads bytes from a system specific
 * default source.
 *
 * The caller is responsible for providing a buffer allocated with sufficient room.
 *
 * @param[out] random_array Pointer to the memory to fill with (pseudo)random bytes
 * @param[in] bytes_to_read The number of random bytes to read into memory
 */
OQS_API void OQS_randombytes(uint8_t *random_array, size_t bytes_to_read);

/**
 * Fills the given memory with the requested number of (pseudo)random bytes.
 *
 * This implementation uses whichever algorithm has been selected by
 * OQS_randombytes_switch_algorithm. The default is OQS_RAND_alg_openssl, which uses OpenSSL's PRNG.
 * Otherwise, it is OQS_RAND_alg_system, which reads bytes from a system specific default source.
 *
 * The caller is responsible for providing a buffer allocated with sufficient room.
 *
 * @param[out] random_array Pointer to the memory to fill with (pseudo)random bytes
 * @param[in] bytes_to_read The number of random bytes to read into memory
 * @return OQS_SUCCESS if the operation was successful, and OQS_ERROR otherwise.
 */
OQS_API OQS_STATUS OQS_randombytes_soft_fail(uint8_t *random_array, size_t bytes_to_read);

#if defined(__cplusplus)
} // extern "C"
#endif

#endif // OQS_RANDOM_H
