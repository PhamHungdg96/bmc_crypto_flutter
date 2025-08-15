#ifndef BMC_CRYPTO_H
#define BMC_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define BMC_CRYPTO_API __declspec(dllexport)
#else
#define BMC_CRYPTO_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

    // --- HÀM HELPER ---
    // Hàm tính kích thước output sau khi đệm (dùng cho ECB và CBC)
    BMC_CRYPTO_API size_t bmc_aes_get_padded_size(size_t len);

    // ==========================================================
    // --- API CHO CHẾ ĐỘ CBC (Cipher Block Chaining) ---
    // ==========================================================
    BMC_CRYPTO_API int bmc_aes128_cbc_encrypt(const uint8_t* plaintext, size_t len, const uint8_t key[16], const uint8_t iv[16], uint8_t* ciphertext);
    BMC_CRYPTO_API int bmc_aes128_cbc_decrypt(const uint8_t* ciphertext, size_t len, const uint8_t key[16], const uint8_t iv[16], uint8_t* plaintext, size_t* out_len);

    BMC_CRYPTO_API int bmc_aes192_cbc_encrypt(const uint8_t* plaintext, size_t len, const uint8_t key[24], const uint8_t iv[16], uint8_t* ciphertext);
    BMC_CRYPTO_API int bmc_aes192_cbc_decrypt(const uint8_t* ciphertext, size_t len, const uint8_t key[24], const uint8_t iv[16], uint8_t* plaintext, size_t* out_len);

    BMC_CRYPTO_API int bmc_aes256_cbc_encrypt(const uint8_t* plaintext, size_t len, const uint8_t key[32], const uint8_t iv[16], uint8_t* ciphertext);
    BMC_CRYPTO_API int bmc_aes256_cbc_decrypt(const uint8_t* ciphertext, size_t len, const uint8_t key[32], const uint8_t iv[16], uint8_t* plaintext, size_t* out_len);


    // ==========================================================
    // --- API CHO CHẾ ĐỘ ECB (Electronic Codebook) ---
    // ==========================================================
    BMC_CRYPTO_API int bmc_aes128_ecb_encrypt(const uint8_t* plaintext, size_t len, const uint8_t key[16], uint8_t* ciphertext);
    BMC_CRYPTO_API int bmc_aes128_ecb_decrypt(const uint8_t* ciphertext, size_t len, const uint8_t key[16], uint8_t* plaintext, size_t* out_len);

    BMC_CRYPTO_API int bmc_aes192_ecb_encrypt(const uint8_t* plaintext, size_t len, const uint8_t key[24], uint8_t* ciphertext);
    BMC_CRYPTO_API int bmc_aes192_ecb_decrypt(const uint8_t* ciphertext, size_t len, const uint8_t key[24], uint8_t* plaintext, size_t* out_len);

    BMC_CRYPTO_API int bmc_aes256_ecb_encrypt(const uint8_t* plaintext, size_t len, const uint8_t key[32], uint8_t* ciphertext);
    BMC_CRYPTO_API int bmc_aes256_ecb_decrypt(const uint8_t* ciphertext, size_t len, const uint8_t key[32], uint8_t* plaintext, size_t* out_len);


    // ==========================================================
    // --- API CHO CHẾ ĐỘ CTR (Counter) ---
    // ==========================================================
    // Lưu ý: Trong CTR, hàm mã hóa và giải mã là một.
    BMC_CRYPTO_API int bmc_aes128_ctr_xcrypt(const uint8_t* data, size_t len, const uint8_t key[16], const uint8_t iv[16], uint8_t* out_data);
    BMC_CRYPTO_API int bmc_aes192_ctr_xcrypt(const uint8_t* data, size_t len, const uint8_t key[24], const uint8_t iv[16], uint8_t* out_data);
    BMC_CRYPTO_API int bmc_aes256_ctr_xcrypt(const uint8_t* data, size_t len, const uint8_t key[32], const uint8_t iv[16], uint8_t* out_data);
    #define bmc_aes128_ctr_encrypt bmc_aes128_ctr_xcrypt
    #define bmc_aes192_ctr_encrypt bmc_aes192_ctr_xcrypt
    #define bmc_aes256_ctr_encrypt bmc_aes256_ctr_xcrypt
    #define bmc_aes128_ctr_decrypt bmc_aes128_ctr_xcrypt
    #define bmc_aes192_ctr_decrypt bmc_aes192_ctr_xcrypt
    #define bmc_aes256_ctr_decrypt bmc_aes256_ctr_xcrypt

    // --- Phần API cho SHA-256 ---
    #define BMC_SHA256_HASH_SIZE 32
    BMC_CRYPTO_API void bmc_sha256(const uint8_t* data, size_t len, uint8_t output[BMC_SHA256_HASH_SIZE]);

    // --- Phần API cho SHA-3 ---
    #define BMC_SHA3_256_HASH_SIZE 32
    #define BMC_SHA3_384_HASH_SIZE 48
    #define BMC_SHA3_512_HASH_SIZE 64

    BMC_CRYPTO_API void bmc_sha3_256(const uint8_t* data, size_t len, uint8_t output[BMC_SHA3_256_HASH_SIZE]);
    BMC_CRYPTO_API void bmc_sha3_384(const uint8_t* data, size_t len, uint8_t output[BMC_SHA3_384_HASH_SIZE]);
    BMC_CRYPTO_API void bmc_sha3_512(const uint8_t* data, size_t len, uint8_t output[BMC_SHA3_512_HASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // BMC_CRYPTO_H