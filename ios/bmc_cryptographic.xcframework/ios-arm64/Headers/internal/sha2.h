#ifndef __SHA2_H__
#define __SHA2_H__

#include <stdint.h> // Sử dụng stdint.h tiêu chuẩn
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_BLOCK_LENGTH		64
#define SHA256_DIGEST_LENGTH		32
#define SHA256_DIGEST_STRING_LENGTH	(SHA256_DIGEST_LENGTH * 2 + 1)

typedef struct _SHA256_CTX {
	uint32_t	state[8];
	uint64_t	bitcount;
	uint8_t	    buffer[SHA256_BLOCK_LENGTH];
} SHA256_CTX;


void SHA256_Init(SHA256_CTX*);
void SHA256_Update(SHA256_CTX*, const uint8_t*, size_t);
void SHA256_Final(uint8_t[SHA256_DIGEST_LENGTH], SHA256_CTX*);
char* SHA256_End(SHA256_CTX*, char[SHA256_DIGEST_STRING_LENGTH]);
char* SHA256_Data(const uint8_t*, size_t, char[SHA256_DIGEST_STRING_LENGTH]);

// Hàm one-shot tiện lợi để lấy hash dạng nhị phân
void SHA256_Auth(unsigned char PData[], int len, unsigned char SignData[]);

#ifdef	__cplusplus
}
#endif /* __cplusplus */

#endif /* __SHA2_H__ */