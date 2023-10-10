#include "mbedtls/sha256.h"
#include <stdio.h>

#include "clef.h"

int construire_clef(char* pwd, unsigned int pwd_sz, unsigned char* key, unsigned int *k_sz ){
    mbedtls_sha256_context sha256;
    mbedtls_sha256_init(&sha256);
    mbedtls_sha256_starts(&sha256, 0); // 0 for SHA-256
    mbedtls_sha256_update(&sha256, pwd, pwd_sz);
    mbedtls_sha256_finish(&sha256, key);
    mbedtls_sha256_free(&sha256);
    int written = sizeof(key)*4;
    k_sz = &written;
    printf("value stored in k_sz = %i\n", *k_sz);
    printf("CLEF: ");
    for (int i = 0; i < *k_sz ; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    return *k_sz;
}