#include "chiffre.h"
#include "mbedtls/aes.h"


contexte_cry* creer_ctx_cry(){
    printf("Context preparation\n");
    contexte_cry* ctx = malloc(sizeof(contexte_cry));
    printf("context created\n");
    return ctx;
}


int detruire_ctx_cry(contexte_cry* ctx_cry){
    free(ctx_cry);
    return 0;
}


/*
à l’appel ctx_cry pointe vers une structure contexte_cry déjà allouée
*/
int preparer_ctx_cry(contexte_cry* ctx_cry, unsigned char* key, unsigned int key_sz, unsigned char* iv, unsigned int iv_sz){
    printf("context waiting for set up");
    ctx_cry->key = key;
    ctx_cry->key_sz = key_sz;
    ctx_cry->iv = iv;
    ctx_cry->iv_sz = iv_sz;
    printf("KEY: ");
    for (int i = 0; i < key_sz ; i++) {
        printf("%02x", key[i]);
    }
    printf("KEY_SZ: %i\n", key_sz);
    printf("IV: ");
    for (int i = 0; i < 16 ; i++) {
        printf("%02x", iv[i]);
    }
    printf("IV_SZ: %i\n", iv_sz);
    printf("context set up\n");
    return 0;
}


/*
à l’appel buffer_crypto pointe vers un buffer de *buffer_crypto_sz octets
déjà alloué
en sortie, *buffer_crypto_sz contient le nombre d’octets effectivement
utilisés dans buffer_crypto
si la taille de buffer_crypto est inférieure à la taille nécessaire,
la fonction retourne un code d’erreur et *buffer_crypto_sz vaut 0
*/

int chiffrer_all_data(contexte_cry* ctx_cry, unsigned char* buffer_plain, unsigned int buffer_plain_sz, unsigned char* buffer_crypto, unsigned int* buffer_crypto_sz){
    mbedtls_aes_context aes;
    unsigned char* key = ctx_cry->key;
    unsigned int key_sz = ctx_cry->key_sz;
    unsigned char* iv = ctx_cry->iv;

    printf("KEY: ");
    for (int i = 0; i < key_sz ; i++) {
        printf("%02x", key[i]);
    }
    printf("KEY_SZ: %i", key_sz);
    printf("IV: ");
    for (int i = 0; i < 16 ; i++) {
        printf("%02x", iv[i]);
    }
    printf("BUFFER_PLAIN: ");
    for (int i = 0; i < buffer_plain_sz ; i++) {
        printf("%02x", buffer_plain[i]);
    }
    printf("BUFFER_PLAIN_SZ: %i", buffer_plain_sz);
    printf("BUFFER_PLAIN_CRYPTO: ");
    for (int i = 0; i < *buffer_crypto_sz ; i++) {
        printf("%02x", buffer_crypto[i]);
    }
    printf("BUFFER_CRYPTO_SZ: %i", buffer_crypto_sz);

    mbedtls_aes_setkey_enc( &aes, key, key_sz );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 48, iv, buffer_plain, buffer_crypto );

    
    printf("\n"); 

    mbedtls_aes_free(&aes);
    return 0;
}


/*
à l’appel buffer_plain pointe vers un buffer de *buffer_plain_sz octets
déjà alloué
en sortie, *buffer_plain_sz contient le nombre d’octets effectivement
utilisés dans buffer_plain
si la taille de buffer_plain est inférieure à la taille nécessaire,
la fonction retourne un code d’erreur et *buffer_plain_sz vaut 0
*/
int dechiffrer_all_data(contexte_cry* ctx_cry, unsigned char* buffer_plain, unsigned int *buffer_plain_sz, unsigned char* buffer_crypto, unsigned int buffer_crypto_sz){
    mbedtls_aes_context aes;
    unsigned char* key = ctx_cry->key;
    unsigned int key_sz = ctx_cry->key_sz;
    unsigned char* iv = ctx_cry->iv;
    
    int setkey = mbedtls_aes_setkey_enc( &aes, key, key_sz );
    if( setkey != 0){
        printf("MBEDTLS_ERR_AES_INVALID_KEY_LENGTH\n");
        return setkey;
    }
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 48, iv, buffer_crypto, buffer_plain );
    
    
    mbedtls_aes_free(&aes);
    return 0;
}
