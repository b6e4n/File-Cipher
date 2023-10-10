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
    printf("context waiting for set up\n");
    ctx_cry->key = key;
    ctx_cry->key_sz = key_sz;
    ctx_cry->iv = iv;
    ctx_cry->iv_sz = iv_sz;
    
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
    unsigned char * key = ctx_cry->key;
    unsigned char * iv = ctx_cry->iv;
    unsigned int k_sz = ctx_cry->key_sz;
    unsigned int iv_sz = ctx_cry->iv_sz;

    unsigned char input [128];
    unsigned char output[128];

    /*
    --> gestion du pading à gérer, AES CBC chiffre par bloc de 16 bytes, dans l'énoncé il est marqué que le pading se fait à 0x80 = 128
    --> Dans l'exemple mbedtls, le padding est fait à 48
    --> il va falloir ajouter 0x80 et des 0 à la fin pour avoir une tailler de 128
    */

    unsigned char* padded_buffer = (unsigned char*)malloc(0x80);
    if (padded_buffer == NULL) {
        printf("Memory allocation failed.\n");
        return 0;
    }
    memcpy(padded_buffer, buffer_plain, buffer_plain_sz);
    memset(padded_buffer + buffer_plain_sz, 0x80, 0x80 - buffer_plain_sz);
    memset(padded_buffer + buffer_plain_sz + 1, 0, 0x80 - buffer_plain_sz - 1);
    
    printf("PADDED BUFFER CLAIR: ");
    for (int i = 0; i < 128 ; i++) {
        printf("%c", padded_buffer[i]);
    }
    printf("\n");
    printf("longueur padded %i\n", strlen(padded_buffer));
    mbedtls_aes_context aes;
    mbedtls_aes_setkey_enc( &aes, key, 256 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 0x80, iv, padded_buffer, buffer_crypto );
    buffer_plain = padded_buffer;

    printf("CHIFFRE: ");
    for (int i = 0; i < 128 ; i++) {
        printf("%c", buffer_crypto[i]);
    }
    printf("\n");
    printf("longueur chiffre %i\n", strlen(buffer_crypto));
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
    mbedtls_aes_context aes_ctx;
    unsigned char key = ctx_cry->key; // 128-bit AES key
    unsigned char iv = ctx_cry->iv;  // 128-bit IV

    mbedtls_aes_init(&aes_ctx);

    // Set the decryption key
    mbedtls_aes_setkey_dec(&aes_ctx, key, 128);

    // Perform decryption
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, buffer_plain_sz, iv, buffer_crypto, buffer_plain);

    // Clean up the AES context
    mbedtls_aes_free(&aes_ctx);

    printf("Buffer déchiffré : %s\n", buffer_plain);
    return 0;
}
