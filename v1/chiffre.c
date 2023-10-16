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

    unsigned char * padded_buffer_plain;
    unsigned char * iv_copy;

    size_t buffer_size = sizeof(buffer_plain);

    printf("Size of the buffer_plain just before encryption in bytes: %zu\n", buffer_size);
    /*
    --> gestion du pading à gérer, AES CBC chiffre par bloc de 16 bytes, dans l'énoncé il est marqué que le pading se fait à 0x80 = 128
    --> Dans l'exemple mbedtls, le padding est fait à 48
    --> il va falloir ajouter 0x80 et des 0 à la fin pour avoir une tailler de 128
    */
   /*
    unsigned char* padded_buffer = (unsigned char*)malloc(0x80);
    if (padded_buffer == NULL) {
        printf("Memory allocation failed.\n");
        return 0;
    }
    memcpy(padded_buffer, buffer_plain, buffer_plain_sz);
    memset(padded_buffer + buffer_plain_sz, 0x80, 0x80 - buffer_plain_sz);
    memset(padded_buffer + buffer_plain_sz + 1, 0, 0x80 - buffer_plain_sz - 1);
    */

   int padding = 16 - (buffer_plain_sz % 16);
   padded_buffer_plain = (unsigned char*) malloc(*buffer_crypto_sz);

   if (padded_buffer_plain != NULL) {
        printf("buffer_plain_sz : %i\n", buffer_plain_sz);
        // Copy the first 16 bytes from source_data to destination_data
        memcpy(padded_buffer_plain, buffer_plain, buffer_plain_sz);

        // Set the 16th byte to 0x80
        padded_buffer_plain[buffer_plain_sz] = 0x80;

        // Fill the remaining bytes in destination_data with null bytes using a for loop
        for (int i = buffer_plain_sz; i < padding; i++) {
            padded_buffer_plain[i] = 0;
        }
        printf("padded_buffer_plain : %s\n", padded_buffer_plain);
        // Now, destination_data contains the first 16 bytes of source_data with the 16th byte set to 0x80 and the rest filled with null bytes

        // You can use destination_data as needed
    }
    size_t buffer_size_2 = sizeof(padded_buffer_plain);
/*
    printf("Size of the buffer_padded just before encryption in bytes: %zu\n", buffer_size_2);
    
    printf("PADDED BUFFER CLAIR: ");
    for (int i = 0; i < 128 ; i++) {
        printf("%c", padded_buffer[i]);
    }
    printf("\n");
    printf("longueur padded %i\n", strlen(padded_buffer));
     printf("PADDED: ");
    for (int j = 0; j < 128 ; j++) {
        printf("%c", padded_buffer[j]);
    }
    printf("\n");
    printf("\n");
    */

   printf("INSIDE CHIFFRMEENT b4iv size : %i\n", iv_sz);
        printf("INSIDE CHIFFREMENT b4 IV: ");
        for (int i = 0; i < iv_sz ; i++) {
            printf("%02x", iv[i]);
        }
        printf("\n");
        iv_copy = (unsigned char *) malloc(16);
    memcpy(iv_copy, iv, iv_sz);
    mbedtls_aes_context aes;
    mbedtls_aes_setkey_enc( &aes, key, 256 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, *buffer_crypto_sz, iv, padded_buffer_plain, buffer_crypto );
    //buffer_plain = padded_buffer;
    printf("INSIDE CHIFFRMEENT afeter iv size : %i\n", iv_sz);
        printf("INSIDE CHIFFREMENT after IV: ");
        for (int i = 0; i < iv_sz ; i++) {
            printf("%02x", iv[i]);
        }
        printf("\n");
    printf("INSIDE CHIFFRMEENT afeter ctx-cry iv size : %i\n", ctx_cry->iv_sz);
        printf("INSIDE CHIFFREMENT after ctx-cry IV: ");
        for (int i = 0; i < ctx_cry->iv_sz ; i++) {
            printf("%02x", ctx_cry->iv[i]);
        }
        printf("\n");

        printf("INSIDE CHIFFRMEENT afeter iv_copy size : %i\n", ctx_cry->iv_sz);
        printf("INSIDE CHIFFREMENT after iv_copy IV: ");
        for (int i = 0; i < ctx_cry->iv_sz ; i++) {
            printf("%02x", iv_copy[i]);
        }
        printf("\n");
    
    printf("CHIFFRE: ");
    for (int i = 0; i < *buffer_crypto_sz ; i++) {
        printf("%02x", buffer_crypto[i]);                     
    }
    printf("\n");
    printf("longueur chiffre %i\n", strlen(buffer_crypto));
    
    mbedtls_aes_free(&aes);
    ctx_cry->iv = iv_copy;
    printf("INSIDE CHIFFRMEENT COPYYY afeter iv_copy size : %i\n", ctx_cry->iv_sz);
        printf("INSIDE CHIFFREMENT COPYYYY after iv_copy IV: ");
        for (int i = 0; i < ctx_cry->iv_sz ; i++) {
            printf("%02x", ctx_cry->iv[i]);
        }
        printf("\n");
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
    unsigned char *key = ctx_cry->key; 
    unsigned char *iv = ctx_cry->iv;
    printf("B4 DECRYPT IV: ");
    for (int i = 0; i < 16 ; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    printf("B4 DECRYPT KEY: ");
    for (int j = 0; j < 32 ; j++) {
        printf("%02x", key[j]);
    }
    printf("\n");
    printf("\n");
    printf("B4 DECRYPT CHIFFRE: ");
    for (int i = 0; i < 128 ; i++) {
        printf("%c", buffer_crypto[i]);
    }
    printf("\n");
    printf("B4 DECRYPT longueur chiffre %i\n", strlen(buffer_crypto));
    printf("valeurde buffer_crypto_sz : %i\n", buffer_crypto_sz);
    mbedtls_aes_init(&aes_ctx);

    // Set the decryption key
    mbedtls_aes_setkey_dec(&aes_ctx, key, 256);

    // Perform decryption
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, buffer_crypto_sz, iv, buffer_crypto, buffer_plain);

    // Clean up the AES context
    mbedtls_aes_free(&aes_ctx);

    printf("DECHIFFRE: ");
    for (int i = 0; i < 128 ; i++) {
        printf("%c", buffer_plain[i]);
    }
    printf("\n");
    printf("longueur dechiffre %i\n", strlen(buffer_plain));
    return 0;
}
