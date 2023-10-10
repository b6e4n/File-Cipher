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
    
    return 0;
}
