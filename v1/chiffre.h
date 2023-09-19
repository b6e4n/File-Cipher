#include <stdlib.h>

typedef struct {
unsigned char* key;
unsigned int key_sz;
unsigned char* iv; //à utiliser pour chainage entre appel
//à chiffrer_data() et déchiffrer_data()
unsigned int iv_sz;
//autres champs utiles ...
} contexte_cry;


contexte_cry* creer_ctx_cry();


int detruire_ctx_cry(contexte_cry* ctx_cry);


/*
à l’appel ctx_cry pointe vers une structure contexte_cry déjà allouée
*/
int preparer_ctx_cry(contexte_cry* ctx_cry, unsigned char* key, unsigned int key_sz, unsigned char* iv, unsigned int iv_sz);


/*
à l’appel buffer_crypto pointe vers un buffer de *buffer_crypto_sz octets
déjà alloué
en sortie, *buffer_crypto_sz contient le nombre d’octets effectivement
utilisés dans buffer_crypto
si la taille de buffer_crypto est inférieure à la taille nécessaire,
la fonction retourne un code d’erreur et *buffer_crypto_sz vaut 0
*/

int chiffrer_all_data(contexte_cry* ctx_cry, unsigned char* buffer_plain, unsigned int buffer_plain_sz, unsigned char* buffer_crypto, unsigned int* buffer_crypto_sz);


/*
à l’appel buffer_plain pointe vers un buffer de *buffer_plain_sz octets
déjà alloué
en sortie, *buffer_plain_sz contient le nombre d’octets effectivement
utilisés dans buffer_plain
si la taille de buffer_plain est inférieure à la taille nécessaire,
la fonction retourne un code d’erreur et *buffer_plain_sz vaut 0
*/
int dechiffrer_all_data(contexte_cry* ctx_cry, unsigned char* buffer_plain, unsigned int* buffer_plain_sz, unsigned char* buffer_crypto, unsigned int buffer_crypto_sz);
