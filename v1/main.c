
#include "generation.h"
#include "clef.h"
#include "chiffre.h"
#include "io.h"

#include <string.h>
#include <stdio.h>

#define LECTURE 0x01
#define ECRITURE 0x02
#define CRYPTO 0x04
#define PLAIN 0x08

int main() {
    
/*
variables
*/
    unsigned char iv[16];
    unsigned int iv_sz = 16;
    unsigned char key[32];
    unsigned int k_sz = 32;
    char pwd[80] = "MOTDEPASSE";
    unsigned char* buffer_plain = NULL;
    //unsigned int p_sz = 0;
    unsigned char* buffer_crypto = NULL;
    unsigned int c_sz = 0;
    //contexte_io* io_crypto = NULL;
    contexte_io* io_plain = NULL;
    contexte_cry* cry = NULL;

    //Chiffrement d'un texte clair
    io_plain = creer_ctx_io();
    preparer_ctx_io(io_plain, "fichier_clair", ECRITURE|PLAIN);

    //Génération d'un IV
    generer_iv(iv, iv_sz);

    //Génération de la clé depuis le mot de passe pwd
    construire_clef(pwd,strlen(pwd), key, &k_sz);
    
    //initialisation crypto
    cry = creer_ctx_cry();
    
    //preparation du contexte crypto
    preparer_ctx_cry(cry,key, k_sz, iv, iv_sz);


    printf("k_sz = %i\n", k_sz);
    printf("KEY: ");
    for (int i = 0; i < k_sz ; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    printf("iv_sz = %i\n", iv_sz);
    printf("IV: ");
    for (int i = 0; i < iv_sz ; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    
    buffer_plain = malloc(sizeof(unsigned char)*1000);
    lire_all_data(io_plain, buffer_plain, 1000);
    printf("buffer plain : %s\n", buffer_plain);

    // --> chiffrer les datas contenues dans buffer_plain
    // --> ecrire le iv + le chiffré dans un fichier fichier.bin
    detruire_ctx_cry(cry);
    detruire_ctx_io(io_plain);

    return 0;
}
