
#include "generation.h"
#include "clef.h"
#include "chiffre.h"
#include "io.h"

#include <string.h>
#include <stdio.h>
#include <getopt.h>

#define LECTURE 0x01
#define ECRITURE 0x02
#define CRYPTO 0x04
#define PLAIN 0x08


void print_usage(){
    printf("Usage : protect [option]\n");
    printf("    -c mode chiffrement\n");
    printf("    -d mode déchiffrement\n");
    printf("    -p <mot de passe> mot de passe à utiliser\n");
    printf("    -i <fichier> fichier d’entrée\n");
    printf("    -o <fichier> fichier de sortie\n");
    printf("    -h affiche cette aide\n");
}

int main(int argc, char *argv[]) {
    

    /*
variables
*/
    unsigned char iv[16];
    unsigned int iv_sz = 16;
    unsigned char key[32];
    unsigned int k_sz = 0;
    unsigned char* buffer_plain = NULL;
    unsigned int p_sz = 0;
    unsigned char* buffer_crypto = NULL;
    unsigned int c_sz = 0;
    contexte_io* io_crypto = NULL;
    contexte_io* io_plain = NULL;
    contexte_cry* cry = NULL;

    int opt= 0;
    int chiffrement = -1, dechiffrement = -1;
    char *password = NULL, *input = NULL, *output = NULL;

    while ((opt = getopt(argc, argv,"cdp:i:o:")) != -1) {
        switch (opt) {
             case 'c' : chiffrement = 0;
                 break;
             case 'd' : dechiffrement = 0;
                 break;
             case 'p' : password = optarg; 
                 break;
             case 'i' : input = optarg;
                 break;
             case 'o' : output = optarg;
                 break;
             default: print_usage(); 
                 exit(EXIT_FAILURE);
        }
    }
    if (password == NULL || input == NULL || output ==NULL) {
        print_usage();
        exit(EXIT_FAILURE);
    }
    

    if(chiffrement == 0 && dechiffrement == -1){
        

        io_plain = creer_ctx_io();
        preparer_ctx_io(io_plain, input, LECTURE|PLAIN);
        

        generer_iv(iv, iv_sz);
        

        construire_clef(password, strlen(password), key, &k_sz);
        

        cry = creer_ctx_cry();
        preparer_ctx_cry(cry, key, k_sz, iv, iv_sz);
        


        io_crypto = creer_ctx_io();
        preparer_ctx_io(io_crypto, output, ECRITURE|CRYPTO);

        p_sz = data_size(io_plain);

        buffer_plain = (unsigned char*) malloc(p_sz);

        c_sz = (p_sz / 16) * 16 + 16;
        buffer_crypto = (unsigned char*) malloc(c_sz);
        lire_all_data(io_plain, buffer_plain, p_sz);

        chiffrer_all_data(cry, buffer_plain, p_sz, buffer_crypto, &c_sz);
        
        ecrire_iv(io_crypto, cry->iv, cry->iv_sz);
        
        ecrire_all_data(io_crypto, buffer_crypto, c_sz);
        


        detruire_ctx_cry(cry);
        detruire_ctx_io(io_plain);
        detruire_ctx_io(io_crypto);
        free(buffer_crypto);
        free(buffer_plain);
    
    } else if(chiffrement == -1 && dechiffrement == 0){
        
        io_crypto = creer_ctx_io();
        preparer_ctx_io(io_crypto, input, LECTURE|CRYPTO);
        construire_clef(password, strlen(password), key, &k_sz);
        

        lire_iv(io_crypto, iv, &iv_sz);
        

        cry = creer_ctx_cry();
        preparer_ctx_cry(cry, key, k_sz, iv, iv_sz);
        

        io_plain = creer_ctx_io();
        preparer_ctx_io(io_plain, output, ECRITURE|PLAIN);

        c_sz = data_size(io_crypto);

        buffer_crypto = (unsigned char*) malloc(c_sz);
        buffer_plain = (unsigned char*) malloc(c_sz);

        lire_all_data(io_crypto, buffer_crypto, c_sz);
        dechiffrer_all_data(cry, buffer_plain, &p_sz, buffer_crypto, c_sz);
        ecrire_all_data(io_plain, buffer_plain, p_sz);

        detruire_ctx_cry(cry);
        detruire_ctx_io(io_crypto);
        detruire_ctx_io(io_plain);
        free(buffer_crypto);
        free(buffer_plain);

    
        
    } else{
        print_usage();
    }
        
    return 0;
}
