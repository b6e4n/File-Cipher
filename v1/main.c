
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
    //print_usage(); //https://linuxprograms.wordpress.com/2012/06/22/c-getopt_long-example-accessing-command-line-arguments/

    /*
variables
*/
    unsigned char iv[16];
    unsigned int iv_sz = 16;
    unsigned char key[32];
    unsigned int k_sz = 32;
    char* pwd = NULL;
    unsigned char* buffer_plain = NULL;
    unsigned int p_sz = 0;
    unsigned char* buffer_crypto = NULL;
    unsigned int c_sz = 0x80;
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
        
        printf("chiffrement :%i\n", chiffrement);
        printf("dechiffrement :%i\n", dechiffrement);
        printf("pass :%s\n", password);
        printf("input :%s\n", input);
        printf("output :%s\n", output);

        io_plain = creer_ctx_io();
        preparer_ctx_io(io_plain, input, LECTURE|PLAIN);
        printf("filename plain : %s\n", io_plain->filename);
        printf("flag plain : %i\n", io_plain->flag);

        generer_iv(iv, iv_sz);
        printf("IV: ");
        for (int i = 0; i < iv_sz ; i++) {
            printf("%02x", iv[i]);
        }
        printf("\n");

        construire_clef(password, strlen(password), key, &k_sz);
        printf("key size : %i\n", k_sz);
        printf("KEY: ");
        for (int i = 0; i < k_sz ; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");

        cry = creer_ctx_cry();
        preparer_ctx_cry(cry, key, k_sz, iv, iv_sz);
        printf("CRY key size : %i\n",cry->key_sz);
        printf("CRY KEY: ");
        for (int i = 0; i < cry->key_sz ; i++) {
            printf("%02x", cry->key[i]);
        }
        printf("\n");
        printf("CRY iv size : %i\n", cry->iv_sz);
        printf("CRY IV: ");
        for (int i = 0; i < cry->iv_sz ; i++) {
            printf("%02x", cry->iv[i]);
        }
        printf("\n");

        io_crypto = creer_ctx_io();
        preparer_ctx_io(io_crypto, output, ECRITURE|CRYPTO);
        printf("filename crypto : %s\n", io_crypto->filename);
        printf("flag crypto : %i\n", io_crypto->flag);

        p_sz = data_size(io_plain);
        printf("size of the plain file : %i\n", p_sz);

        buffer_plain = (unsigned char*) malloc(p_sz);
        buffer_crypto = (unsigned char*) malloc(p_sz);

        lire_all_data(io_plain, buffer_plain, p_sz);
        printf("buffer plain : %s\n", buffer_plain);


        
    }
        

    /*
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
    
    p_sz = data_size(io_plain);

    buffer_crypto = (unsigned char*) malloc(c_sz);
    buffer_plain = (unsigned char*) malloc(p_sz);

    lire_all_data(io_plain, buffer_plain, c_sz+1);
    printf("buffer plain : %s\n", buffer_plain);

    
    // --> chiffrer les datas contenues dans buffer_plain
    chiffrer_all_data(cry, buffer_plain, p_sz, buffer_crypto, c_sz);
    //dechiffrer_all_data(cry,buffer_plain, c_sz, buffer_crypto, c_sz);
    // --> ecrire le iv + le chiffré dans un fichier fichier.bin
    detruire_ctx_cry(cry);
    detruire_ctx_io(io_plain);

    */

    return 0;
}
