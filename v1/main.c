
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

    int opt= 0;
    int chiffrement = -1, dechiffrement = -1, password = -1, input =-1, output =-1;

    //Specifying the expected options
    //The two options l and b expect numbers as argument
    static struct option long_options[] = {
        {"chiffrement",      no_argument,       0,  'c' },
        {"dechiffrement", no_argument,       0,  'd' },
        {"password",    required_argument, 0,  'p' },
        {"input",   required_argument, 0,  'i' },
        {"output",   required_argument, 0,  'o' },
        {0,           0,                 0,  0   }
    };

    int long_index =0;
    while ((opt = getopt_long(argc, argv,"cdp:i:o:", 
                   long_options, &long_index )) != -1) {
        switch (opt) {
             case 'c' : chiffrement = 0;
                 break;
             case 'd' : dechiffrement = 0;
                 break;
             case 'p' : password = atoi(optarg); 
                 break;
             case 'i' : input = atoi(optarg);
                 break;
             case 'o' : output = atoi(optarg);
                 break;
             default: print_usage(); 
                 exit(EXIT_FAILURE);
        }
    }
    if (password == -1 || input ==-1 || output ==-1) {
        print_usage();
        exit(EXIT_FAILURE);
    }
    
/*
variables
*/
    unsigned char iv[16];
    unsigned int iv_sz = 16;
    unsigned char key[32];
    unsigned int k_sz = 32;
    char pwd[80] = "MOTDEPASSE";
    unsigned char* buffer_plain = NULL;
    unsigned int p_sz = 0;
    unsigned char* buffer_crypto = NULL;
    unsigned int c_sz = 0x80;
    contexte_io* io_crypto = NULL;
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

    return 0;
}
