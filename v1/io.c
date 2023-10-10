#include "io.h"

#include <stdio.h>

contexte_io* creer_ctx_io(){
    printf("Create context IO\n");
    contexte_io * io_crypto = malloc(sizeof(contexte_io));
    printf("Context IO created\n");
    return io_crypto;
}

int detruire_ctx_io(contexte_io* ctx_io){
    free(ctx_io);
    return 0;
}


int preparer_ctx_io(contexte_io* ctx_io, char* filename, int flag){
    ctx_io->filename = filename;
    ctx_io->flag = flag;
}

int lire_all_data(contexte_io* ctx_io, unsigned char* buffer, unsigned int sz){
    FILE* fichier = NULL;
    printf("Ouverture du fichier\n");
    fichier = fopen(ctx_io->filename, "r");

    if(fichier!=NULL){
        printf("Lecture du fichier\n");
        while (fgets(buffer, sz, fichier) != NULL)
        {
            printf("%s", buffer);
        }

    } else{
        printf("Erreur à la lecture du fichier\n");

        return 0;
    }
    fclose(fichier);
    return 0;
}