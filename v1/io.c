#include "io.h"

#include <stdio.h>
#include <stdlib.h>

contexte_io* creer_ctx_io(){

    contexte_io * io_crypto = malloc(sizeof(contexte_io));
    return io_crypto;
}

int detruire_ctx_io(contexte_io* ctx_io){

    free(ctx_io);
    return 0;
}


int preparer_ctx_io(contexte_io* ctx_io, char* filename, int flag){

    ctx_io->filename = filename;
    ctx_io->flag = flag;
    return 0;
}


int lire_all_data(contexte_io* ctx_io, unsigned char* buffer, unsigned int sz){
    
   FILE *f = fopen(ctx_io->filename, "r");
   size_t bytesRead;

    if (f == NULL) {
        printf("Erreur lors de l'ouverture du fichier %s pour écrire les données, vérifier que celui-ci existe bien\n", ctx_io->filename);
        exit(-1);
    }
//Dans le cas d'un fichier chiffré, on ne lit pas l'IV
    if(ctx_io->flag < 8){
        fseek(f, 16, SEEK_SET);
        bytesRead = fread(buffer, 1, sz, f);

        if (bytesRead == 0) {
            printf("Erreur lors de la lecture du fichier chiffré %s\n", ctx_io->filename);
            fclose(f);
            exit(-1);
        }

    } else{

        bytesRead = fread(buffer, 1, sz, f);

        if (bytesRead == 0) {
            printf("Erreur lors de la lecture du fichier chiffré %s\n", ctx_io->filename);
            fclose(f);
            exit(-1);
        }

    }
    fclose(f);
    return bytesRead;
}


unsigned int data_size(contexte_io* ctx_io){
    
    if((ctx_io->flag & 0x2) == 0x2){
        printf("La fonction data_size ne peut pas être utilisée sur un fichier en écriture\n");
        return 0;
    }
    
    FILE* f = fopen(ctx_io->filename, "r"); 
  
    if (f == NULL) { 
        printf("Le fichier %s n'a pas pu être ouvert, vérifier que celui-ci existe\n", ctx_io->filename); 
        exit(-1); 
    } 

    fseek(f, 0L, SEEK_END);
    long int res = ftell(f); 
    fclose(f); 
    
    if((ctx_io->flag & 0x4) == 0x4){
        return res - 16;
    } else if((ctx_io->flag & 0x8) == 0x8){
        return res;
    } else{
        exit(-1);
    }

}


int lire_iv(contexte_io* ctx_io, unsigned char* iv, unsigned int* iv_sz){

    int numread = 0;
    FILE *f = fopen(ctx_io->filename, "r" );
    if(  f != NULL ){
       numread = fread( iv, 1, *iv_sz, f );
      fclose( f );

   } else{
      printf( "Le fichier %s n'a pu être ouvert, vérifier son existence\n", ctx_io->filename );
      *iv_sz = 0;
      exit(-1);
   }

   return numread;
}


int ecrire_iv(contexte_io* ctx_io, unsigned char* iv, unsigned int iv_sz){

    int numwrite = 0;
    FILE *f = fopen(ctx_io->filename, "w");
    if (f != NULL){
        numwrite = fwrite(iv, sizeof(char), iv_sz, f);  

    } else {
        printf( "Le fichier %s n'a pu être ouvert, vérifier son existence\n", ctx_io->filename );
        exit(-1);
    }
    fclose( f );
    return numwrite;

}


int ecrire_all_data(contexte_io* ctx_io, unsigned char* buffer, unsigned int sz){

    int numwrite = 0;
    FILE *f = fopen(ctx_io->filename, "a");
    if (f != NULL){
        numwrite = fwrite(buffer, sizeof(char), sz, f);
        
    } else {
        printf( "Le fichier %s n'a pu être ouvert, vérifier son existence\n", ctx_io->filename );
        exit(-1);
    }
    fclose(f);
    return numwrite;
}