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


unsigned int data_size(contexte_io* ctx_io){
    FILE* fp = fopen(ctx_io->filename, "r"); 
  
    // checking if the file exist or not 
    if (fp == NULL) { 
        printf("File Not Found!\n"); 
        return -1; 
    } 
  
    fseek(fp, 0L, SEEK_END); 
  
    // calculating the size of the file 
    long int res = ftell(fp); 
  
    // closing the file 
    fclose(fp); 
    
    printf("Size of the file : %i\n", res);
    return res; 

}


int lire_iv(contexte_io* ctx_io, unsigned char* iv, unsigned int* iv_sz){

    FILE *stream = fopen(ctx_io->filename, "r" );
    if(  stream != NULL ){
      // Attempt to read in 25 characters
      int numread = fread( iv, sizeof( char ), iv_sz, stream );
      printf( "Number of items read = %d\n", numread );
      printf( "Contents of buffer = %.25s\n", iv );
      fclose( stream );
   }
   else{
      printf( "File could not be opened\n" );

   }
      
}


int ecrire_iv(contexte_io* ctx_io, unsigned char* iv, unsigned int iv_sz){
    FILE *stream = fopen(ctx_io->filename, "w");
    if (stream != NULL){
        int numwrite = fwrite(iv, sizeof(char), iv_sz, stream);
        printf( "Number of items read = %d\n", numwrite );
        printf( "Contents of buffer = %.25s\n", iv );
        fclose( stream );
    } else {
        printf( "File could not be opened\n" );
    }

}