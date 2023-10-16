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
    

   FILE *f = fopen(ctx_io->filename, "r");
   size_t bytesRead;

    if (f == NULL) {
        perror("Erreur lors de l'ouverture du fichier");
        return -1;
    }

    if(ctx_io->flag < 8){
        printf("Je suis dans le cas d'une lecture defichier chiffre, je skip le IV\n");
        fseek(f, 16, SEEK_SET);
        bytesRead = fread(buffer, 1, sz, f);

        if (bytesRead == 0) {
            perror("Erreur lors de la lecture du fichier");
            fclose(f);
            return -1;
        }

    } else{
        // Lecture du contenu du fichier dans le tampon
        bytesRead = fread(buffer, 1, sz, f);

        if (bytesRead == 0) {
            perror("Erreur lors de la lecture du fichier");
            fclose(f);
            return -1;
        }

    }

    

    // Fermeture du fichier
    fclose(f);

    return bytesRead;
    
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
    printf("filename where trying to read IV : %s\n", ctx_io->filename);
    if(  stream != NULL ){
      // Attempt to read in 25 characters
      int numread = fread( iv, 1, *iv_sz, stream );
      //printf( "Number of items read = %d\n", numread );
      //printf( "Contents of buffer = %.25s\n", iv );
      
      fclose( stream );
      
   }
   else{
      printf( "File could not be opened\n" );
      *iv_sz = 0;
      exit(-1);

   }
   printf("size of iv_sz = %i\n", *iv_sz);
   printf("IV: ");
      for (int i = 0; i < *iv_sz ; i++) {
          printf("%02x", iv[i]);
      }
      printf("\n");
      
}


int ecrire_iv(contexte_io* ctx_io, unsigned char* iv, unsigned int iv_sz){
    FILE *stream = fopen(ctx_io->filename, "w");
    
    if (stream != NULL){
        printf("IV: ");
        for (int i = 0; i < iv_sz ; i++) {
            printf("%02x", iv[i]);
        }
        printf("\n");
        int numwrite = fwrite(iv, sizeof(char), iv_sz, stream);
        printf( "Number of items written iv in crypto file = %d\n", numwrite );
        //printf( "Contents of buffer iv in crypto file = %s\n", iv );
        
    } else {
        printf( "File could not be opened\n" );
    }
    
    fclose( stream );
    return 0;

}


int ecrire_all_data(contexte_io* ctx_io, unsigned char* buffer, unsigned int sz){
    FILE *stream = fopen(ctx_io->filename, "a");
    if (stream != NULL){
        int numwrite = fwrite(buffer, sizeof(char), sz, stream);
        
    } else {
        printf( "File could not be opened\n" );
    }
    fclose(stream);
    return 0;
}