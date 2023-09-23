
#include "generation.h"
#include "clef.h"
#include "chiffre.h"

#include <string.h>

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
    //contexte_io* io_plain = NULL;
    contexte_cry* cry = NULL;


    generer_iv(iv, iv_sz);
    printf("IV: ");
    for (int i = 0; i < iv_sz; i++) {
        printf("%02x", iv[i]);
    }
    printf("iv_sz: %i\n",iv_sz);
    printf("k_sz: %i\n", k_sz);
    printf("&k_sz: %i\n", &k_sz);
    construire_clef(pwd,strlen(pwd), key, &k_sz);
    printf("CLEF: ");
    for (int i = 0; i < k_sz ; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    

    //initialisation crypto
    cry = creer_ctx_cry();
    
    preparer_ctx_cry(cry,key, k_sz, iv, iv_sz);
    unsigned char * message = "bonjour";
    c_sz = strlen(message);
    printf("C_SZ : %i\n", c_sz);

    //operation crypto
    buffer_crypto = (unsigned char*) malloc(c_sz);
   
    buffer_plain = (unsigned char*) malloc(c_sz);
    
    memcpy(buffer_plain, message, c_sz);
    buffer_plain[c_sz] = '\0';
    printf("BUFFERPLAIN: %s", buffer_plain);


    chiffrer_all_data(cry,buffer_plain,c_sz,buffer_crypto,c_sz);
    dechiffrer_all_data(cry,buffer_plain, c_sz,buffer_crypto,c_sz);

    return 0;
}
