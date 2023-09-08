
#include "generation.h"
#include "clef.h"

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
    //unsigned char* buffer_plain = NULL;
    //unsigned int p_sz = 0;
    //unsigned char* buffer_crypto = NULL;
    //unsigned int c_sz = 0;
    //contexte_io* io_crypto = NULL;
    //contexte_io* io_plain = NULL;
    //contexte_cry* cry = NULL;


    generer_iv(iv, iv_sz);
    construire_clef(pwd,strlen(pwd), key, &k_sz);

    return 0;
}
