
typedef struct {
    char* filename;
    unsigned int offset; //offset courant dans le fichier
    unsigned int flag; //notamment, chiffré ou clair
    //autres champs utiles ...
} contexte_io;


contexte_io* creer_ctx_io();

int detruire_ctx_io(contexte_io* ctx_io);

/*
à l’appel ctx_io pointe vers une structure contexte_io déjà allouée
filename est une chaine de caractères se terminant par \0
flag sera utilisé pour passer différentes options (lecture, écriture,
clair, chiffré, etc.)
*/
int preparer_ctx_io(contexte_io* ctx_io, char* filename, int flag);


/*
place dans iv la valeur lue depuis le fichier correspondant à ctx_io.
à l’appel, iv pointe vers un buffer de *iv_sz octets
déjà alloué
en sortie, *iv_sz contient le nombre d’octets effectivement
utilisés dans iv si la taille de iv est inférieure à la taille nécessaire,
la fonction retourne un code d’erreur et *iv_sz vaut 0
ne doit être appelée que sur un fichier chiffré
*/
int lire_iv(contexte_io* ctx_io, unsigned char* iv, unsigned int* iv_sz);


/*
écrit l’iv dans le fichier correspondant à ctx_io
utilise la zone pointée par iv pour écrire l’iv
dans le fichier
ne doit être appelée que sur un fichier chiffré
*/
int ecrire_iv(contexte_io* ctx_io, unsigned char* iv, unsigned int iv_sz);


/*
lit depuis le fichier correspondant à ctx_io la totalité des
données
à l’appel ctx_io pointe vers une structure contexte_io déjà alloué et
buffer pointe vers un buffer déjà alloué de sz octets
*/
int lire_all_data(contexte_io* ctx_io, unsigned char* buffer, unsigned int sz);


/*
écrit dans le fichier correspondant à ctx_io les sz octets de buffer
à l’appel ctx_io pointe vers une structure contexte_io déjà alloué et
buffer pointe vers un buffer déjà alloué de sz octets
*/
int ecrire_all_data(contexte_io* ctx_io, unsigned char* buffer, unsigned int sz);


/*
retourne le nombre d’octets de données dans le fichier
retourne 0 si le fichier correspondant à ctx_io est en écriture
*/
unsigned int data_size(contexte_io* ctx_io);