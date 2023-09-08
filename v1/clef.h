/*
à l’appel key pointe vers un buffer déjà alloué de *k_sz octets
en sortie, *k_sz contient le nombre d’octets effectivement
utilisés dans key
*/

int construire_clef(char* pwd, unsigned int pwd_sz, unsigned char* key, unsigned int *k_sz );