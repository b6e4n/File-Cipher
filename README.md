# Protect

L’objectif est de préparer une base de discussion sur le développement d’un utilitaire de
chiffrement permettant de chiffrer un simple fichier. L’utilitaire utilisera un mot de passe pour protéger le fichier, l’interface sera en ligne de commande et fonctionnera sous plateforme Linux.

Dans cette première version, l'utilitaire est permet de chiffrer et de déchiffrer un fichier via un mot de passe fourni par l'utilisateur.
Le chiffrement utilisé est l'AES-256 en mode CBC.

## Compilation du projet

Dans le répertoire v1 se situe le Makefile de la première version.
$ cd v1
$ make

## Utilisation de l'utilitaire Protect

Exemple d'utilisation :
- Chiffrement   --> protect -c -p motdepasse -i fichier_clair.txt -o fichier_chiffre.bin
- Déchiffrement --> protect -d -p motdepasse -i fichier_chiffre.bin -o fichier_chiffre.txt

L'aide peut être affichée via l'option -h : protect -h


## Bug observé

Dans cette v1, la création d'un fichier chiffrée entraîne la création d'un fichier annexe avec des caractères aléatoires dû à un problème de gestion de chaîne pour créer le nom d'un fichier (la lecture du nom de ficheird éborde sur d'autres espaces mémoires que celui attribué à la variable filename)
