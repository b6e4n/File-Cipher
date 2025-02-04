# File-Cipher

The objective is to prepare a discussion base for the development of an encryption utility that allows encrypting a single file. The utility will use a password to protect the file, and its interface will be command-line based, running on a Linux platform.

In this first version, the utility enables encrypting and decrypting a file using a password provided by the user.
The encryption method used is AES-256 in CBC mode.

# Build

The Makefile for the first version is located in the v1 directory.
```
$ cd v1  
$ make
```

# Using the File-Cipher Utility

Example usage:

    Encryption → cipher -c -p password -i plaintext.txt -o encrypted.bin
    Decryption → cipher -d -p password -i encrypted.bin -o decrypted.txt

Help can be displayed using the -h option:
```sh
cipher -h  
```
