CC = gcc
CFLAGS = -Wall -O2

MBEDTLS_INC = .
MBEDTLS_LIB = library

all: cipher

cipher: main.o generation.o clef.o chiffre.o io.o
	$(CC) $(CFLAGS) -o protect main.o generation.o clef.o chiffre.o io.o -L$(MBEDTLS_LIB) -lmbedtls -lmbedcrypto -lmbedx509

main.o: main.c
	$(CC) $(CFLAGS) -I$(MBEDTLS_INC) -c main.c 

generation.o: generation.c
	$(CC) $(CFLAGS) -I$(MBEDTLS_INC) -c generation.c

clef.o: clef.c
	$(CC) $(CFLAGS) -I$(MBEDTLS_INC) -c clef.c

chiffre.o: chiffre.c
	$(CC) $(CFLAGS) -I$(MBEDTLS_INC) -c chiffre.c

io.o: io.c
	$(CC) $(CFLAGS) -I$(MBEDTLS_INC) -c io.c

clean:
	rm -f protect *.o
