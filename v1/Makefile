CC = gcc
CFLAGS = -Wall -O2

# Add the path to mbedtls include and library directories
MBEDTLS_INC = .
MBEDTLS_LIB = library

all: protect

protect: main.o generation.o clef.o
	$(CC) $(CFLAGS) -o protect main.o generation.o clef.o -L$(MBEDTLS_LIB) -lmbedtls -lmbedcrypto -lmbedx509

main.o: main.c
	$(CC) $(CFLAGS) -I$(MBEDTLS_INC) -c main.c 

generation.o: generation.c
	$(CC) $(CFLAGS) -I$(MBEDTLS_INC) -c generation.c

clef.o: clef.c
	$(CC) $(CFLAGS) -I$(MBEDTLS_INC) -c clef.c

clean:
	rm -f protect *.o
