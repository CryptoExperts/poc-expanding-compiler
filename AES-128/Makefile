CC=gcc -std=c11 -w
LIBR=-lm
FLAGS=-O0
DEPS = gf256.h aes128.h gadgets.h aes128_sharing.h

all: main

main: main.o $(DEPS)
	$(CC) $(FLAGS) -o main main.c gf256.c aes128.c gadgets.c aes128_sharing.c $(LIBR)

main.o: main.c $(DEPS)
	$(CC) $(FLAGS) -c main.c $(LIBR)
	
gf256.o: gf256.c $(DEPS)
	$(CC) $(FLAGS) -c  gf256.c $(LIBR)
	
gadgets.o: gadgets.c $(DEPS)
	$(CC) $(FLAGS) -c  gadgets.c $(LIBR)
	
aes128.o: aes128.c $(DEPS)
	$(CC) $(FLAGS) -c  aes128.c $(LIBR)
	
aes128_sharing.o: aes128_sharing.c $(DEPS)
	$(CC) $(FLAGS) -c  aes128_sharing.c $(LIBR)

clean:
	rm -f *.o main
