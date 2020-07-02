CC=gcc -std=c11 -w
LIBR=-lm
FLAGS=-O0
SUBF=./aes_files/
DEPS = $(SUBF)gf256.h $(SUBF)aes128.h $(SUBF)gadgets.h $(SUBF)aes128_sharing.h

all: main

main: main.o $(DEPS)
	$(CC) $(FLAGS) -o main main.c $(SUBF)gf256.c $(SUBF)aes128.c $(SUBF)gadgets.c $(SUBF)aes128_sharing.c $(LIBR)

main.o: main.c $(DEPS)
	$(CC) $(FLAGS) -c main.c $(LIBR)
	
$(SUBF)gf256.o: $(SUBF)gf256.c $(DEPS)
	$(CC) $(FLAGS) -c  $(SUBF)gf256.c $(LIBR)
	
$(SUBF)gadgets.o: $(SUBF)gadgets.c $(DEPS)
	$(CC) $(FLAGS) -c  $(SUBF)gadgets.c $(LIBR)
	
$(SUBF)aes128.o: $(SUBF)aes128.c $(DEPS)
	$(CC) $(FLAGS) -c  $(SUBF)aes128.c $(LIBR)
	
$(SUBF)aes128_sharing.o: $(SUBF)aes128_sharing.c $(DEPS)
	$(CC) $(FLAGS) -c  $(SUBF)aes128_sharing.c $(LIBR)

clean:
	rm -f *.o $(SUBF)*.o main
