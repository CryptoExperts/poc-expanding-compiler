# Protected n-share AES-128

This project is an implementation in C of a protected n-share AES-128 introduced in the following publication :

> [Random Probing Security: Verification, Composition, Expansion and New Constructions](https://eprint.iacr.org/2020/786)  
> By Sonia Belaïd, Jean-Sébastien Coron, Emmanuel Prouff, Matthieu Rivain and Abdul Rahman Taleb 
> In the proceedings of CRYPTO 2020.

It is a compiled program that uses for basic operations, gadgets  G<sub>add</sub><sup>(k)</sup>, G<sub>copy</sub><sup>(k)</sup> and G<sub>mult</sub><sup>(k)</sup>, as described in the paper.

## Content

This repository contains the code of the protected AES-128 implemented in C:

* __main.c:__ contains the main function that executes the AES-128 encryption and decryption algorithms.

In **aes_files** folder:

* __aes128.h, aes128.c:__ contains a standard implementation of the AES-128 algorithm to compare with the protected n-share implemented version.
* __aes128_sharing.h, aes128_sharing.c:__ contains the protected implementation of the n-share AES-128 algorithm.
* __gadgets.h, gadgets.c:__ contains the three n-share gadgets functions (add, copy, mult), as well as the n-share variables generation and compression functions.
* __gf256.h, gf256.c:__ contains the functions for addition and multiplication in the field GF(256).
* __Makefile:__ to compile the program

## Usage

Using the program requires having a gcc compiler with the standard math library (uses the flag `-lm`).

To compile the program :

```
make
```

To clean :

```
make clean
```

To run AES-128 algorithm :

```
./main
```

Plaintext and key values should be specified in the file `main.c` 

## Gadgets Specification

When changing number of shares, and gadgets, only two files have to be modified : `gadgets.h` and `gadgets.c`

In the file `gadget.h`, the user should specify the value for the macro NB_SHARES : 

```
#define NB_SHARES 3
```

for example for a 3-share execution.

As for the gadgets, the user should modify in the file `gadgets.c` the functions:

```
void add_gadget_function(uint8_t * a, uint8_t * b, uint8_t * c)
void copy_gadget_function(uint8_t * a, uint8_t * d, uint8_t * e)
void mult_gadget_function(uint8_t * a, uint8_t * b, uint8_t * c)
```

These 3 functions have been generated using the gadget compiler available in the same repository (check the folder _Compiler_). The user can simply recreate these functions using the compiler (G<sub>add</sub><sup>(k)</sup>, G<sub>copy</sub><sup>(k)</sup> and G<sub>mult</sub><sup>(k)</sup>), and use them in this implementation. By default, we use a 27-share AES-128 using the 3-share gadgets construction from the paper, compiled with the expanding circuit compiler with expansion level `k = 3`.

## Output Format (Example)

An execution example outputs the following on the standard output :

```
$ ./main
Round Keys:
 f 15 71 c9 47 d9 e8 59  c b7 ad d6 af 7f 67 98 
dc 90 37 b0 9b 49 df e9 97 fe 72 3f 38 81 15 a7 
d2 c9 6b b7 49 80 b4 5e de 7e c6 61 e6 ff d3 c6 
c0 af df 39 89 2f 6b 67 57 51 ad  6 b1 ae 7e c0 
2c 5c 65 f1 a5 73  e 96 f2 22 a3 90 43 8c dd 50 
58 9d 36 eb fd ee 38 7d  f cc 9b ed 4c 40 46 bd 
71 c7 4c c2 8c 29 74 bf 83 e5 ef 52 cf a5 a9 ef 
37 14 93 48 bb 3d e7 f7 38 d8  8 a5 f7 7d a1 4a 
48 26 45 20 f3 1b a2 d7 cb c3 aa 72 3c be  b 38 
fd  d 42 cb  e 16 e0 1c c5 d5 4a 6e f9 6b 41 56 
b4 8e f3 52 ba 98 13 4e 7f 4d 59 20 86 26 18 76 

REGULAR ENCRYPTION SUCCESS
SHARING ENCRYPTION SUCCESS

Cipher text:
ff  b 84 4a  8 53 bf 7c 69 34 ab 43 64 14 8f b9 


Timings: 

AES standard enc took 0.061035 ms

AES standard dec took 0.056028 ms


AES sharing enc took 291.994095 ms

AES sharing dec took 235.274792 ms
```

The program first outputs the values of the round keys taken after the `key expansion` step, before any encryption/decryption :

```
Round Keys:
 f 15 71 c9 47 d9 e8 59  c b7 ad d6 af 7f 67 98 
dc 90 37 b0 9b 49 df e9 97 fe 72 3f 38 81 15 a7 
d2 c9 6b b7 49 80 b4 5e de 7e c6 61 e6 ff d3 c6 
c0 af df 39 89 2f 6b 67 57 51 ad  6 b1 ae 7e c0 
2c 5c 65 f1 a5 73  e 96 f2 22 a3 90 43 8c dd 50 
58 9d 36 eb fd ee 38 7d  f cc 9b ed 4c 40 46 bd 
71 c7 4c c2 8c 29 74 bf 83 e5 ef 52 cf a5 a9 ef 
37 14 93 48 bb 3d e7 f7 38 d8  8 a5 f7 7d a1 4a 
48 26 45 20 f3 1b a2 d7 cb c3 aa 72 3c be  b 38 
fd  d 42 cb  e 16 e0 1c c5 d5 4a 6e f9 6b 41 56 
b4 8e f3 52 ba 98 13 4e 7f 4d 59 20 86 26 18 76 
```

Then, the program first runs regular (no shares) AES-128 encryption/decryption, and if the decryption of the ciphertext outputs the original plaintext, the program outputs :

```
REGULAR ENCRYPTION SUCCESS
```

Then, the program runs the secure n-share  AES-128 encryption/decryption, and if the decryption of the ciphertext outputs the original plaintext, and the recombination of the ciphertext shares gives the same ciphertext as the one with the regular AES-128 encryption,  the program outputs :

```
SHARING ENCRYPTION SUCCESS
```

Finally, the program outputs the resulting ciphertext:

```
Cipher text:
ff  b 84 4a  8 53 bf 7c 69 34 ab 43 64 14 8f b9 
```

And timings for each of the standard and n-share AES-128 encryption/decryption :

```
Timings: 

AES standard enc took 0.061035 ms

AES standard dec took 0.056028 ms


AES sharing enc took 291.994095 ms

AES sharing dec took 235.274792 ms
```

If any of the outputs is incorrect, the program specifies an error (this shouldn't occur).

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)

