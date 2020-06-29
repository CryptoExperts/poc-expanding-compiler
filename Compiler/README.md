# Expanding Circuit Compiler

This program is an implementation in SageMath of the Expanding Circuit Compiler introduced in the following publication :

> [Random Probing Security: Verification, Composition, Expansion and New Constructions](https://eprint.iacr.org/2020/786)  
> By Sonia Belaïd, Jean-Sébastien Coron, Emmanuel Prouff, Matthieu Rivain and Abdul Rahman Taleb 
> In the proceedings of CRYPTO 2020.

The program is designed to compile n​-share base gadgets G<sub>add</sub>, G<sub>copy</sub>   and G<sub>mult</sub>, into expanded n<sup>k</sup>-share gadgets G<sub>add</sub><sup>(k)</sup>, G<sub>copy</sub><sup>(k)</sup>   and G<sub>mult</sub><sup>(k)</sup>, as described in the paper.

## Content

This repository contains the code of the Expanding Circuit Compiler implemented in SageMath and Python3:

- **compiler.sage:** contains the main program that runs the tool and the main compilation function.
- **{addition, copy, multiplication, variables}_f.py:** contains different functions that are needed for the compilation.
- **verify_compilation.py:** contains the program that verifies the correctness of the resulting compiled gadgets.

## Usage

Using the compiler requires having [SageMath](http://www.sagemath.org/) installed and Python (3 or higher). The main function of the tool is in the file `Compiler.sage`. To get all options, run the following command:

```
sage compiler.sage -h
```

This outputs :

```
usage: compiler.sage.py [-h] [-c_type C_TYPE]
                        Add_gadget Copy_gadget Mult_gadget k

positional arguments:
  Add_gadget      Name of the addition gadget's file to use
  Copy_gadget     Name of the copy gadget's file to use
  Mult_gadget     Name of the multiplication gadget's file to use
  k               Expansion level

optional arguments:
  -h, --help      show this help message and exit
  -c_type C_TYPE  If specified, Gadgets are also saved as C functions, with
                  variables of type C_TYPE

```

The four mandatory parameters are the ones specifying each of the addition, copy and multiplication gadgets sage files, as well as the expansion level k. The resulting  n<sup>k</sup>-share gadgets G<sub>add</sub><sup>(k)</sup>, G<sub>copy</sub><sup>(k)</sup> and G<sub>mult</sub><sup>(k)</sup> are then saved in similar sage files in the same format.

If the parameter `c_type` is specified, then the resulting gadgets are also saved in separate C files, as C functions, using the value of the parameter `c_type` for the inputs, outputs and intermediate variables types.

#### Execution Examples

- The following command outputs G<sub>add</sub><sup>(2)</sup>,  G<sub>copy</sub><sup>(2)</sup> and  G<sub>mult</sub><sup>(2)</sup> in sage circuit files :

  ```
  sage Compiler.sage add.sage copy.sage mult.sage 2
  ```

* The following command outputs   G<sub>add</sub><sup>(3)</sup>,  G<sub>copy</sub><sup>(3)</sup> and  G<sub>mult</sub><sup>(3)</sup> in sage circuit files and also in C files, using C standard integer type:

  ```
  sage Compiler.sage add.sage copy.sage mult.sage 3 -c_type int
  ```


## Input Format

Input gadget files have to be sage files in the following format :

```
#ORDER 1
#SHARES 2
#IN a b
#RANDOMS r0
#OUT d

c0 = a0 * b0	
d0 = c0 + r0

c1 = a1 * b1
c1 = c1 + r0
tmp = a0 * b1
c1 = c1 + tmp
tmp = a1 * b0

d1 = c1 + tmp
```

Above is an example of the ISW​ multiplication gadget with 2 shares. 

* `#ORDER 1`  is the order of the gadget (1-Probing secure)
* `#SHARES 2` is the number of shares used in the gadget
* `#IN a b` are the input variables of the gadget
* `#RANDOMS r0` are all of the random variables used in the gadget
* `#OUT d` is the output variable of the gadget

The next lines are the instructions (or gates) of the gadget. Allowed operations are `+` and `*`. The shares of input/output variables range from 0 to \#shares - 1 . To specify the share for each variable, simply use the variable name suffixed by the share number `(eg. a0, b1, d0, ...)​`. 

__The variable names of the format `r#_` where `#` is a number `(eg. r0_, r15_, ...)`, are reserved formats for the tool processing and should not be used in the gadget description.__



## Output Format (Example)

Consider three 2-share base gadgets G<sub>add</sub>, G<sub>copy</sub> and G<sub>mult</sub>. Let's run the following command:

````
sage Compiler.sage add.sage copy.sage mult.sage 2 -c_type uint8_t
````

Running this command outputs the following on standard output :

```
Started Compilation

Compiling Add...
################################## Starting k = 1 ##################################
################################## Starting k = 2 ##################################

Add gadget CIRCUIT saved in ./output_gadgets/Add_compiled_gadget_k2.sage
Add gadget C function saved in ./output_gadgets/Add_compiled_gadget_k2.c
Add Complexity (Na, Nc, Nm, Nr) = (20, 8, 0, 8)

Compiling Copy...
################################## Starting k = 1 ##################################
################################## Starting k = 2 ##################################

Copy gadget CIRCUIT saved in ./output_gadgets/Copy_compiled_gadget_k2.sage
Copy gadget C function saved in ./output_gadgets/Copy_compiled_gadget_k2.c
Copy Complexity (Na, Nc, Nm, Nr) = (32, 20, 0, 16)

Compiling Mult...
################################## Starting k = 1 ##################################
################################## Starting k = 2 ##################################

Mult gadget CIRCUIT saved in ./output_gadgets/Mult_compiled_gadget_k2.sage
Mult gadget C function saved in ./output_gadgets/Mult_compiled_gadget_k2.c
Mult Complexity (Na, Nc, Nm, Nr) = (52, 44, 16, 20)



Total Compilation time = 0.00804090499878 seconds

Verifying that outputs of compiled gadgets are correct...

Done

```

As you can see, each of the resulting gadgets complexities have been printed :

```
Add Complexity (Na, Nc, Nm, Nr) = (20, 8, 0, 8)
...
Copy Complexity (Na, Nc, Nm, Nr) = (32, 20, 0, 16)
...
Mult Complexity (Na, Nc, Nm, Nr) = (52, 44, 16, 20)
```

In addition, this execution generated six files in the folder `./output_gadgets` : `Add_compiled_gadget_k2.sage, Copy_compiled_gadget_k2.sage, Mult_compiled_gadget_k2.sage, Add_compiled_gadget_k2.c, Copy_compiled_gadget_k2.c, Mult_compiled_gadget_k2.c     `.

If the parameter `-c_type` has not been specified, then only three `.sage` were going to be generated.

In the C files, the functions have the following signatures : 

```
void Add_gadget_function(uint8_t * a, uint8_t * b, uint8_t * c);  //inputs a,b; output c
void Copy_gadget_function(uint8_t * a, uint8_t * d, uint8_t * e); //input a; outputs d,e
void Mult_gadget_function(uint8_t * a, uint8_t * b, uint8_t * c); //inputs a,b; output c
```

The variables are considered to be arrays of `c_type = uint8_t` shares. For operations `+` , `*` and for randoms, these functions use supposedly existing functions : `uint8_t Add(uint8_t a, uint8_t b) ` , `uint8_t Multiply(uint8_t a, uint8_t b)`  and ```uint8_t get_rand()```. The user should define these functions before using the gadgets, to specify what addition and multiplication mean in the considered application, and how to generate randoms. For example for AES application, addition is a simple xor :

```
uint8_t Add(uint8_t a, uint8_t b){ return a^b; }
```

and randoms can be generated as :

```
uint8_t get_rand(){ return rand() ^ 0xff; }
```

The tool finally outputs the total execution time it took to generate the expanded 4-share gadgets G<sub>add</sub><sup>(2)</sup>,  G<sub>copy</sub><sup>(2)</sup> and  G<sub>mult</sub><sup>(2)</sup> :

```
Total Compilation time = 0.00804090499878 seconds
```

And then verifies that the compiled gadgets have correct outputs; mainly it verifies that :

```
![\Large x=\sum_{i=0}^{n^k - 1}c_i = \sum_{i=0}^{n^k - 1}a_i + \sum_{i=0}^{n^k - 1}b_i](https://latex.codecogs.com/svg.latex?x%3D%5Cfrac%7B-b%5Cpm%5Csqrt%7Bb%5E2-4ac%7D%7D%7B2a%7D)
```

* For G<sub>add</sub><sup>(k)</sup> : <img src="https://latex.codecogs.com/svg.latex?\sum_{i=0}^{n^k%20-%201}c_i%20=%20\sum_{i=0}^{n^k%20-%201}a_i%20+%20\sum_{i=0}^{n^k%20-%201}b_i"/>

* For G<sub>copy</sub><sup>(k)</sup> :   <img src="https://latex.codecogs.com/svg.latex?\sum_{i=0}^{n^k%20-%201}d_i%20=%20\sum_{i=0}^{n^k%20-%201}a_i"/>and  <img src="https://latex.codecogs.com/svg.latex?\sum_{i=0}^{n^k%20-%201}e_i%20=%20\sum_{i=0}^{n^k%20-%201}a_i"/>
* For G<sub>mult</sub><sup>(k)</sup> :  <img src="https://latex.codecogs.com/svg.latex?\sum_{i=0}^{n^k%20-%201}c_i%20=%20\sum_{i=0}^{n^k%20-%201}a_i%20*%20\sum_{i=0}^{n^k%20-%201}b_i"/>

where the index $i$ specifies the share index of the variable. If any of the above verifications is incorrect, it probably means that there is an error in one or more of the base gadgets  G<sub>add</sub>, G<sub>copy</sub>  and G<sub>mult</sub>.

In this execution case, the outputs are correct and the tool prints :

```
Verifying that outputs of compiled gadgets are correct...

Done
```

without any error message.

#### Example of output files

For example, this is what the file `Add_compiled_gadget_k2.sage` contains :

```
#ORDER 1
#SHARES 4
#IN a b 
#RANDOMS r0 r2 r7 r6 r3 r5 r4 r1 
#OUT c 

var0 = r0 + r1
var1 = r2 + r1

var2 = r0 + r3
var3 = r2 + r3

var4 = a0 + b0
var5 = var4 + r4

var6 = a1 + b1
var7 = var6 + r4

var8 = var5 + var0
c0 = var8 + r5

var9 = var7 + var1
c1 = var9 + r5

var10 = a2 + b2
var11 = var10 + r6

var12 = a3 + b3
var13 = var12 + r6

var14 = var11 + var2
c2 = var14 + r7

var15 = var13 + var3
c3 = var15 + r7
```

and this is what the file `Add_compiled_gadget_k2.c` contains :

```
void Add_gadget_function(uint8_t * a, uint8_t * b, uint8_t * c){
	uint8_t r0 = get_rand();
	uint8_t r2 = get_rand();
	uint8_t r7 = get_rand();
	uint8_t r6 = get_rand();
	uint8_t r3 = get_rand();
	uint8_t r5 = get_rand();
	uint8_t r4 = get_rand();
	uint8_t r1 = get_rand();

	uint8_t var0 = Add(r0, r1) ;
	uint8_t var1 = Add(r2, r1) ;

	uint8_t var2 = Add(r0, r3) ;
	uint8_t var3 = Add(r2, r3) ;

	uint8_t var4 = Add(a[0], b[0]) ;
	uint8_t var5 = Add(var4, r4) ;

	uint8_t var6 = Add(a[1], b[1]) ;
	uint8_t var7 = Add(var6, r4) ;

	uint8_t var8 = Add(var5, var0) ;
	c[0] = Add(var8, r5) ;

	uint8_t var9 = Add(var7, var1) ;
	c[1] = Add(var9, r5) ;

	uint8_t var10 = Add(a[2], b[2]) ;
	uint8_t var11 = Add(var10, r6) ;

	uint8_t var12 = Add(a[3], b[3]) ;
	uint8_t var13 = Add(var12, r6) ;

	uint8_t var14 = Add(var11, var2) ;
	c[2] = Add(var14, r7) ;

	uint8_t var15 = Add(var13, var3) ;
	c[3] = Add(var15, r7) ;
}
```

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)