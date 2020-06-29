###############################################################################
#
# Implementation of Expanding Circuit Compiler in SageMath
#
# This program compiles circuits and expands them k times with respect to
# random probing security and random probing expandability property (RPE) 
# that were introduced in the following publication:
# 
#    "Random Probing Security: Verification, Composition, Expansion and New 
#    Constructions"
#    By Sonia Belaïd, Jean-Sébastien Coron, Emmanuel Prouff, Matthieu Rivain, 
#    and Abdul Rahman Taleb
#    In the proceedings of CRYPTO 2020.
#
# Copyright (C) 2020 CryptoExperts
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
###############################################################################

import sys
import copy
import bisect
import time
import re
import numpy as np
import itertools
import math
import argparse
import os

from addition import *
from copy import *
from multiplication import *
from variables import *


##############################################################################
#
# read_gadget
#
# 	INPUTS:
#		- gadget_filename: gadget's pseudo-code sage file
#
#	OUTPUT:
#		- info_dict: a python dict containing all the information
#          about the gadget (inputs, randoms, outputs, nb. of shares, gates)
#
##############################################################################
def read_gadget(gadget_filename):
    
    gadget = open(gadget_filename)
    lines = gadget.readlines()
    gadget.close()
    
    info_dict = dict()
    info_dict["inputs"] = lines[2].split()[1:]             
    info_dict["nb_shares"] = int(lines[1].split()[1])    
    info_dict["outputs"] = lines[4].split()[1:]             
    info_dict["randoms"] = lines[3].split()[1:]             
    
    used_out_var = dict()
    var_counter = 0
    lines = lines[5:]
    
    ################ Loop to read all the instructions in the gadget file ################
    for i in range(len(lines)):
        line = lines[i]
        args = line.split()
        if((line == '\n') or (len(args) ==0)):
            continue
        
        token_index = 1
        while(token_index < len(args)):
            token_index += 1
            
            if(args[token_index] in info_dict["randoms"]):
                args[token_index] = "_"+args[token_index]
            elif(args[token_index] in used_out_var):
                args[token_index] = used_out_var[args[token_index]]
                
            token_index += 1
                
        if(args[0][0] not in info_dict["outputs"]):
            used_out_var[args[0]] = "var"+str(var_counter)
            args[0] = "var"+str(var_counter)
            var_counter += 1
            
        lines[i] = " ".join(args)+"\n"
    
    info_dict["instructions"] = lines
    info_dict["copies"] = dict()                       
    info_dict["randoms"] = ["_"+r for r in info_dict["randoms"]]
    
    return info_dict



##############################################################################
#
# compile_gadget
#
# 	INPUTS:
#		- k: Expansion level
#        - add_gadget, copy_gadget, mult_gadget: the three gadgets' python
#                           dicts created using the function read_gadget
#        - gadget_type: the gadget to be compiled (add, copy or mult)
#
#	OUTPUT:
#		- gadget: compiles the gadget of "gadget_type" into
#                  a k-expanded gadget and returns the corresp. python dict 
#
##############################################################################
def compile_gadget(k, add_gadget, copy_gadget, mult_gadget, nb_shares, gadget_type):
    if(gadget_type == "copy"):
        gadget = copy.deepcopy(copy_gadget)
        nb_inputs = 1
        nb_outputs = 2
    else:
        gadget = dict()
        gadget["copies"] = dict()
        gadget["randoms"] = []
        gadget["nb_shares"] = nb_shares
        gadget["inputs"] = ["a", "b"]
        gadget["outputs"] = ["c"]
        if(gadget_type == "Add"):
            ####### Base gadget is a simple add instruction #######
            gadget["instructions"] = ["c = a + b"]
        else:
            ####### Base gadget is a simple mult instruction #######
            gadget["instructions"] = ["c = a * b"]
        nb_inputs = 2
        nb_outputs = 1
            
    # the first iteration only consists in copying the gadget
    print("################################## Starting k = 1 ##################################")
    if(gadget_type == "add"):
        instructions = replace_add_instruction(gadget["instructions"][0], add_gadget, nb_shares, "a00")
        gadget["instructions"] = instructions
    elif(gadget_type == "mult"):
        instructions = replace_mult_instruction(gadget["instructions"][0], mult_gadget, nb_shares, "m00")
        gadget["instructions"] = instructions
    replace_variables(gadget, nb_inputs, nb_outputs)
    update_copy_dict(gadget)
    
    for itera in range(1,k+1):
        
        print("################################## Starting k = "+str(itera+1)+" ##################################")
        instructions = []   #List of instructions lists
        randoms_to_add = []
        
        ######### COPY of inputs and randoms
        copies = gadget["copies"]
        indice = 0
        for v in copies:
            if(("var" in v) or (copies[v] <= 1)):
                continue
            out = copy_var_n_times(v, copy_gadget, "c"+str(itera), nb_shares, copies[v], indice)
            instructions += out[0]
            randoms_to_add += out[1]
            indice = out[2]
                
            co = 0
            for i in range(len(gadget["instructions"])):
                line = gadget["instructions"][i].split()
                while(v in line):
                    line[line.index(v)] = v+"_copy"+str(co)
                    co += 1
                gadget["instructions"][i] = " ".join(line)   
            
        ######### ITERATING through instructions plus copying remaining vars if necessary
        ind = 0
        for i in range(len(gadget["instructions"])):
            
            ins = gadget["instructions"][i]
            if("+" in ins):
                instructions += replace_add_instruction(ins, add_gadget, nb_shares, "a"+str(itera)+str(ind))
                ind += 1
            elif("*" in ins):
                instructions += replace_mult_instruction(ins, mult_gadget, nb_shares, "m"+str(itera)+str(ind))
                ind += 1
            else:
                instructions.append(ins)

            line = ins.split()
            if(len(line) == 0):
                continue
            v = line[0]
            if((v in copies) and (copies[v] >= 2)):
                out = copy_var_n_times(v, copy_gadget, "c"+str(itera), nb_shares, copies[v], indice)
                instructions += out[0]
                randoms_to_add += out[1]
                indice = out[2]
                
                co = 0
                for j in range(i+1, len(gadget["instructions"])):
                    line = gadget["instructions"][j].split()
                    while(v in line):
                        line[line.index(v)] = v+"_copy"+str(co)
                        co += 1
                    gadget["instructions"][j] = " ".join(line)   
        
        gadget["instructions"] = instructions
        gadget["randoms"] += randoms_to_add
        replace_variables(gadget, nb_inputs, nb_outputs)
        update_copy_dict(gadget)
    
    gadget["nb_shares"] = nb_shares**(k+1)
    return gadget

    

##############################################################################
#
# write_gadget
#
# 	INPUTS:
#		- gadget: the gadget's python dict to be written in a file
#        - filename: the name of the file to store the gadget in
#                       (should end with .sage or .c)
#        - c_variable_type: specifies the variables type if the gadget
#                       is to be stored in a C file as C function
#        - gadget_type: add, copy or mult
#        - write_xor: specifies if the addition instructions should be written
#                   as xor (^) or simple additions (+) in the file
#
#	OUTPUT:
#		- write the gadget in the file "filename" (sage or C)
#
##############################################################################
def write_gadget(gadget, filename, c_variable_type = None, gadget_type = None, write_xor = False):
    #If the gadget is to be stored in a C file format
    if(filename[-2:] == ".c"):
        f = open(filename, "w")
        f.write("void "+ gadget_type + "_gadget_function(")
        for a in gadget["inputs"]:
            f.write(c_variable_type +" * "+ a +", ")
        for o in gadget["outputs"][:-1]:
            f.write(c_variable_type +" * "+ o +", ")
        
        f.write(c_variable_type + " * " + gadget["outputs"][-1] + "){\n")
            
        for r in gadget["randoms"]:
            f.write("\t" + c_variable_type + " " + r[1:] + " = get_rand();\n")
            
        f.write("\n")
        for ins in gadget["instructions"]:
            
            args = ins.split()
            new_line = []
            if(len(args) <= 1):
                f.write(ins+"\n")
                continue
            
            for a in args:
                if(a[0] == "_"):
                    new_line.append(a[1:])
                elif((a[0] in gadget["inputs"]) or (a[0] in gadget["outputs"])):
                    new_line.append(a[0]+"["+a[1:]+"]")
                else:
                    new_line.append(a)
            
            if(args[0][0] in gadget["outputs"]):
                if("+" in new_line):
                    if(write_xor):
                        f.write("\t" + new_line[0] + " = " + new_line[2] + " ^ " + new_line[4] +" ;\n")
                    else:
                        f.write("\t" + new_line[0] + " = Add(" + new_line[2] + ", " + new_line[4] +") ;\n")
                        
                elif("*" in new_line):
                    f.write("\t" + new_line[0] + " = Multiply(" + new_line[2] + ", " + new_line[4] +") ;\n")
                else:
                    f.write("\t" + " ".join(new_line)+" ;\n")
            else:
                if("+" in new_line):
                    if(write_xor):
                        f.write("\t" + c_variable_type + " "+ new_line[0] + " = " + new_line[2] + " ^ " + new_line[4] +" ;\n")
                    else:
                        f.write("\t" + c_variable_type + " "+ new_line[0] + " = Add(" + new_line[2] + ", " + new_line[4] +") ;\n")
                
                elif("*" in new_line):
                    f.write("\t" + c_variable_type + " "+ new_line[0] + " = Multiply(" + new_line[2] + ", " + new_line[4] +") ;\n")
                else:
                    f.write("\t" + c_variable_type + " "+ " ".join(new_line)+" ;\n")
            
        f.write("}\n")
        f.close()
        
    #Else the gadget will be stored in a standard sage circuit file format
    else:
        complexity = [0, 0, 0, 0]
        varsi = dict()
        f = open(filename, "w")
        f.write("#ORDER 1\n")
        f.write("#SHARES "+str(gadget["nb_shares"])+"\n")
        f.write("#IN ")
        for i in gadget["inputs"]:
            f.write(i+" ")
        f.write("\n")
        
        f.write("#RANDOMS ")
        for r in gadget["randoms"]:
            f.write(r[1:]+" ")
            complexity[3] += 1
        f.write("\n")
        
        f.write("#OUT ")
        for o in gadget["outputs"]:
            f.write(o+" ")
        f.write("\n")
                
        for i in gadget["instructions"]:
            args = i.split()
            new_line = []
            if(len(args) <= 1):
                f.write(i+"\n")
                continue
            
            if("*" in i):
                complexity[2] += 1
            elif("+" in i):
                complexity[0] += 1
                
            if(args[2] not in varsi):
                varsi[args[2]] = 0
            if(args[4] not in varsi):
                varsi[args[4]] = 0
            varsi[args[2]] += 1
            varsi[args[4]] += 1
                    
            for a in args:
                if(a[0] == "_"):
                    new_line.append(a[1:])
                else:
                    new_line.append(a)
            f.write(" ".join(new_line)+"\n")
        f.close()
        
        for k in varsi:
            complexity[1] += (varsi[k]-1)
        return complexity 
        
def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("Add_gadget", help="Name of the addition gadget's file to use")
    parser.add_argument("Copy_gadget", help="Name of the copy gadget's file to use")
    parser.add_argument("Mult_gadget", help="Name of the multiplication gadget's file to use")
    parser.add_argument("k", help="Expansion level", type = int, default=1)
    
    parser.add_argument("-c_type", help="If specified, Gadgets are also saved as C functions, with variables of type C_TYPE", type=str, default=None)
    
    
    args = parser.parse_args()

    if(args.k < 1):
        parser.error("Value of k should be strictly greater than 0")
    
    add_dict = read_gadget(args.Add_gadget)
    copy_dict = read_gadget(args.Copy_gadget)
    mult_dict = read_gadget(args.Mult_gadget)
    
    directory = "./output_gadgets/"
    if not os.path.exists(directory):
        os.makedirs(directory)
   
    print("Started Compilation\n")
    
    
    gadget_types = ["add", "copy", "mult"]
    
    start = time.time()
    
    for gadget_type in gadget_types:
        print("Compiling "+ gadget_type + "...")
        gadget = compile_gadget(args.k-1, add_dict, copy_dict, mult_dict, add_dict["nb_shares"], gadget_type)
        
        filename = directory+gadget_type+"_compiled_gadget_k"+str(args.k)+".sage"
        complexity = write_gadget(gadget, filename, args.c_type, gadget_type)    
        
        print("\n" + gadget_type + " gadget CIRCUIT saved in " + filename)
        if(args.c_type):
            filename = directory+gadget_type+"_compiled_gadget_k"+str(args.k)+".c"
            write_gadget(gadget, filename, args.c_type, gadget_type)  
            print(gadget_type + " gadget C function saved in " + filename)
            
        print(gadget_type + " complexity (Na, Nc, Nm, Nr) = (" + str(complexity)[1:-1] + ")\n")
        
        
    end = time.time()
    print("\n\nTotal Compilation time = " + str(end - start) + " seconds")
    
    
    #################################### Verifying that outputs of compiled gadgets are correct #################################### 
    #################################### For Addition Gadgets, Verify that on inputs a, b and output c,     sum(c_i) = sum(a_i) + sum(b_i)
    #################################### For Copy Gadgets, Verify that on input a and outputs d and e,      sum(d_i) = sum(a_i) and sum(e_i) = sum(a_i)
    #################################### For Mult Gadgets, Verify that on inputs a, b and output c,         sum(c_i) = sum(a_i) * sum(b_i)
    
    print("\nVerifying that outputs of compiled gadgets are correct...\n")
    load("verify_compilation.sage")
    a = verify(directory+"add_compiled_gadget_k"+str(args.k)+".sage")
    b = verify(directory+"copy_compiled_gadget_k"+str(args.k)+".sage")
    c = verify(directory+"mult_compiled_gadget_k"+str(args.k)+".sage")
    
    #################################### Errors should not occur unless the gadget is incorrect or there is a certain bug in the program
    if(not(a)):
        print("Error! Compiled Add Gadget does not hold correct output! This should not occur!")
        print("Either base gadgets are incorrect, or there is a bug in the compiler.")
        exit()
        
    if(not(b)):
        print("Error! Compiled Copy Gadget does not hold correct output! This should not occur!")
        print("Either base gadgets are incorrect, or there is a bug in the compiler.")
        exit()
        
    if(not(c)):
        print("Error! Compiled Mult Gadget does not hold correct output! This should not occur!")
        print("Either base gadgets are incorrect, or there is a bug in the compiler.")
        exit()
        
        
    print("Done")
    
if __name__ == "__main__":
    main()
    
