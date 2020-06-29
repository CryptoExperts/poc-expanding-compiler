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

import copy

from addition import *
from variables import *

def update_copy_dict(info_dict):
    
    copy_d = dict()

    for line in info_dict["instructions"]:
        if(line == "\n"):
            continue
        
        args = line.split()
        if(len(args) == 0):
            continue
        
        token_index = 1
        while(token_index < len(args)):
            token_index += 1
            
            if(args[token_index] in copy_d):
                copy_d[args[token_index]] += 1
            else:
                copy_d[args[token_index]] = 1
                
            token_index += 1
            
        if(args[0] in copy_d):
            copy_d[args[0]] = 0
            
    info_dict["copies"] = copy_d

def copy_var(inp, out1, out2, copy_gadget, random_suffix, nb_shares):    
    gad_inp = copy_gadget["inputs"][0]
    gad_out1 = copy_gadget["outputs"][0]
    gad_out2 = copy_gadget["outputs"][1]
    
    replacement = copy.deepcopy(copy_gadget["instructions"])
    for i in range(len(replacement)):
        
        if(replacement[i] == '\n'):
            continue
        line = replacement[i].split()
        if(len(line) == 0):
            continue
        
        if(line[0][0] == gad_out1):
            line[0] = out1+"_"+line[0][1:]+"_"
        elif(line[0][0] == gad_out2):
            line[0] = out2+"_"+line[0][1:]+"_"
            
        token_index = 1
        while(token_index < len(line)):
            token_index += 1
            
            if(line[token_index][0] == gad_out1):
                line[token_index] = out1+"_"+line[token_index][1:]+"_"
                
            elif(line[token_index][0] == gad_out2):
                line[token_index] = out2+"_"+line[token_index][1:]+"_"
                
            elif(line[token_index][0] == gad_inp):
                line[token_index] = inp+"_"+line[token_index][1:]+"_"
                
            elif(line[token_index][0] == "_"):
                line[token_index] += "__"+random_suffix+"__"
                
            token_index += 1
            
        replacement[i] = " ".join(line)+"\n"
    
    randoms = [r+"__"+random_suffix for r in copy_gadget["randoms"]]
    
    return replacement, randoms



def copy_var_n_times(v, copy_gadget, random_suffix, nb_shares, n, indice):
    instructions = []
    randoms_to_add = []
    
    if(n == 2):
        suff = random_suffix + str(indice)
        indice += 1
        out = copy_var(v, v+"_copy0", v+"_copy1", copy_gadget, suff, nb_shares)
        instructions += out[0]
        randoms_to_add += out[1]

    else:
        #First Copy
        suff = random_suffix +str(indice)
        indice += 1
        out = copy_var(v, v+"_copy0", v+"_tmp0", copy_gadget, suff, nb_shares)
        instructions += out[0]
        randoms_to_add += out[1]
        
        for i in range(1, n-2):
            suff = random_suffix + str(indice)
            indice += 1
            out = copy_var(v+"_tmp"+str(i-1), v+"_copy"+str(i), v+"_tmp"+str(i), copy_gadget, suff, nb_shares)
            instructions += out[0]
            randoms_to_add += out[1]
            
        i = n-2
        #last copy
        suff = random_suffix + str(indice)
        indice += 1
        out = copy_var(v+"_tmp"+str(i-1), v+"_copy"+str(i), v+"_copy"+str(i+1), copy_gadget, suff, nb_shares)
        instructions += out[0]
        randoms_to_add += out[1]
     
    instructions.append("\n")
    
    return instructions, randoms_to_add, indice