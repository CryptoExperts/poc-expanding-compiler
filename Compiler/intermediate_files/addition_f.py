# coding=utf-8
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
import math

from copy_f import *
from variables_f import *


##############################################################################
#
# replace_add_instruction
#
# 	INPUTS:
#		- add_instruction: string in the format "out = inp1 + inp2"
#        - add_gadget_dict: add gadget's python dict created 
#                           using the function read_gadget
#        - random_suffix: string to suffix random variables names with
#
#	OUTPUT:
#		- replacement: instructions from add_gadget_dict to replace
#                       add_instruction with during the compilation
#
##############################################################################
def replace_add_instruction(add_instruction, add_gadget_dict, nb_shares, random_suffix):
    
    args = add_instruction.split()
    
    input1 = args[2]
    input2 = args[4]
    output = args[0]
    
    gad_inp1 = add_gadget_dict["inputs"][0]
    gad_inp2 = add_gadget_dict["inputs"][1]
    gad_out = add_gadget_dict["outputs"][0]
    
    replacement = copy.deepcopy(add_gadget_dict["instructions"])
    for i in range(len(replacement)):
        
        if(replacement[i] == '\n'):
            continue
        line = replacement[i].split()
        if(len(line) == 0):
            continue
        
        if(line[0][0] == gad_out):
            line[0] = output+"_"+line[0][1:]+"_"
            
        token_index = 1
        
        while(token_index < len(line)):
            token_index += 1
            
            if(line[token_index][0] == gad_out):
                line[token_index] = output+"_"+line[token_index][1:]+"_"
                
            elif(line[token_index][0] == gad_inp1):
                line[token_index] = input1+"_"+line[token_index][1:]+"_"
                
            elif(line[token_index][0] == gad_inp2):
                line[token_index] = input2+"_"+line[token_index][1:]+"_"
                
            elif(line[token_index][0] == "_"):
                line[token_index] += "__"+random_suffix+"__"
                
            token_index += 1
            
        replacement[i] = " ".join(line)+"\n"
        
    return replacement