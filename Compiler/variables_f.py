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


##############################################################################
#
# replace_variables
#
# 	INPUTS:
#		- gadget: gadget circuit that is being compiled
#        - nb_inputs, nb_outputs: number of inputs/outputs of the gadget
#
#	OUTPUT:
#		- rewrites the gadget instructions by replacing all intermediate 
#          variables names by "var#" where # is an incremented index, and 
#          every "var#" is unique
#
##############################################################################
def replace_variables(gadget, nb_inputs, nb_outputs):
    random_counter = 0
    inp1_counter = 0
    inp1_dict = dict()
    if(nb_inputs == 2):
        inp2_counter = 0
        inp2_dict = dict()
    out1_counter = 0
    out1_dict = dict()
    if(nb_outputs == 2):
        out2_counter = 0
        out2_dict = dict()
    random_dict = dict()
    
    new_lines = []
    lines = gadget["instructions"]
    used_out_var = dict()
    var_counter = 0
    for line in lines:
        
        args = line.split()
        if(len(args) == 0):
            new_lines.append("\n")
            continue
        new_line = []
        token_index = 1
        while(token_index < len(args)):
            new_line.append(args[token_index])
            token_index += 1
            
            v = args[token_index]
            if(v in used_out_var):
                new_line.append(used_out_var[v])
                
            elif("copy" in v):
                used_out_var[v] = "var"+str(var_counter)
                var_counter += 1
                new_line.append(used_out_var[v])
            #It's a random variable
            elif(v[0] == "_"):
                if(v not in random_dict):
                    random_dict[v] = "_" + "r" + str(random_counter)
                    random_counter += 1
                new_line.append(random_dict[v])
                
            elif(v[0] in gadget["inputs"]):
                
                if(v[0] == gadget["inputs"][0]):
                    if(v not in inp1_dict):
                        inp1_dict[v] = v[0] + str(inp1_counter)
                        inp1_counter += 1
                    new_line.append(inp1_dict[v])
                else:
                    if(v not in inp2_dict):
                        inp2_dict[v] = v[0] + str(inp2_counter)
                        inp2_counter += 1
                    new_line.append(inp2_dict[v])
                    
            elif(v[0] in gadget["outputs"]):
                
                if(v[0] == gadget["outputs"][0]):
                    if(v not in out1_dict):
                        out1_dict[v] = v[0] + str(out1_counter)
                        out1_counter += 1
                    new_line.append(out1_dict[v])
                else:
                    if(v not in out2_dict):
                        out2_dict[v] = v[0] + str(out2_counter)
                        out2_counter += 1
                    new_line.append(out2_dict[v])
            else:
                used_out_var[v] = "var"+str(var_counter)
                var_counter += 1
                new_line.append(used_out_var[v])
                
            token_index += 1
        
        v = args[0]
        if(v in used_out_var):
            used_out_var[v] = "var"+str(var_counter)
            var_counter += 1
            new_line.insert(0, used_out_var[v])
        elif("copy" in v):
            used_out_var[v] = "var"+str(var_counter)
            var_counter += 1
            new_line.insert(0, used_out_var[v])
        elif(v[0] in gadget["outputs"]):
            if(v[0] == gadget["outputs"][0]):
                if(v not in out1_dict):
                    out1_dict[v] = v[0] + str(out1_counter)
                    out1_counter += 1
                new_line.insert(0, out1_dict[v])
            else:
                if(v not in out2_dict):
                    out2_dict[v] = v[0] + str(out2_counter)
                    out2_counter += 1
                new_line.insert(0, out2_dict[v])
        else:
            used_out_var[v] = "var"+str(var_counter)
            var_counter += 1
            new_line.insert(0, used_out_var[v])
            
        new_lines.append(" ".join(new_line))
                    
    gadget["instructions"] = new_lines
    gadget["randoms"] = random_dict.values()