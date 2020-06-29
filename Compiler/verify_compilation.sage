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

def verify(circuit_file):
    #result output circuit file after modification
    output_pol_ring = open("sage_tmp2_numpy.sage", "w")
    output_pol_ring.write('P.<')
    
    f1 = open(circuit_file)
    lines = f1.readlines()
    f1.close()
    
    Mut = False
    for l in lines:
        if("*" in l):
            Mut = True
            break
    
    #Copying first 5 files for ORDER, SHARES, IN, RANDOMS, OUT in the specified order
    nb_shares = int(lines[1].split()[1])
        
    inputs = lines[2].split()[1:]
    nb_shares = int(lines[1].split()[1])
    outputs = lines[4].split()[1:]
    
    #Writing Sage_tmp2 File for polynomial Ring
    varss = lines[2].split()[1:]
    for v in varss:
        for i in range(nb_shares):
            output_pol_ring.write(v+str(i)+",")
    
    #RANDOMS with _
    args = lines[3].split()
    tmp = 0
    for r in args[1:-1]:
        output_pol_ring.write(r+",")
    
    ri = args[-1]
    output_pol_ring.write(ri)
    output_pol_ring.write('>=BooleanPolynomialRing()')
    output_pol_ring.close()
    
    load("sage_tmp2_numpy.sage")
    load(circuit_file)
    
    exp = [eval("0") for e in outputs]
    
    for i in range(len(outputs)):
        out = outputs[i]
        for l in lines:
            args = l.split()
            if(len(args) <= 1):
                continue
                
            if(args[0][0] == out):
                exp[i] = exp[i]+eval(" ".join(args[2:]))

    #print("Evaluations : ")
    #for i in range(len(outputs)):
    #    print(outputs[i]+" = " + str(exp[i]) + "\n")

    exp_res = [eval("0") for e in outputs]
    exp_cop = copy.deepcopy(exp)
    #print("Verifications : ")
    if(Mut):
        inp1 = inputs[0]
        inp2 = inputs[1]
        
        for i1 in range(nb_shares):
            for i2 in range(nb_shares):
                exp[0] += eval(inp1+str(i1) + " * " + inp2+str(i2))
                exp_res[0] += eval(inp1+str(i1) + " * " + inp2+str(i2))
                
    #    print(outputs[0]+ " = " + str(exp[0]) + "\n")
        
    else:
        for o in range(len(outputs)):
            for a in inputs:
                for i in range(nb_shares):
                    exp[o] = exp[o]+eval(a+str(i))
                    exp_res[o] += eval(a+str(i))
                    #print(str(eval(a+str(i))))
                    
    #        print(outputs[o]+" = " + str(exp[o]) + "\n")
    
    os.remove("sage_tmp2_numpy.sage")
    #print(str(exp_res == exp_cop))
    return (exp_res == exp_cop) and (exp == [0 for e in outputs])