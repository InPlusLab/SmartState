# -*- coding: utf-8 -*-
import os
import re
import numpy as np
import pandas as pd
import pandas as pd 
import networkx as nx
def detection(path):

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    os.chdir(path)   #修改当前工作目录

    b=pd.read_table("contract.tac",delimiter='\n',header=None)
    k=0
    b.columns = ["3IR"]
    b['blockname']='0'
    b['leftvariable']='0'
    b['rightvariable']='0'
    b['option']='0'
    b['functionname']='0'
    for i in range(0,len(b)):
        blockindex=b.iloc[i,0].find('block')
        if blockindex>0:
            k=b.iloc[i,0][(blockindex+6):]
            b.iloc[i,1]=k
            #print (b.iloc[i,0][(blockindex+6):])
        b.iloc[i,1]=k
        bsplit=re.split(r'(?:[, : \s ( )])',b.iloc[i,0])
        #print(bsplit)
        if (bsplit.count('=')>0):
            eindex=bsplit.index('=')
            b.iloc[i,4]=bsplit[eindex+1]
            #print (bsplit[eindex])
            for p in range(0,eindex):
                findvar=bsplit[p]
                
                if (findvar.find('v')>-1):
                    b.iloc[i,2]= findvar
            
            for p in range(eindex,len(bsplit)):
                if (bsplit[p].find('v')>-1):
                    b.iloc[i,3]=b.iloc[i,3]+','+ bsplit[p]
        else:
            if(len(bsplit)>7 and b.iloc[i,0].find('succ')<0):
                b.iloc[i,4]=bsplit[6]
                for p in range(0,len(bsplit)):
                    if (bsplit[p].find('v')>-1):
                        b.iloc[i,3]=b.iloc[i,3]+','+ bsplit[p]
        if (bsplit[0]=='function'):
            b.iloc[i,5]=bsplit[1]
        else:
            b.iloc[i,5]=b.iloc[i-1,5]

    #print(b)
    #LFSG

    G=nx.DiGraph()#创建空的简单有向图
    if os.path.getsize('LocalBlockEdge.csv')>0:
        controledge = pd.read_csv("LocalBlockEdge.csv",delimiter='\t',header=None)      #control edge
    else:
        controledge =[]

    #if os.path.getsize('IRFunction_Return.csv')>0:
    #    returnedge=pd.read_csv("IRFunction_Return.csv",delimiter='\t',header=None)      #return edge
    #else:
    #    returnedge=[]

    #if os.path.getsize('IRFunctionCall.csv')>0:
    #    calledge=pd.read_csv("IRFunctionCall.csv",delimiter='\t',header=None)           #call edge
    #else:
    #    calledge=[]

    #print(calledge)

    #if os.path.getsize('PublicFunction.csv')>0:
    #    externedge=pd.read_csv("PublicFunction.csv",delimiter='\t',header=None)    #externedge
    #else:
    #    externedge=[]
        
    #if os.path.getsize('State-dependency-edge.csv')>0:
    #    SDedge=pd.read_csv("State-dependency-edge.csv",delimiter=',',header=None)    #externedge
    #else:
    #    SDedge=[]

    controllength=len(controledge)
    #returnlength=len(returnedge)
    #calllength=len(calledge)
    #externlength=len(externedge)
    #SDlength=len(SDedge)

    for i in range(0,controllength): #1515097                             #add control edge
        G.add_edge(controledge.iloc[i,0],controledge.iloc[i,1])

    #functions=list(nx.weakly_connected_components(G))

    #print('Functions list',functions)

    #for i in range(0,externlength): #1515097                              #add extern edge DOS attack without these edge
    #    G.add_edge("reverting_node",externedge.iloc[i,0])

    #for i in range(0,calllength): #1515097                              #add return edge
    #    for j in range(0,returnlength):
    #       if calledge.iloc[i,1]==returnedge.iloc[j,0]:
    #           G.add_edge(returnedge.iloc[j,1],calledge.iloc[i,0])
            
    #for i in range(0,calllength):                                #add call edge
        #G.add_edge(calledge.iloc[i,0],calledge.iloc[i,1])

    #blcok_list=list(set(b.iloc[:,1].tolist))

    #ROllBACK indicator detection
    block_name=[]
    for i in range(0,len(b)):
        if(b.iloc[i,1] in G.nodes()):
            block_name.append(b.iloc[i,1])
    block_list=list(set(block_name))
    #block_list.remove(0)
    vulblock=[]
    for i in range(0,len(block_list)):
        analysis_block=[]
        #print(block_list[i])  
        prev_block=list(G.predecessors(block_list[i]))
        succ_block=list(G.successors(block_list[i]))
        analysis_block=analysis_block+prev_block+succ_block
        analysis_block.append(block_list[i])
        #print(analysis_block) 
        
        option_list=[]
        for k in range(0,len(analysis_block)):
            for m in range(0,len(b)):
                if(b.iloc[m,1]==analysis_block[k]):
                    option_list.append(b.iloc[m,4])
            

        #print("option_list",option_list)
        count=0
        #print('index',option_list.count('ORIGIN'))
        if(option_list.count('ORIGIN')>0):
            count=count+1
        if(option_list.count('BLOCKHASH')>0):
            count=count+1
        if(option_list.count('EXTCODEHASH')>0):
            count=count+1
        if(option_list.count('TIMESTAMP')>0):
            count=count+1
        if(option_list.count('NUMBER')>0):
            count=count+1
        if(option_list.count('COINBASE')>0):
            count=count+1
        if(option_list.count('DIFFICULTY')>0):
            count=count+1
        if(option_list.count('CHAINID')>0):
            count=count+1
        if(option_list.count('BASEFEE')>0):
            count=count+1
        if(option_list.count('GASLIMIT')>0):
            count=count+1
        if(count>2):
            vulblock.append(block_list[i])
            #print('bug',block_list[i])
    vul_function=[]
    for n in range(0,len(b)):
        for i in range(0,len(vulblock)):
            if(b.iloc[n,1]==vulblock[i]):
                vul_function.append(b.iloc[n,5])
    vul_function=list(set(vul_function))
    print('main detection finish!')
    return vulblock, vul_function
        
       
#python3 main_detection.py