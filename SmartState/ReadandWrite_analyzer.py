# -*- coding: utf-8 -*-
import os
import re
import numpy as np
import pandas as pd
import networkx as nx
import csv

def find_predecessors(G,exist_block):
    prev_block=list(G.predecessors(exist_block))
    return prev_block

def find_successors(G,exist_block):
    succ_block=list(G.successors(exist_block))
    return succ_block

def RAW_analysis(path):
    #path = "/pro/decom/FSE/gigahorse/gigahorse-toolchain/.temp/new/out"                           # 设置路径
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    os.chdir(path)   #修改当前工作目录

    # .temp/0x869eb8a1a479a80f9907673eae8336625dc3e526/out
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

    if os.path.getsize('IRFunction_Return.csv')>0:
        returnedge=pd.read_csv("IRFunction_Return.csv",delimiter='\t',header=None)      #return edge
    else:
        returnedge=[]

    if os.path.getsize('IRFunctionCall.csv')>0:
        calledge=pd.read_csv("IRFunctionCall.csv",delimiter='\t',header=None)           #call edge
    else:
        calledge=[]

    #print(calledge)

    if os.path.getsize('PublicFunction.csv')>0:
        externedge=pd.read_csv("PublicFunction.csv",delimiter='\t',header=None)    #externedge
    else:
        externedge=[]
        
    if os.path.getsize('State-dependency-edge.csv')>0:
        SDedge=pd.read_csv("State-dependency-edge.csv",delimiter=',',header=None)    #externedge
    else:
        SDedge=[]

    controllength=len(controledge)
    returnlength=len(returnedge)
    calllength=len(calledge)
    externlength=len(externedge)
    SDlength=len(SDedge)

    for i in range(0,controllength): #1515097                             #add control edge
        G.add_edge(controledge.iloc[i,0],controledge.iloc[i,1])

    functions=list(nx.weakly_connected_components(G))

    #print('Functions list',functions)

    for i in range(0,externlength): #1515097                              #add extern edge DOS attack without these edge
        G.add_edge("reverting_node",externedge.iloc[i,0])

    for i in range(0,calllength): #1515097                              #add return edge
        for j in range(0,returnlength):
            if calledge.iloc[i,1]==returnedge.iloc[j,0]:
                G.add_edge(returnedge.iloc[j,1],calledge.iloc[i,0])
            
    for i in range(0,calllength):                                #add call edge
        G.add_edge(calledge.iloc[i,0],calledge.iloc[i,1])

    #find revert block
    revert_op=[]
    if (b.iloc[:,4].tolist().count('REVERT')>0):
        option_list= np.array(b.iloc[:,4].tolist())
        revert_op = np.where(option_list=='REVERT')
    #print('revert_op',revert_op)
    revert_block=[]
    if(len(revert_op)>0):
        for i in range(0,len(revert_op[0])):
            revert_block.append(b.iloc[revert_op[0][i],1])   

    #find branch



    storage=[]
    for i in range(0,len(revert_block)):
        exist_block=revert_block[i]
        #print('revert',revert_block[i])
        branch_block=[]
        branch=0
        while(branch<2):
            preblock=find_predecessors(G,exist_block)
            if(len(preblock)<2 and len(preblock)>0):
                sucblock=find_successors(G,preblock[0])
                branch=len(sucblock)
                branch_block.append(exist_block)
                exist_block=preblock[0]
            else:
                branch=3
                #print('sys.error')
        branch_block.append(exist_block)
        #print('exist_block',exist_block,'branch_block',branch_block)
        for k in range(len(branch_block)):
            if(os.path.getsize('State-dependency-edge.csv')>0):
                if (SDedge.iloc[:,1].tolist().count(branch_block[k])>0):
                    r_list= np.array(SDedge.iloc[:,1].tolist())
                    read_re = np.where(r_list==branch_block[k])
                    for n in range(0,len(read_re[0])):
                        #print('storage',SDedge.iloc[read_re[0][n],0])
                        storage.append([SDedge.iloc[read_re[0][n],1],SDedge.iloc[read_re[0][n],0]])
                        #print(SDedge.iloc[read_re[0][n],1])

    
    #storage=list(set(storage))           
    #print('storage',storage)    
    dependency=[]
    for k in range(0,len(storage)):
        r_list = np.array(SDedge.iloc[:,1].tolist())
        write_re = np.where(r_list==storage[k][1])
        for n in range(0,len(write_re[0])):
            storage[k].append(SDedge.iloc[write_re[0][n],0])
            dependency.append([SDedge.iloc[write_re[0][n],0],storage[k][0]])
    #print('storage',storage) 
    #print('dependency',dependency)        
    #find storage Read(sload)

    #find Write block and generate method edge



    with open("RaW-edge.csv",'w',newline='',encoding='UTF-8') as f_c_csv:
        writer = csv.writer(f_c_csv)
        #writer.writerow(['source','target'])
        for m in range(0,len(dependency)):
            
            writer.writerow(dependency[m])
    print("RaW edge finsih！")


    #python3 ReadandWrite_analyzer.py