# -*- coding: utf-8 -*-
import os
import re
import numpy as np
import pandas as pd
import networkx as nx

def block_propagate(exist_block,taint_val,b,taint_block,taint_op_list):
    for d in range(0,len(b)):
        
        if (b.iloc[d,1]==exist_block[0] and (b.iloc[d,4] in taint_op_list)):
            #print(b.iloc[d,0])
            lefttaint=0
            right=list(set(re.split(r'(?:[,])',b.iloc[d,3])))
            #print('right',right)
            for y in range(0,len(right)):
                if (right[y] in taint_val):
                    lefttaint=lefttaint + 1
            if (lefttaint>0 and b.iloc[d,2]!='0'):
                taint_val=taint_val+[b.iloc[d,2]]
                #print('taint_val',taint_val)
    taint_block=taint_block+exist_block
    return list(set(taint_val)), list(set(taint_block))

def edge_propagate(G,exist_block):
    next_block=list(G.successors(exist_block[0]))
    return next_block

def taint_analysis(path,vul_indicator):

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
        
    if os.path.getsize('RaW-edge.csv')>0:
        RAWedge=pd.read_csv("RaW-edge.csv",delimiter=',',header=None)    #externedge
    else:
        RAWedge=[]

    controllength=len(controledge)
    returnlength=len(returnedge)
    calllength=len(calledge)
    externlength=len(externedge)
    SDlength=len(SDedge)
    RAWlength=len(RAWedge)

    for i in range(0,controllength): #1515097                             #add control edge
        G.add_edge(controledge.iloc[i,0],controledge.iloc[i,1])

    #functions=list(nx.weakly_connected_components(G))

    #print('Functions list',functions)

    for i in range(0,externlength): #1515097                              #add extern edge DOS attack without these edge
        G.add_edge("reverting_node",externedge.iloc[i,0])

    for i in range(0,calllength): #1515097                              #add return edge
        for j in range(0,returnlength):
            if calledge.iloc[i,1]==returnedge.iloc[j,0]:
                G.add_edge(returnedge.iloc[j,1],calledge.iloc[i,0])
            
    for i in range(0,calllength):                                #add call edge
        G.add_edge(calledge.iloc[i,0],calledge.iloc[i,1])


    #print('controledge',controledge,'SDedge',SDedge)           

    #mload and mstore analysis
    for z in range(0,len(b)):
        if (b.iloc[z,4]=='MSTORE'):
            Msplit=re.split(r'(?:[, : \s])',b.iloc[z,0])
            #print(Msplit)
            if (Msplit[7].find('(')>-1):
                SHAaddress1=Msplit[7][Msplit[7].index('(')+1:Msplit[7].index(')')]
                memory='v_'+b.iloc[z,5]+'_'+SHAaddress1
                b.iloc[z,2]=memory 
            else:
                leftfind=[z]
            
                uloop=1
                findSHA3=0
                while(findSHA3<1 and uloop<10):
                    findSHA3=0
                    SHAsplit=[]
                    for m in range(0,len(leftfind)):
                        SHAsplit=list(set(SHAsplit+re.split(r'(?:[,])',b.iloc[leftfind[m],3])))
                    #print('SHAsplit',SHAsplit)
                    leftfind=[]
                    for n in range(0,len(SHAsplit)):
                        if (SHAsplit[n]!='0' and b.iloc[:,2].tolist().count(SHAsplit[n])>0):
                            leftfind.append(b.iloc[:,2].tolist().index(SHAsplit[n]))
                    #print('leftfind',leftfind)         
                    for m in range(0,len(leftfind)):
                        if (leftfind[m]!=z):
                            if (b.iloc[leftfind[m],0].find('(')<0):
                                findSHA3=findSHA3 or 0
                            if (b.iloc[leftfind[m],0].find('(')>-1):
                                findSHA3=findSHA3 or 1
                            
                                SHAaddress1=b.iloc[leftfind[m],0][b.iloc[leftfind[m],0].index('(')+1:b.iloc[leftfind[m],0].index(')')]
                            
                                memory='v_'+b.iloc[leftfind[m],5]+'_'+SHAaddress1
                                b.iloc[z,2]=memory
                            
                    uloop=uloop+1
            #print('check2',b.iloc[z,2]) ##modify here
            
    for z in range(0,len(b)):
        if (b.iloc[z,4]=='MLOAD'):
            if (b.iloc[z,0].find('(')>-1):
                SHAaddress1=b.iloc[z,0][b.iloc[z,0].index('(')+1:b.iloc[z,0].index(')')]
                memory='v_'+b.iloc[z,5]+'_'+SHAaddress1
                b.iloc[z,3]=memory
                
                
            else:
                leftfind=[z]
            
                uloop=1
                findSHA3=0
                while(findSHA3<1 and uloop<10):
                    findSHA3=0
                    SHAsplit=[]
                    for m in range(0,len(leftfind)):
                        SHAsplit=list(set(SHAsplit+re.split(r'(?:[,])',b.iloc[leftfind[m],3])))
                    #print('SHAsplit',SHAsplit)
                    leftfind=[]
                    for n in range(0,len(SHAsplit)):
                        if (SHAsplit[n]!='0'and b.iloc[:,2].tolist().count(SHAsplit[n])>0):
                            leftfind.append(b.iloc[:,2].tolist().index(SHAsplit[n]))
                            
                    for m in range(0,len(leftfind)):
                        if (b.iloc[leftfind[m],0].find('(')<0):
                            findSHA3=findSHA3 or 0
                        if (b.iloc[leftfind[m],0].find('(')>-1):
                            findSHA3=findSHA3 or 1
                            
                            SHAaddress1=b.iloc[leftfind[m],0][b.iloc[leftfind[m],0].index('(')+1:b.iloc[leftfind[m],0].index(')')]
                            
                            memory='v_'+b.iloc[leftfind[m],5]+'_'+SHAaddress1
                            b.iloc[z,3]=memory
                            
                    uloop=uloop+1
            #print('check3',b.iloc[z,3]) ##modify here  
        


    #define source,sink
    source=['revertingnode']
    sink=[]

    #whether vulnerability indicator is reachable by the taint
    taint_val=[]
    #vul_indicator=['0x66fB0x117'] #modify here
    for v in range(0,len(vul_indicator)):
        for i in range(0,len(b)):
            if(b.iloc[i,1]==vul_indicator[v]):
                if(b.iloc[i,2]!='0'):
                    taint_val.append(b.iloc[i,2])
    
    #taint_val=['v672V117','v675V117','v677V117','v678V117'] #modify here
    taint_block=[]
    trace_call=[]
    for n in range(0,len(vul_indicator)):
        trace_call=trace_call+list(nx.all_simple_paths(G,'reverting_node',vul_indicator[n]))
    #print(trace_call)

    for i in range(0,len(SDedge)): #1515097                             #add state dependency edge
        G.add_edge(SDedge.iloc[i,0],SDedge.iloc[i,1])
        
    for i in range(0,len(RAWedge)): #1515097                             #add state dependency edge
        G.add_edge(RAWedge.iloc[i,0],RAWedge.iloc[i,1])

    #node propagation
    exist_block=vul_indicator
    taint_op_list=['ADD','MUL','SUB','DIV','SDIV','MOD','SMOD','EXP','NOT','LT','GT','SLT','SGT','EQ','ISZERO','SIGNEXTEND','AND','OR','XOR','BYTE','SHL','SHR','SAR','ADDMOD','MULMOD','ADDRESS','BALANCE','CALLER','CALLVALUE','CALLDATALOAD','CALLDATACOPY','RETURNDATACOPY','POP','MLOAD','MSTORE','MSTORE8','SLOAD','SSTORE']
    #print(exist_block in taint_block)





    next_block=[]           


    k=0           

    while(len(exist_block)>0 and k<100):
        next_block=[]  
        for i in range(0,len(exist_block)):
            if (exist_block[i]!='0'):
                (taint_val,taint_block)= block_propagate([exist_block[i]],taint_val,b,taint_block,taint_op_list)
                
                next_block=next_block+edge_propagate(G,[exist_block[i]])
        exist_block=[]
        #print('nextblock',next_block)
        for r in range(0,len(next_block)):
            if (next_block[r] not in taint_block):
                exist_block=exist_block+[next_block[r]]
        k=k+1
            
    #print('taint_val',taint_val,'taint_block',taint_block,'next_block',next_block) 
    taint_stor=[]
    for k in range(0,len(taint_block)):
        if(taint_block[k].find('stor')>-1):
            taint_stor.append(taint_block[k])           
    print("Taint analysis finish!")
    return list(set(taint_stor)) 

# python3 taintanalysis.py