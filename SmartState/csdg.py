# -*- coding: utf-8 -*-
import os
import re
import numpy as np

path = "./gigahorse/gigahorse-toolchain/.temp/new/out"                           # 设置路径
os.chdir(path)   #修改当前工作目录

import pandas as pd
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

print(b)
#LFSG
import pandas as pd 
import networkx as nx
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

#print('controledge',controledge,'SDedge',SDedge)           
for i in range(0,len(SDedge)): #1515097                             #add control edge
    G.add_edge(SDedge.iloc[i,0],SDedge.iloc[i,1])

#print(list(nx.all_neighbors(G, '0x30a')))
# python3 csdg.py
#nx.draw_networkx(G)


def functioninquiry (block):
    inquirefunction=[]
    nameorder=[]
    for element in block:
        for i in range(0,len(functions)):
            if list(functions[i]).count(element)>0:
                inquirefunction.append(list(functions[i]))
                nameorder.append(i)
    return inquirefunction, nameorder

(functionselector,selectorname)=functioninquiry(['0x0'])
functionselector=functionselector[0]
G.remove_nodes_from(functionselector)


#call_graph construction

functioncall=[]

for i in range(0,calllength):                                #add call edge
    G.add_edge(calledge.iloc[i,0],calledge.iloc[i,1])
    functioncall.append(calledge.iloc[i,0])

#print('functioncall:',functioncall)


calledgelist=[]
calledgeelement=[]
callgraph=[]
for i in range(0,calllength):                                  
    if functionselector.count(calledge.iloc[i,0])<1 and functionselector.count(calledge.iloc[i,1])<1:
         G.add_edge(calledge.iloc[i,0],calledge.iloc[i,1])
         calledgelist.append([calledge.iloc[i,0],calledge.iloc[i,1]])
         
         calledgeelement.append(calledge.iloc[i,0])
         calledgeelement.append(calledge.iloc[i,1])
         km=0
         for ki in range(0,len(functions)):
             if list(functions[ki]).count(calledge.iloc[i,1]):
                 ak=ki
             if list(functions[ki]).count(calledge.iloc[i,0]):
                 bk=ki
         callgraph.append([ak,bk])
         km=km+1

calledgecom=set(calledgeelement)

callG=nx.DiGraph()#调用图
for element in callgraph:
    callG.add_edge(element[0],element[1])
print('callgraph',callgraph)

# python3 csdg.py