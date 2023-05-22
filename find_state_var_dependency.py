import os
import re
import time
import pandas as pd
import csv
def find_SVD (path):

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    os.chdir(path)   #修改当前工作目录


    #state-dependency edge
    SD_edge=[]
    b=pd.read_table("contract.tac",delimiter='\n',header=None)
    k=0
    b.columns = ["3IR"]
    b['blockname']='0'
    b['leftvariable']='0'
    b['rightvariable']='0'
    b['option']='0'
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
        
            
    #print(b)
             

    #find sload state variable, struct, array, mapping
    for j in range(0,len(b)):
        sloadindex=b.iloc[j,0].find('SLOAD')
        if (sloadindex>0):   
            sloadstatement=b.iloc[j,0][(sloadindex+5):]
            addressindex=sloadstatement.find('(')
            if(addressindex>0):  ##find state variable, struct, array
                stateaddress=sloadstatement[(addressindex+1):]
                stateaddressmodify=stateaddress[:(len(stateaddress)-1)]
                state_var='stor_'+stateaddressmodify
                #print([state_var,b.iloc[j,1]]) ##modify here
                SD_edge.append([state_var,b.iloc[j,1]])
            else:
                leftfind=[j]
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
                        if (b.iloc[leftfind[m],4].find('SHA3')<0):
                            findSHA3=findSHA3 or 0
                        if (b.iloc[leftfind[m],4].find('SHA3')>-1):
                            findSHA3=findSHA3 or 1
                            #print(leftfind[m])
                            if(b.iloc[leftfind[m],0].count('(')>0 and b.iloc[leftfind[m],0].count(')')>0):
                                SHAaddress1=b.iloc[leftfind[m],0][b.iloc[leftfind[m],0].index('(')+1:b.iloc[leftfind[m],0].index(')')]
                            if(b.iloc[leftfind[m],0].count(')')>0):
                                delete=b.iloc[leftfind[m],0][b.iloc[leftfind[m],0].index(')')+1:] 
                            if(b.iloc[leftfind[m],0].count('(')>0 and b.iloc[leftfind[m],0].count(')')>0 and delete.count('(')>0 and delete.count(')')>0):
                                SHAaddress2=delete[delete.index('(')+1:delete.index(')')]
                                mapping='stor_'+SHAaddress1+'_'+SHAaddress2
                                SD_edge.append([mapping,b.iloc[j,1]])
                            #print([mapping,b.iloc[j,1]]) ##modify here
                    uloop=uloop+1
            
                #while(findSHA3<1):
                #    findSHA3=0
                #    SHAsplit=[]
                #    for m in range(0,len(leftfind)):
                #        SHAsplit=list(set(SHAsplit+re.split(r'(?:[,])',b.iloc[m,3])))
                #    leftfind=[]
                #    for n in range(1,len(SHAsplit)):
                #        leftfind=leftfind+b.iloc[:,2].find(SHAspilt[n])
                #    for m in range(0,len(leftfind)):
                #        if (b.iloc[leftfind(m),4].find('SHA3')<0):
                #            findSHA3=findSHA3 or 0
                #        if (b.iloc[leftfind(m),4].find('SHA3')>-1):
                #            findSHA3=findSHA3 or 1
                #            print(leftfind(m))
                #    time.sleep(6)
            
            
    #find sload state variable, struct, array, mapping
    #find the key                    
    for j in range(0,len(b)):
        sstoreindex=b.iloc[j,0].find('SSTORE')  
        if (sstoreindex>0):   
            storesplit=re.split(r'(?:[, : \s])',b.iloc[j,0])
            if (len(storesplit)>8):
                storekey=storesplit[7]
                staddressindex=storekey.find('(')
                if(staddressindex>0):  ##find state variable, struct, array
                    storeaddress=storekey[(addressindex+1):]
                    storeaddressmodify=storekey[:(len(stateaddress)-1)]
                    store_var='stor_'+stateaddressmodify
                    #print([b.iloc[j,1],store_var]) #modify here
                    SD_edge.append([b.iloc[j,1],store_var])
                else:
                    leftfind=[j]
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
                            if (b.iloc[leftfind[m],4].find('SHA3')<0):
                                findSHA3=findSHA3 or 0
                            if (b.iloc[leftfind[m],4].find('SHA3')>-1):
                                findSHA3=findSHA3 or 1
                                #print(leftfind[m])
                                if(b.iloc[leftfind[m],0].count('(')>0 and b.iloc[leftfind[m],0].count(')')>0):
                                    SHAaddress1=b.iloc[leftfind[m],0][b.iloc[leftfind[m],0].index('(')+1:b.iloc[leftfind[m],0].index(')')]
                                if(b.iloc[leftfind[m],0].count(')')>0):
                                    delete=b.iloc[leftfind[m],0][b.iloc[leftfind[m],0].index(')')+1:]    
                                if(b.iloc[leftfind[m],0].count('(')>0 and b.iloc[leftfind[m],0].count(')')>0 and delete.count('(')>0 and delete.count(')')>0):
                                    SHAaddress2=delete[delete.index('(')+1:delete.index(')')]
                                    mapping='stor_'+SHAaddress1+'_'+SHAaddress2
                                    #print([b.iloc[j,1],mapping]) ##modify here
                                    SD_edge.append([b.iloc[j,1],mapping])
                        uloop=uloop+1
            
    #print('state-dependency edge',SD_edge)                        



    with open("State-dependency-edge.csv",'w',newline='',encoding='UTF-8') as f_c_csv:
        writer = csv.writer(f_c_csv)
        #writer.writerow(['source','target'])
        for m in range(0,len(SD_edge)):
        
            writer.writerow(SD_edge[m])
    print("ASD analysis finsih！")
                
    #python3 find_state_var_dependency.py       