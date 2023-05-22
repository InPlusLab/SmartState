from tkt.run_tkt import run_tkt
import re
import os
import csv
#filename= './tkt/0x9CEFd9588f076c5f805341864adC8a6F077A5b99.csv'
def TSDgeneration(tran_path,filename,path):
    path_name=tran_path+'/'+filename+'.csv'
    FSM_model=run_tkt(path_name)
    FSM_edge=[]
    for i in range(0,len(FSM_model)-1):
        FSM_split=re.split(r'(?:[->:(])', FSM_model[i])
        #print(edge)
        FSM_edge.append([int(FSM_split[0].strip()),int(FSM_split[2].strip()),FSM_split[3].strip()])

    #print(FSM_edge)
    TSD_edge=[]
    for m in range(0,len(FSM_edge)):
        for n in range(0,len(FSM_edge)):
            #print(FSM_edge[m][1], FSM_edge[n][0])
            if(FSM_edge[m][1] == FSM_edge[n][0] and FSM_edge[m][2]!=FSM_edge[n][2]):
                #print(m,n)
                TSD_edge.append([FSM_edge[m][2],FSM_edge[n][2]])

    # os.chdir(path)
    with open(os.path.join(path, "TSD-edge.csv"),'w',newline='',encoding='UTF-8') as f_c_csv:
        writer = csv.writer(f_c_csv)
        #writer.writerow(['source','target'])
        for m in range(0,len(TSD_edge)):
        
            writer.writerow(TSD_edge[m])
    print("TSD analysis finsih！")

#python3 TSDgeneration.py