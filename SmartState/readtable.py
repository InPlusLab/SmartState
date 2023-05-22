import pandas as pd
b=pd.read_csv("dapp_Result_for_dos.csv",header=None)
analyze_before=[]
for n in range(0,len(b)):
    analyze_before.append(b.iloc[n,0])
print(len(analyze_before),analyze_before)

#python3 readtable.py