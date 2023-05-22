import sys
# sys.path.append('.')
import pandas as pd
import subprocess


def get_prefix(s):
    return s[:8]


def run_tkt(filename):

    trans = pd.read_csv(filename, usecols=['timeStamp','functionName_without_parms'])
    trans = trans.sort_values(trans.columns[0])

    task = filename[:6]

    temporal_res = []
    temporal_res.append('START\n')

    for _, item in trans.iterrows():
        template = "{};{};B;{};a\n"
        temporal_res.append(template.format(task, item[1], item[0]))

    temporal_res.append('STOP')

    with open('./tkt/trace/trace.csv', 'w+') as f:
        f.writelines(temporal_res)

    TA_cmd = "java -cp tkt/tkt.jar it.unimib.disco.lta.timedKTail.ui.InferModel ./tkt/TA.jtml tkt/trace/"

    TA_run_cmd = TA_cmd.split(' ')
    p = subprocess.Popen(TA_run_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')
    p.wait()

    # java -jar export.jar TA.jtml
    TA_path_cmd = "java -jar tkt/export.jar ./tkt/TA.jtml"
    path_run_cmd = TA_path_cmd.split(' ')

    p = subprocess.Popen(path_run_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8')

    stdout, stderr = p.communicate()
    
    lines = " "

    if p.returncode == 0:
        stdout = str(stdout)
        lines = stdout.split('\n')
        # print(lines)

    return lines


#python3 run_tkt.py