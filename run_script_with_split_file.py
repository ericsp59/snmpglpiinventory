from sys import argv
import math
import os
import subprocess

script, scan_script, regions_file = argv

cur_dir = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(cur_dir+'/ntwks'):
    os.mkdir(cur_dir+'/ntwks')

for f in os.listdir(cur_dir+'/ntwks'):
    os.remove(os.path.join(cur_dir+'/ntwks', f))    

def split_list_on_equal_parts(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def split_list(lst, c_num):
    tmp_list = []
    n = math.ceil(len(lst) / c_num)
    for x in range(0, len(lst), n):
        e_c = lst[x : n + x]
        if len(e_c) < n:
            e_c = e_c + [None for y in range(n - len(e_c))]
        tmp_list.append(e_c)
        # yield e_c
    return tmp_list            

# networks_spliting_list = split_list(net_list , parts_count)
f = open(regions_file, "r", encoding='utf-8')

all_regions_list = []
for line in f:
    all_regions_list.append(line)

spliting_list = split_list(all_regions_list , 50)


for i, el_list in enumerate(spliting_list):
    ntwks_part_file = open(f'{cur_dir}/ntwks/{i}_part.txt', 'w',encoding='utf-8')
    for net in el_list:
        if (net != None):
            ntwks_part_file.write(net)
    ntwks_part_file.close() 


for ntwks_file in os.listdir(cur_dir+'/ntwks'):
    print(f'python3 {scan_script} {cur_dir}/ntwks/{ntwks_file}')
    os.system(f'python3 {scan_script} {cur_dir}/ntwks/{ntwks_file} &')
    # subprocess.run(["python3", scan_script, f"{cur_dir}/ntwks/{ntwks_file}"], capture_output=True)
print('FINISHED')    
