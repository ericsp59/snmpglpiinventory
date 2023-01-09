from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.entity import engine, config
# from mysql.connector import connect, Error
from copy import copy, deepcopy
import nmap
import json
import re
from datetime import datetime
from sys import argv
import os
import ipaddress
from threading import Thread
import math
from datetime import datetime, date, time
import subprocess
import xml.etree.ElementTree as ET
from xml.dom import minidom

# mydb = connect(
#     host="localhost",
#     user="root",
#     password="glpi1234$",
#     database="glpi"
# )

cur_dir = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(cur_dir+'/logs'):
    os.mkdir(cur_dir+'/logs')
if not os.path.exists(cur_dir+'/tmp'):
    os.mkdir(cur_dir+'/tmp')

date_now =  datetime.now().strftime("%d-%m-%Y")


parts_count = 7

community_list = [ 'public', 'Avaya_RO', 'gvc_RD']
# community_list = ['Avaya_RO', 'gvc_RD']
custom_names_list = ['Avaya Phone', 'Brother NC-9300h', 'MFC-9340CDW']

def check_snmp_community_connect(host, community):
    try:
        cmd = f'snmpwalk -r1 -t1  -L n -v2c -c {community} {host} 1.3.6.1.2.1.1.3'
        res = os.system(f'{cmd}')
        if (res == 0):
            return True
        else:
            return False
    except:
        print(f'error_check_snmp_community_connect: {host}_{community}')
        return False             


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

# def check_inv_file_for_err(file):
#     f = open(file, "r", encoding='utf-8')
#     print(f)

def get_glpi_inventory_info(host, community, i):
    # print(f'get inv file {host} {community}')
    try:
        os.system(f'glpi-netinventory --host {host} --timeout 3 --credentials version:2c,community:{community} > {cur_dir}/tmp/{i}_{host}_{community}_inv.xml')    
    except:
        print(f'error_glpi-netinventory: {host}_{community}')

def check_dev_for_custom(host, community, name, i):
    try:
        f = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
        if (f.read().find(name) != -1):
            print(f'{host} - {name}')
            return name
        else:
            return False  
    except:
        print(f'error {i}: {host} {community}')          




def nmap_ping_scan(network_prefix,i):
    nm = nmap.PortScanner()
    try:
        ping_scan_raw_result = nm.scan(hosts=network_prefix, arguments='-v -n -sn')
        # ping_scan_raw_result = nm.scan(hosts=network_prefix, arguments='-v -n -sn -host-timeout 5s --min-parallelism 20')
        host_list = [result['addresses']['ipv4'] for result in ping_scan_raw_result['scan'].values() if
                    result['status']['state'] == 'up']
        # down_host_list = [result['addresses']['ipv4'] for result in ping_scan_raw_result['scan'].values() if
        #             result['status']['state'] == 'down']

        # for h in down_host_list:
        #     logfile.write(f'{h} is down\n')                 

        # print(f'ping_{network_prefix}:\n{host_list}\n')

        host_list_161_open = [] 
        ping_scan_161_raw_result = []
        if (host_list != []):
            for host in host_list:
                try:    
                    # ping_scan_161_raw_result = nm.scan(hosts=host, arguments='-sU -p 161 ')
                    ping_scan_161_raw_result = nm.scan(hosts=host, arguments='-sU -p 161 -host-timeout 5s --min-parallelism 20')

                    for result in ping_scan_161_raw_result['scan'].values():
                        if result['udp'][161]['state'] == 'open':
                            host_list_161_open.append(result['addresses']['ipv4']) 
                        elif ((result['udp'][161]['state'] == 'closed') or (result['udp'][161]['state'] == 'filtered')):
                            logFileName = f'net_log_{i}_{date_now}.txt'
                            logfile = open(f'{cur_dir}/logs/{logFileName}', 'a')
                            logfile.write(f'{host} 161 port is closed\n')
                            logfile.close()
                except Exception as e:
                    print(f'error_nmap_ping_scan_161: {host}\n {e}\n')                     
            if (host_list_161_open != []):                                        
                return host_list_161_open
    except Exception as e:
        print(f'error_nmap_ping_scan: {network_prefix}\n {e}\n')            


def change_tag_value(host, community, tag_name, tag_value,i):
    inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
    fileStr = inv_file.read()
    pattern = f'<{tag_name}>.*</{tag_name}>'
    new_file_str = re.sub(pattern, f'<{tag_name}>{tag_value}</{tag_name}>', fileStr)
    res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
    res_inv_file.write(new_file_str) 
    res_inv_file.close()            

def inject_dev(host, community, location,i):
    try:
        change_tag_value(host, community, 'LOCATION', location,i)
    except:
        print(f'change_tag_value: {host}_{community}')    
    try:
        print(f'{host}: inject_dev')    
        os.system(f'glpi-injector -v -r --file {cur_dir}/tmp/{i}_{host}_{community}_inv.xml --debug --url http://10.32.52.110/glpi/front/inventory.php')
    except:
        print(f'error_inject_dev: {host}_{community}')


def ingect_custom_snmp_info(host, community, name, dev_location,i):
    if (str(name) == 'MFC-9340CDW'):
        try:
            snmp_phone_info_dict = get_brother_MFC_9340CDW_snmp_info(host, community, name)
            inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
            fileStr = inv_file.read()
            
            new_file_str1 = fileStr.replace('<MODEL>MFC-9340CDW</MODEL>',
            f'''<MODEL>{snmp_phone_info_dict['model']}</MODEL>
            <LOCATION>{dev_location}</LOCATION>''')

            new_file_str = new_file_str1.replace('<PORT>',
            f'''<PORT>
            <IP>{host}</IP>''')

            res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            res_inv_file.write(new_file_str) 
            res_inv_file.close()
            try:
                print(f'{host}: ingect_custom_snmp_info')  
                os.system(f'glpi-injector -v -r --file {cur_dir}/tmp/{i}_{host}_{community}_inv.xml --debug --url http://10.32.52.110/glpi/front/inventory.php')
            except:
                print(f'error_inject_custom_snmp_info: {host}_{community}') 
        except Exception as e:
            print(f'!!!check_dev_for_custom!!!: {i} {host}\n {e}\n')



    if (str(name) == 'Brother NC-9300h'):
        try:
            snmp_phone_info_dict = get_brother_NC_9300h_snmp_info(host, community, name)
            inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
            fileStr = inv_file.read()
            
            new_file_str = fileStr.replace('<MODEL>NC-9300h</MODEL>',
            f'''<MODEL>{snmp_phone_info_dict['model']}</MODEL>
            <LOCATION>{dev_location}</LOCATION>''')

            res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            res_inv_file.write(new_file_str) 
            res_inv_file.close()
            try:
                os.system(f'glpi-injector -v -r --file {cur_dir}/tmp/{i}_{host}_{community}_inv.xml --debug --url http://10.32.52.110/glpi/front/inventory.php')
            except:
                print(f'error_inject_custom_snmp_info: {host}_{community}') 
        except Exception as e:
            print(f'!!!check_dev_for_custom!!!: {i} {host}\n {e}\n')


    if (str(name) == 'Avaya Phone'):
        try:
            snmp_phone_info_dict = get_avaya_snmp_info(host, community, name)
            inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
            fileStr = inv_file.read()

            registration = 'registered' if snmp_phone_info_dict['reg_state']=='2' else 'not_reg'
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y")
            last_reg_date = f'регистрация {dt_string}' if registration == 'registered' else ''
            

            new_file_str1 = fileStr.replace('<TYPE>PHONE</TYPE>',
            f'''<SERIAL>{snmp_phone_info_dict['serial_num']}</SERIAL>
            <TYPE>PHONE</TYPE>
            <LOCATION>{dev_location}</LOCATION>
            <COMMENT>{last_reg_date}</COMMENT>
            <CONTACT_NUM>{snmp_phone_info_dict['phone_num']}</CONTACT_NUM>
            <CONTACT>{registration}: {snmp_phone_info_dict['user']}</CONTACT>''')

            new_file_str = new_file_str1 .replace('<MODEL>J129D03A</MODEL>',
            f'''<MODEL>{snmp_phone_info_dict['model']}</MODEL>''')

            res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            res_inv_file.write(new_file_str) 
            res_inv_file.close()
            try:
                os.system(f'glpi-injector -v -r --file {cur_dir}/tmp/{i}_{host}_{community}_inv.xml --debug --url http://10.32.52.110/glpi/front/inventory.php')
            except:
                print(f'error_inject_custom_snmp_info: {host}_{community}') 

            def create_locations_query(location):
                now = datetime.now()
                dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
                insert_query = f"""
                INSERT INTO glpi_locations (name, completename, date_creation)
                VALUES('{location}', '{location}', NOW())
                ON DUPLICATE KEY UPDATE name = '{location}';
                """
                return insert_query
        except Exception as e:
            print(f'!!!check_dev_for_custom!!!: {i} {host}\n {e}\n')          

    
 

def get_brother_MFC_9340CDW_snmp_info(host, community,  name):
    oid_dicts_list = {
        'MFC-9340CDW': {
            'model':'iso.3.6.1.2.1.25.3.2.1.3',
        }
    }     
    res = {}
    new_name = name.replace(' ','')
    for oid in oid_dicts_list[new_name]:
        res.update({oid: get_oid_param(host, oid_dicts_list[new_name][oid], community)})  
    return res

def get_brother_NC_9300h_snmp_info(host, community,  name):
    oid_dicts_list = {
        'BrotherNC-9300h': {
            'model':'iso.3.6.1.2.1.25.3.2.1.3',
        }
    }     
    res = {}
    new_name = name.replace(' ','')
    for oid in oid_dicts_list[new_name]:
        res.update({oid: get_oid_param(host, oid_dicts_list[new_name][oid], community)})
    return res

def get_avaya_snmp_info(host, community,  name):

    # table: glpi_logs
    # item_type: Phone
    # id_search_option: 31 #status
    # old_value:
    # new_value:

    # insert into glpi_logs (itemtype, items_id, id_search_option, new_value) values('Phone', 5, 31, 'test_state_2');
    # select old_value,date_mod from glpi_logs where itemtype='Phone' and items_id=5 ORDER BY date_mod LIMIT 1;

    oid_dicts_list = {
        'AvayaPhone': {
            'name':'iso.3.6.1.4.1.6889.2.69.6.1.52',
            'mac' :'iso.3.6.1.4.1.6889.2.69.6.1.50', # = STRING: "c8:1f:ea:a1:5a:19" 
            'model' :'iso.3.6.1.4.1.6889.2.69.6.1.52', #= STRING: "J129D02A" 
            'IpAddress' : 'iso.3.6.1.4.1.6889.2.69.6.1.38', #= IpAddress: 10.4.194.29 ip
            'user' : 'iso.3.6.1.4.1.6889.2.69.6.7.26', #= STRING: "067010083@op.ru" user
            'reg_state': 'iso.3.6.1.4.1.6889.2.69.6.7.60',
            'phone_num' : 'iso.3.6.1.4.1.6889.2.69.6.13.13', 
            'serial_num': 'iso.3.6.1.4.1.6889.2.69.6.1.57',
            'last_reg' :'iso.3.6.1.4.1.6889.2.69.6.7.300', #= STRING: "2022-Mar-25 05:26:21" 
        }
    }     
    res = {}
    new_name = name.replace(' ','')
    for oid in oid_dicts_list[new_name]:
        try:
            res_oid = get_oid_param(host, oid_dicts_list[new_name][oid], community)
            # print(f'!!!res_oid: {res_oid}!!!')
            res.update({
                oid: res_oid
                })
        except Exception as e:
            print(f'!!!res_oid!!!: {i} {host} {oid}\n {e}\n{res_oid}\n')      
    return res




cmdGen = cmdgen.CommandGenerator()
def get_oid_param(dev_ip, oid_type, community):
    errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
    cmdgen.CommunityData(community),
    cmdgen.UdpTransportTarget((dev_ip, 161)),  
    cmdgen.MibVariable(oid_type),
    lookupMib=True,   
    )

    if errorIndication:
        print(errorIndication)
        # sys.exit()
    else:
        if errorStatus:
            print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'))
        else:
            current_dict = {}
            current_param = ''
            try:
                for varBindTableRow in varBindTable:
                    for name, val in varBindTableRow:
                        # print(name.prettyPrint(), val.prettyPrint())
                        current_param += val.prettyPrint()
                        current_param += ';'
                # print('---')        
                # print(current_param[:-1])        
                return current_param[:-1]
            except Exception as e:
                print(f'!!!get_oid_param_func!!!: {dev_ip} {oid_type} {community}\n {e}\n')     
# def get_oid_param(phone_ip, oid_type, community):
#     errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
#     cmdgen.CommunityData(community),
#     cmdgen.UdpTransportTarget((phone_ip, 161)),oid_type)
#     if errorIndication:
#         print(errorIndication)
#     else:
#         if errorStatus:
#             print('%s at %s' % (
#             errorStatus.prettyPrint(),
#             errorIndex and varBindTable[-1][int(errorIndex)-1] or '?'))
#         else:
#             current_dict = {}
#             current_param = ''
#             for varBindTableRow in varBindTable:
#                 for name, val in varBindTableRow:
#                     current_param += val.prettyPrint()
#                 return current_param


def add_dev_inventory(id_region_net_tuple,i):
    dev_location = id_region_net_tuple[0] + " " + id_region_net_tuple[1] 
    dev_ip = id_region_net_tuple[2]
    net_obj = ipaddress.IPv4Network(dev_ip)

    try:
        dev_opn_161_list = nmap_ping_scan(str(net_obj),i)
        if (dev_opn_161_list != [] and dev_opn_161_list != None):
            print(f'\n{i}: {id_region_net_tuple}:\n{dev_opn_161_list}\n')
            for host in dev_opn_161_list:
                for community in community_list:
                    try:
                        if (check_snmp_community_connect(host, community)):
                            try:
                                get_glpi_inventory_info(host, community,i)
                                is_custom = False
                                for name in custom_names_list:
                                    try:
                                        if(check_dev_for_custom(host, community, name,i) == name):
                                            is_custom = True
                                            try:
                                                ingect_custom_snmp_info(host, community, name, dev_location,i)
                                            except Exception as e:
                                                print(f'!!!ingect_custom_snmp_info!!!: {i} {host}\n {e}\n')    
    
                                    except Exception as e:
                                        print(f'!!!check_dev_for_custom!!!: {i} {host}\n {e}\n') 
                                if (is_custom == False):
                                    try:
                                        inject_dev(host, community, dev_location,i)
                                    except Exception as e:
                                        print(f'!!!inject_dev!!!: {i} {host}\n {e}\n')                                              
                                break

                            except Exception as e:
                                print(f'!!!get_glpi_inventory_info!!!: {i} {host}\n {e}\n')         

                        else:
                            pass
                    except Exception as e:
                        print(f'!!!check_snmp_community!!!: {i} {host}\n {e}\n')        
        else:
            print(f'\n{i}: {id_region_net_tuple} - no allowed hosts\n')        

    except Exception as e:
        print(f'!!!error!!!: {i} {str(net_obj)}\n {e}\n')

   
       


def th_func(pirocid_region_net_list, i):

    
    if (pirocid_region_net_list[i] != None):
        for id_region_net_tuple in pirocid_region_net_list[i]:

            if (id_region_net_tuple) != None:
                # print(f'{i} - add_dev_inventory: {id_region_net_tuple}')
                try:
                    add_dev_inventory(id_region_net_tuple,i)
                except Exception as e:
                    print(f'!!!exept_error!!!: {i} {id_region_net_tuple}\n {e}\n')
                    # # pass
                    # print(f'exept_error: {i}: {id_region_net_tuple}\n')
    print(f'!!!END!!! {i}:\n{pirocid_region_net_list[i]}\n')                

                       


script, regions_file = argv
f = open(regions_file, "r", encoding='utf-8')

net_list = []
count = 0
for x in f:
    if count < 0:
        break
    else:  
        x.replace('\n','')
        y = x.replace('\n','')
        z = y.split(', ')
        if len(z[0]) == 2:
            z[0] = '00'+z[0]
            print(z[0])  
        if len(z[0]) == 3:
            z[0] = '0'+z[0]  
            print(z[0])        
        t = tuple(map(str, z))
        net_list.append(t)
        count += 1

networks_spliting_list = split_list(net_list , parts_count)

# for i,x in enumerate(s):
#     print i

for i, pirocid_region_net_list in enumerate(networks_spliting_list):
    for count in range(parts_count):
        if (count == i):
            th = Thread(target=th_func, args=(networks_spliting_list, i))
            th.start()







