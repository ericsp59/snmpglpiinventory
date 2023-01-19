from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.entity import engine, config
from pysnmp.smi import compiler, view, rfc1902											  
from mysql.connector import connect, Error
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

import numpy as np

storage_db_type = 'PluginGenericobjectStoragesystem'

# mydb = connect(
#      host="localhost",
#      user="root",
#      password="glpi1234$",
#      database="glpi"
#  )

cur_dir = os.path.dirname(os.path.abspath(__file__))
if not os.path.exists(cur_dir+'/logs'):
    os.mkdir(cur_dir+'/logs')
if not os.path.exists(cur_dir+'/tmp'):
    os.mkdir(cur_dir+'/tmp')

date_now =  datetime.now().strftime("%d-%m-%Y")


parts_count = 1

community_list = [ 'public', 'Avaya_RO', 'gvc_RD']
# community_list = ['Avaya_RO', 'gvc_RD']
custom_names_list = ['OceanStor Dorado 5000','Avaya Phone', 'Brother NC-9300h', 'MFC-9340CDW']

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

    info_pattern = f'<INFO>.*</INFO>'
    info_pattern_match_res = re.search(info_pattern, fileStr.replace('\n','---'))
    # print(f'====\ninfo_patern\n {info_pattern_match_res}\n====')
    if (info_pattern_match_res != None):
        info_file_str = info_pattern_match_res.group(0)
        # print(info_file_str.replace('---','\n'))

        pattern = f'<{tag_name}>.*</{tag_name}>'
        is_tag_exist = re.search(pattern, info_file_str)

        if (is_tag_exist != None):
            new_info_file_str = re.sub(pattern, f'<{tag_name}>{tag_value}</{tag_name}>', info_file_str)
            new_file_str = re.sub(info_pattern, new_info_file_str.replace('---','\n'), fileStr.replace('\n','---'))
            res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            res_inv_file.write(new_file_str.replace('---','\n')) 
            res_inv_file.close()
        else:
            new_info_file_str = re.sub(r'<INFO>', f'<INFO>\n\t\t\t\t<{tag_name}>{tag_value}</{tag_name}>', info_file_str)  
            new_file_str = re.sub(info_pattern, new_info_file_str.replace('---','\n'), fileStr.replace('\n','---'))  
            res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            res_inv_file.write(new_file_str.replace('---','\n')) 
            res_inv_file.close()

def change_port_ip(host, community, tag_name, tag_value,i): ## for printers  
    inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
    fileStr = inv_file.read()
    port_pattern = f'<PORT>.*</PORT>'
    port_pattern_match_res = re.search(port_pattern, fileStr.replace('\n','---'))
    if (port_pattern_match_res != None):
        port_file_str = port_pattern_match_res.group(0)  

        pattern = f'<{tag_name}>.*</{tag_name}>'
        is_tag_exist = re.search(pattern, port_file_str)

        if (is_tag_exist != None):
            new_port_file_str = re.sub(pattern, f'<{tag_name}>{tag_value}</{tag_name}>', port_file_str)
            new_file_str = re.sub(port_pattern, new_port_file_str.replace('---','\n'), fileStr.replace('\n','---'))
            res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            res_inv_file.write(new_file_str.replace('---','\n')) 
            res_inv_file.close()
        else:
            new_port_file_str = re.sub(r'<PORT>', f'<PORT>\n\t\t\t\t<{tag_name}>{tag_value}</{tag_name}>', port_file_str)  
            new_file_str = re.sub(port_pattern, new_port_file_str.replace('---','\n'), fileStr.replace('\n','---'))  
            res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            res_inv_file.write(new_file_str.replace('---','\n')) 
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

def find_value_in_tag(tag_name, f_str):
    pattern = f'<{tag_name}>.*</{tag_name}>'
    tmp = re.search(pattern, f_str).group()
    return tmp.replace(f'<{tag_name}>','').replace(f'</{tag_name}>', '')


def select_storagesystems_serial_query(serial):
    query = f"SELECT id, name, manufacturers_id, plugin_genericobject_storagesystemmodels_id from glpi_plugin_genericobject_storagesystems WHERE serial='{serial}'" 
    return query

def create_storage_in_db(snmp_dev_info_dict):
    now = datetime.now()
    # dd/mm/YY H:M:S
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S") 

def ingect_custom_snmp_info(host, community, name, dev_location,i):
    mydb = connect(
    host="localhost",
    user="root",
    password="glpi1234$",
    database="glpi"
)
    if (str(name) == 'OceanStor Dorado 5000'):
        try:
            snmp_dev_info_dict = get_OceanStor_Dorado_5000_snmp_info(host, community, name)

            # print(snmp_dev_info_dict)
            inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
            fileStr = inv_file.read()
            model = snmp_dev_info_dict['model'][0]
            print(f'!!model {model}')
            # model = find_value_in_tag('MODEL', fileStr)
            name = find_value_in_tag('NAME', fileStr)
            manufacturer = find_value_in_tag('MANUFACTURER', fileStr)

            snmp_dev_info_dict.update({'name': [name]})
            snmp_dev_info_dict.update({'model':[model]})
            snmp_dev_info_dict.update({'manufacturer': [manufacturer]})

            # for key, val in snmp_dev_info_dict.items():
            #     print(f'{key}: {val}')

            dev_name = snmp_dev_info_dict['name'][0]
            dev_serial = snmp_dev_info_dict['serial'][0]
            dev_model = snmp_dev_info_dict['model'][0]
            dev_manufacturer = snmp_dev_info_dict['manufacturer'][0]
            dev_ips = snmp_dev_info_dict['ip_address']
            dev_mac = snmp_dev_info_dict['mac']
            dev_lun_groups = snmp_dev_info_dict['lun_groups']
            dev_host_groups = snmp_dev_info_dict['host_groups']
            dev_storage_pools = snmp_dev_info_dict['storage_pools']

            dev_db_name = None
            dev_model_db_id = None     
            dev_manufacturer_db_id = None
            dev_ip_ids = None

            dev_db_id = None   

            try:
                with mydb as connection:
                    print('connection to DB OK')
                    with connection.cursor() as cursor:
                        cursor.execute(select_storagesystems_serial_query(dev_serial))
                        r = cursor.fetchall()
                        #### IF DEV NOT EXIST
                        if (r == []):
                            #### Check and get model_id
                            cursor.execute(f"SELECT id FROM glpi_plugin_genericobject_storagesystemmodels WHERE name='{dev_model}'")
                            r = cursor.fetchall() 
                            if (r == []):
                                cursor.execute(f"INSERT INTO glpi_plugin_genericobject_storagesystemmodels (name, date_creation) values ('{dev_model}', now())")
                                connection.commit()
                                cursor.execute(f"SELECT id FROM glpi_plugin_genericobject_storagesystemmodels WHERE name='{dev_model}'")
                                r = cursor.fetchall() 
                                if (r != []): dev_model_db_id = r[0][0]
                            else: dev_model_db_id = r[0][0]

                            #### Check and get manufacturer_id
                            cursor.execute(f"SELECT id FROM glpi_manufacturers WHERE name='{dev_manufacturer}'")
                            r = cursor.fetchall() 
                            if (r == []):
                                cursor.execute(f"INSERT INTO glpi_manufacturers (name, date_creation) values ('{dev_manufacturer}', now())")
                                connection.commit()
                                cursor.execute(f"SELECT id FROM glpi_manufacturers WHERE name='{dev_manufacturer}'")
                                r = cursor.fetchall() 
                                if (r != []): dev_manufacturer_db_id = r[0][0]
                            else: dev_manufacturer_db_id = r[0][0]

                            #### ## INSERT DEV
                            cursor.execute(f"INSERT INTO glpi_plugin_genericobject_storagesystems (name, serial, manufacturers_id, date_creation, plugin_genericobject_storagesystemmodels_id) values ('{dev_name}', '{dev_serial}', {dev_manufacturer_db_id}, NOW(), {dev_model_db_id})")
                            connection.commit()
                            cursor.execute(select_storagesystems_serial_query(dev_serial))
                            r = cursor.fetchall()
                            if (r != []): dev_db_id = r[0][0]
                        
                        #### IF DEV EXIST
                        else:
                            dev_db_id = r[0][0]
                            dev_db_name = r[0][1]
                            dev_manufacturer_db_id = r[0][2] 
                            dev_model_db_id = r[0][3]

                        #### Check and create IPs
                        for ip in dev_ips:
                            cursor.execute(f"SELECT id FROM glpi_ipaddresses WHERE name='{ip}' and mainitems_id = {dev_db_id} and mainitemtype='{storage_db_type}'")
                            r = cursor.fetchall()
                            if (r != []):
                                # print(f'{ip}: {r[0][0]}')
                                pass
                            else:
                                cursor.execute(f"INSERT INTO glpi_ipaddresses (name, itemtype, mainitems_id, mainitemtype) values ('{ip}','NetworkName',{dev_db_id},'{storage_db_type}')")
                                connection.commit()

                        #### Check and create MAC           
                        for mac in dev_mac:
                            cursor.execute(f"SELECT id FROM glpi_networkports WHERE mac='{mac}' and items_id = {dev_db_id} and itemtype='{storage_db_type}'")
                            r = cursor.fetchall()
                            if (r != []):
                                # print(f'{mac}: {r[0][0]}')
                                pass
                            else:
                                cursor.execute(f"INSERT INTO glpi_networkports (items_id, mac, itemtype) values ('{dev_db_id}','{mac}','{storage_db_type}')")
                                connection.commit() 

                        # #### Check and create LUN
                        # for lun_gr in dev_lun_groups:
                        #     for key, val in lun_gr.items():
                        #         lun_gr_str = ''
                        #         for k,v in val.items():
                        #             lun_gr_str += k+': '+v+'\n'
                        #         print(f'string - {lun_gr_str}')
                        #         cursor.execute(f"SELECT id FROM glpi_plugin_fields_plugingenericobjectstoragesystemstorgeinfos WHERE items_id = {dev_db_id} and itemtype='{storage_db_type}'")
                        #         r = cursor.fetchall()
                        #         if (r != []):
                        #             print(f'Check and create LUN - exist')
                        #             pass
                        #         else:
                        #             cursor.execute(f"INSERT INTO glpi_plugin_fields_plugingenericobjectstoragesystemstorgeinfos (items_id, itemtype, plugin_fields_containers_id, lungroupfield) values ({dev_db_id},'{storage_db_type}', 1, '{lun_gr_str}')")
                        #             connection.commit()

                        # #### Check and create hostgroup
                        # for host_gr in dev_host_groups:
                        #     for key, val in host_gr.items():
                        #         host_gr_str = ''
                        #         for k,v in val.items():
                        #             host_gr_str += k+': '+v+'\n'
                        #         print(f'string - {host_gr_str}')
                        #         cursor.execute(f"SELECT id FROM glpi_plugin_fields_plugingenericobjectstoragesystemstorgeinfos WHERE items_id = {dev_db_id} and itemtype='{storage_db_type}'")
                        #         r = cursor.fetchall()
                        #         if (r != []):
                        #             print(f'Check and create hostgroup - exist')
                        #             pass
                        #         else:
                        #             cursor.execute(f"INSERT INTO glpi_plugin_fields_plugingenericobjectstoragesystemstorgeinfos (items_id, itemtype, plugin_fields_containers_id, hostgroupfield) values ({dev_db_id},'{storage_db_type}', 1, '{host_gr_str}')")
                        #             connection.commit()

                        # #### Check and create storage_pools
                        # for storage_pool in dev_storage_pools:
                        #     for key, val in storage_pool.items():
                        #         storage_pool_str = ''
                        #         for k,v in val.items():
                        #             storage_pool_str += k+': '+v+'\n'
                        #         print(f'string - {storage_pool_str}')
                        #         cursor.execute(f"SELECT id FROM glpi_plugin_fields_plugingenericobjectstoragesystemstorgeinfos WHERE items_id = {dev_db_id} and itemtype='{storage_db_type}'")
                        #         r = cursor.fetchall()
                        #         if (r != []):
                        #             print(f'Check and create storage_pools - exist')
                        #             pass
                        #         else:
                        #             cursor.execute(f"INSERT INTO glpi_plugin_fields_plugingenericobjectstoragesystemstorgeinfos (items_id, itemtype, plugin_fields_containers_id, storagepoolfield) values ({dev_db_id},'{storage_db_type}', 1, '{storage_pool_str}')")
                        #             connection.commit()    


                        #### Check and create storage_system_storgeinfo
                        lun_gr_str = ''
                        for lun_gr in dev_lun_groups:
                            for key, val in lun_gr.items():
                                for k,v in val.items():
                                    lun_gr_str += k+': '+v+'\n'
                                # print(f'string - {lun_gr_str}') 

                        host_gr_str = ''
                        for host_gr in dev_host_groups:
                            for key, val in host_gr.items():
                                for k,v in val.items():
                                    host_gr_str += k+': '+v+'\n'
                                # print(f'string - {host_gr_str}')                                

                        storage_pool_str = ''
                        for storage_pool in dev_storage_pools:
                            for key, val in storage_pool.items():
                                for k,v in val.items():
                                    storage_pool_str += k+': '+v+'\n'
                                # print(f'string - {storage_pool_str}')                                

                        cursor.execute(f"SELECT id FROM glpi_plugin_fields_plugingenericobjectstoragesystemstorgeinfos WHERE items_id = {dev_db_id} and itemtype='{storage_db_type}'")
                        r = cursor.fetchall()
                        
                        if (r != []):
                            print(f'Check and create storage_system_storgeinfo - exist')
                            pass
                        else:
                            cursor.execute(f"INSERT INTO glpi_plugin_fields_plugingenericobjectstoragesystemstorgeinfos (items_id, itemtype, plugin_fields_containers_id,lungroupfield,hostgroupfield,storagepoolfield) values ({dev_db_id},'{storage_db_type}', 1, '{lun_gr_str}', '{host_gr_str}', '{storage_pool_str}')")
                            connection.commit()             




                        # Create model glpi_plugin_genericobject_storagesystemmodels
                        # Create manufacturer manufacturers_id
                        # Create IP
                        # Create MAC

                        #     cursor.execute(create_storage_system_query(snmp_dev_info_dict))
                        #         connection.commit()

            except Error as e:
                print(f'er -  {e}')            

            print(f'dev_db_id - {dev_db_id}')
            print(f'dev_db_name - {dev_db_name}')
            print(f'dev_models_db_id - {dev_model_db_id}')
            print(f'dev_manufacturer_db_id - {dev_manufacturer_db_id}')
            
            
            # # new_file_str1 = fileStr.replace('<MODEL>MFC-9340CDW</MODEL>',
            # # f'''<MODEL>{snmp_phone_info_dict['model']}</MODEL>
            # # <LOCATION>{dev_location}</LOCATION>''')

            # new_file_str = new_file_str1.replace('<PORT>',
            # f'''<PORT>
            # <IP>{host}</IP>''')

            # res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            # res_inv_file.write(new_file_str) 
            # res_inv_file.close()
            # try:
            #     print(f'{host}: ingect_custom_snmp_info')  
            #     #os.system(f'glpi-injector -v -r --file {cur_dir}/tmp/{i}_{host}_{community}_inv.xml --debug --url http://10.32.52.110/glpi/front/inventory.php')
            # except:
            #     print(f'error_inject_custom_snmp_info: {host}_{community}') 
        except Exception as e:
            print(f'!!!ingect_custom_snmp_info OceanStor Dorado 5000!!!: {i} {host}\n {e}\n')

    if (str(name) == 'MFC-9340CDW'):
        try:
            snmp_phone_info_dict = get_brother_MFC_9340CDW_snmp_info(host, community, name)
																								   
									 
			
																		 
															  
												   

            change_tag_value(host, community, 'LOCATION', dev_location,i)
            change_tag_value(host, community, 'MODEL', snmp_phone_info_dict['model'],i)
            change_port_ip(host, community, 'IP', host,i)

            # inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
            # fileStr = inv_file.read()
            # new_file_str1 = fileStr.replace('<MODEL>MFC-9340CDW</MODEL>',
            # f'''<MODEL>{snmp_phone_info_dict['model']}</MODEL>
            # <LOCATION>{dev_location}</LOCATION>''')
            # new_file_str = new_file_str1.replace('<PORT>',
            # f'''<PORT>
            # <IP>{host}</IP>''')
            # res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            # res_inv_file.write(new_file_str) 
            # res_inv_file.close()
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

            change_tag_value(host, community, 'LOCATION', dev_location,i)
            change_tag_value(host, community, 'MODEL', snmp_phone_info_dict['model'], i)
            # snmp_phone_info_dict = get_brother_NC_9300h_snmp_info(host, community, name)
            # inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
            # fileStr = inv_file.read()
            
            # new_file_str = fileStr.replace('<MODEL>NC-9300h</MODEL>',
            # f'''<MODEL>{snmp_phone_info_dict['model']}</MODEL>
            # <LOCATION>{dev_location}</LOCATION>''')

            # res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            # res_inv_file.write(new_file_str) 
            # res_inv_file.close()
            try:
                os.system(f'glpi-injector -v -r --file {cur_dir}/tmp/{i}_{host}_{community}_inv.xml --debug --url http://10.32.52.110/glpi/front/inventory.php')
            except:
                print(f'error_inject_custom_snmp_info: {host}_{community}') 
        except Exception as e:
            print(f'!!!check_dev_for_custom!!!: {i} {host}\n {e}\n')


    if (str(name) == 'Avaya Phone'):
        try:
            snmp_phone_info_dict = get_avaya_snmp_info(host, community, name)
																								   
									 

            registration = 'registered' if snmp_phone_info_dict['reg_state']=='2' else 'not_reg'
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y")
            last_reg_date = f'регистрация {dt_string}' if registration == 'registered' else ''
			

																 
																	 
							  
											   
											  
																		  
																				 

            change_tag_value(host, community, 'LOCATION', dev_location,i)
            change_tag_value(host, community, 'SERIAL', snmp_phone_info_dict['serial_num'],i)
            change_tag_value(host, community, 'COMMENT', last_reg_date,i)
            change_tag_value(host, community, 'CONTACT_NUM', snmp_phone_info_dict['phone_num'], i)
            change_tag_value(host, community, 'MODEL', snmp_phone_info_dict['model'],i)
            change_tag_value(host, community, 'CONTACT', f"{registration}: {snmp_phone_info_dict['user']}",i)

            # inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "r", encoding='utf-8')
            # fileStr = inv_file.read()
            # registration = 'registered' if snmp_phone_info_dict['reg_state']=='2' else 'not_reg'
            # now = datetime.now()
            # dt_string = now.strftime("%d/%m/%Y")
            # last_reg_date = f'регистрация {dt_string}' if registration == 'registered' else ''
            # new_file_str1 = fileStr.replace('<TYPE>PHONE</TYPE>',
            # f'''<SERIAL>{snmp_phone_info_dict['serial_num']}</SERIAL>
            # <TYPE>PHONE</TYPE>
            # <LOCATION>{dev_location}</LOCATION>
            # <COMMENT>{last_reg_date}</COMMENT>
            # <CONTACT_NUM>{snmp_phone_info_dict['phone_num']}</CONTACT_NUM>
            # <CONTACT>{registration}: {snmp_phone_info_dict['user']}</CONTACT>''')
            # new_file_str = new_file_str1 .replace('<MODEL>J129D03A</MODEL>',
            # f'''<MODEL>{snmp_phone_info_dict['model']}</MODEL>''')
            # res_inv_file = open(f'{cur_dir}/tmp/{i}_{host}_{community}_inv.xml', "w", encoding='utf-8')
            # res_inv_file.write(new_file_str) 
            # res_inv_file.close()
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


def list_split(listA, n):
    for x in range(0, len(listA), n):
        every_chunk = listA[x: n+x]

        if len(every_chunk) < n:
            every_chunk = every_chunk + \
                ['None' for y in range(n-len(every_chunk))]
        yield every_chunk   

def split_list_on_equal_parts(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]       
 
def get_OceanStor_Dorado_5000_snmp_info(host, community,  name):
    ##             1.3.6.1.4.1.34774.4.1.1.1.0
    ## SNMPv2-SMI::enterprises.34774.4.1.1.1.0
    ## 34774.4.1.23.4.5.1.2.2.49.
    #print('test')
    
    oid_dicts_list = {
        'OceanStorDorado5000': {
            'model':'1.3.6.1.4.1.34774.4.1.23.5.6.1.13.1',
            # 'model':'1.3.6.1.4.1.34774.4.1.23.5.6.1.13.1.48',
            'serial':'iso.3.6.1.4.1.34774.4.1.1.1',
            # 'host_name': 'iso.3.6.1.2.1.1.5',
            'ip_address': '1.3.6.1.4.1.34774.4.1.23.5.8.1.6',
            'mac': '1.3.6.1.4.1.34774.4.1.23.5.6.1.10',
            'storage_pools_count': 'iso.3.6.1.4.1.34774.4.1.23.4.2.1.1',
            'lun_groups_count': 'iso.3.6.1.4.1.34774.4.1.23.4.7.1.1',
            'host_groups_count': 'iso.3.6.1.4.1.34774.4.1.23.4.6.1.1',
            'lun_groups': 'iso.3.6.1.4.1.34774.4.1.23.4.7',
            'host_groups': 'iso.3.6.1.4.1.34774.4.1.23.4.6.1',
            'storage_pools': '1.3.6.1.4.1.34774.4.1.23.4.2.1',
            # 'disk_entry': '1.3.6.1.4.1.34774.4.1.23.5.1.1.26'
        }
    }     
    res = {}
    res_mod = {}
    new_name = name.replace(' ','')
    for oid in oid_dicts_list[new_name]:
        res.update({oid: get_oid_param(host, oid_dicts_list[new_name][oid], community)})  

    # for el in res:
    #     print(f'{el}:{res[el]}\n')
    storage_pools_count = 1
    lun_groups_count = 1
    host_groups_count = 1
    try:
        storage_pools_count = len(res['storage_pools_count'].split(";"))
    except Exception as e:
        print(f'!!!storage_pools_count!!!:\n {e}\n')

    try:
        lun_groups_count = len(res['lun_groups_count'].split(";"))
    except Exception as e:
        print(f'!!!lun_groups_count!!!:\n {e}\n')

    try:
        host_groups_count = len(res['host_groups_count'].split(";"))
    except Exception as e:
        print(f'!!!host_groups_count!!!:\n {e}\n')

    # print(f'storage_pools_count: {storage_pools_count}')      
    for x in res:
        
        if (x == 'model'):
            try:
                
                res[x] = '123'
                print(f'{x}: {res[x]} \n === \n') 
            except Exception as e:
                print(f'!!!model!!! \n {e}\n')    

        arr1 = []
        if ((res[x] !=None) and (res[x] != '')):
            arr1 = res[x].replace(',','|').split(';')
            if (x == 'storage_pools'):
                try:
                    split_arr1 = list(list_split(arr1, storage_pools_count))
                    storage_pools_arr = []
                    # print(f'pool_name: {split_arr1[1][2]}')
                    storage_pools_count_list = list(range(storage_pools_count))
                    for st in storage_pools_count_list:
                        storage_pool_dict = {}

                        pool_id = split_arr1[0][st]    
                        pool_name = split_arr1[1][st]    
                        pool_total_capacity = split_arr1[6][st]    
                        pool_free_capacity = split_arr1[8][st]

                        storage_pool_dict.update({pool_id: {f'{pool_id}: pool_name':pool_name, f'{pool_id}: pool_total_capacity': str(math.floor(int(pool_total_capacity)/1000000)) + ' ГБ', f'{pool_id}: pool_free_capacity': str(math.floor(int(pool_free_capacity)/1000000)) + ' ГБ'}})
                        storage_pools_arr.append(storage_pool_dict)
                    # for el in storage_pools_arr:
                    #     print(f'storage_pool: {el}\n')

                    res_mod.update({x: storage_pools_arr})
                except Exception as e:
                    print(f'!!!get_storage_pools!!!: \n {e}\n')  

            elif (x == 'lun_groups'):
                if (arr1 != []):
                    try:
                        split_arr1 = list(list_split(arr1, lun_groups_count)) 
                        lun_groups_arr = []
                        lun_groups_count_list = list(range(lun_groups_count))
                        for el in lun_groups_count_list:
                            # print(f'{el}\n---\n')
                            lun_group_dict = {}   
                            lun_group_id = split_arr1[0][el]
                            lun_group_name = split_arr1[1][el]
                            lun_group_lun_list = split_arr1[2][el]
                            lun_group_dict.update({lun_group_id: {f'{lun_group_id}: lun_group_name': lun_group_name, f'{lun_group_id}: lun_group_lun_list': lun_group_lun_list}})
                            lun_groups_arr.append(lun_group_dict)
                        # for el in lun_groups_arr:
                        #     print(f'lun_group: {el}\n')    
                        res_mod.update({x: lun_groups_arr})
                        
                    except Exception as e:
                        print(f'!!!get_lun_groups!!!: \n {e}\n')    
                else: res_mod.update({x:[]})  

            elif (x == 'host_groups'):
                if (arr1 != []):
                    try:
                        split_arr1 = list(list_split(arr1, host_groups_count)) 
                        host_groups_arr = []
                        host_groups_count_list = list(range(host_groups_count))
                        for el in host_groups_count_list:
                            # print(f'{el}\n---\n')
                            host_group_dict = {} 
                            host_group_id = split_arr1[0][el]
                            host_group_name = split_arr1[1][el]
                            host_group_host_list = split_arr1[2][el]
                            host_group_dict.update({host_group_id: {f'{host_group_id}: host_group_name': host_group_name, f'{host_group_id}: host_group_host_list': host_group_host_list}})
                            host_groups_arr.append(host_group_dict)
                        # for el in host_groups_arr:
                            # print(f'host_group: {el}\n')    
                        res_mod.update({x: host_groups_arr})
                        
                    except Exception as e:
                        print(f'!!!get_lun_groups!!!: \n {e}\n')    
                else: res_mod.update({x:[]})  

            # elif (x == 'host_groups'):
            #     host_group_id = arr1[0]
            #     host_group_name = arr1[1]
            #     host_group_lun_list = arr1[2]
            #     res_mod.update({x: [{host_group_id: {'host_group_name': host_group_name, 'host_group_lun_list': host_group_lun_list}}]})

            elif (x == 'ip_address'):
                
                ip_arr = []
                if (arr1 != []):
                    for ip in arr1:
                        if (ip != ''):
                            ip_arr.append(ip)
                # print(f'ip = {ip_arr}')            
                res_mod.update({x: ip_arr})
																						
			  

            elif (x == 'disk_entry'):
                count = math.floor(len(arr1)/26)
                for disk in arr1:
                    print(disk.encode())
                # splits = np.array_split(arr1, 26)
                # for array in splits:
                #     print(list(array))   
            else:
                res_mod.update({x: arr1})

        else:  res_mod.update({x: []})       
    # print('-------------')        
    # for k,v in res_mod.items():
    #     print(k, v)                     
    return res_mod    

# def get_brother_MFC_9340CDW_snmp_info(host, community,  name):
#     oid_dicts_list = {
#         'MFC-9340CDW': {
#             'model':'iso.3.6.1.2.1.25.3.2.1.3',
#         }
#     }     
#     res = {}
#     new_name = name.replace(' ','')
#     for oid in oid_dicts_list[new_name]:
#         res.update({oid: get_oid_param(host, oid_dicts_list[new_name][oid], community)})  
#     return res

# def get_brother_NC_9300h_snmp_info(host, community,  name):
#     oid_dicts_list = {
#         'BrotherNC-9300h': {
#             'model':'iso.3.6.1.2.1.25.3.2.1.3',
#         }
#     }     
#     res = {}
#     new_name = name.replace(' ','')
#     for oid in oid_dicts_list[new_name]:
#         res.update({oid: get_oid_param(host, oid_dicts_list[new_name][oid], community)})
#     return res


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
    lookupNames=True,
    lookupValues=True,   
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
                        # print(f'{name}: {type(val)}')
                        # print(f'{name}: {type(val.prettyPrint())}\n')
                        if (oid_type == '1.3.6.1.4.1.34774.4.1.23.5.6.1.13.1'):
                        #     print(f'{name}: {type(val)}')
                            raw_string = val.asOctets()
                            raw_string_decode = raw_string.decode('utf-8')
                            # current_param += raw_string
                            # current_param += ';'
                            return raw_string_decode

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







