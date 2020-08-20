from datetime import datetime
import time
import threading
from zulu_time import ZuluTime
import json

class PrintData(threading.Thread):
    def __init__(self, data_collection, network_info, sleep_time):

        threading.Thread.__init__(self)

        self.data_collection = data_collection
        self.network_info = network_info
        self.sleep_time = sleep_time
        self.sleep_time = float(sleep_time)

        self._running = True

    def run(self):

        while self._running:
            time.sleep(self.sleep_time)
            #self.print_report()
            self.print_json()

    def print_json(self):
        networks = self.data_collection.get_local_networks()
        devices = self.data_collection.get_local_network_devices(networks[0])

        tcp = self.data_collection.get_local_device_tcp_ports('172.27.162.0/26', '54:b2:03:08:44:24')
        udp = self.data_collection.get_local_device_tcp_ports('172.27.162.0/26', '54:b2:03:08:44:24')
        protocols = self.data_collection.get_local_device_tcp_ports('172.27.162.0/26', '54:b2:03:08:44:24')
        device_data = self.data_collection.get_local_device_tcp_ports('172.27.162.0/26', '54:b2:03:08:44:24')
        summary = self.data_collection.get_local_device_summary('172.27.162.0/26', '54:b2:03:08:44:24')

        data = self.data_collection.collect.copy()
        #json_data = json.loads(data)
        formatted_json = json.dumps(data, indent=2, default=str)
        print(formatted_json)
        print('\n\n')

    def print_report(self):
        time_stamp = ZuluTime.get_timestamp()
        data = self.data_collection.collect.copy()

        #common = set(str1) & set(str2)

        #print Network Info
        print('******Sneaky Pete v0.1************************************************************')
        print('*---- Local Network -------------------------------------------------------------*')
        print('DEVICE  IP ADDRESS      NETWORK ID          HOSTS       BROADCAST')


        print(f'{self.network_info.interface_name}\t{self.network_info.ip}\t{self.network_info.network_string}\t\t{self.network_info.network_hosts_string}\t{self.network_info.network_broadcast}\n')

        print('*---- Local Devices -------------------------------------------------------------*')
        print('IP ADDRESS      MAC                 MAKE    PROTOCOLS   IS YOU  LAST SEEN    INFO')

        devices = data['local_networks'][self.network_info.network_string]['devices'].values()
        sorted_devices = [x for x in devices if x['ip_address'] is not None]
        sorted_devices = sorted(sorted_devices, key=lambda k: int(k['ip_address'].split('.')[-1]))
        sorted_devices.extend([x for x in devices if x['ip_address'] is None])


        #for key, device in data['local_networks'][self.network_info.network_string]['devices'].items():
        for device in sorted_devices:
            last_seen = device['last_seen']
            time_diff = self._get_time_diff(time_stamp, last_seen)
            data_collect = ','.join(device['data_collect'])

            print(f'{device["ip_address"] if device["ip_address"] is not None else "-------------"}\t{device["mac_address"]}\t{device["manufacturer"]}\t{",".join(device["protocols_seen"])}\t{"yes" if device["is_you"] else "no"}\t{time_diff}\t{data_collect}')

        print('\n')
        print('*---- External Devices ----------------------------------------------------------*')
        print('IP ADDRESS      VIA MAC             MAKE    PROTOCOLS  LAST SEEN')

        for key, device in data['external_devices'].items():
            last_seen = device['last_seen']
            time_diff = self._get_time_diff(time_stamp, last_seen)
            print(f'{device["ip_address"]}\t{device["mac_address"]}\t{device["manufacturer"]}\t{",".join(device["protocols_seen"])}\t{time_diff}')

    def stop(self):
        self._running = False

    def _get_time_diff(self, start_time, stop_time):
        # 0:00:01.034353

        try:
            time_diff = str(start_time - stop_time).split('.')[0]

            # 0:00:01

            val = int(str(time_diff.replace(':', '')))
            # 00001
            if val < 100:
                return str(time_diff).split(':')[-1] + 's'
            elif val < 10000:
                return str(time_diff).split(':')[-2] + 'm'
            else:
                return str(time_diff).split(':')[-3] + 'h'
        except Exception as ex:
            return '????'




"""
******Sneaky Pete v0.1************************************************************
*---- Local Network -------------------------------------------------------------*
DEVICE  IP ADDRESS      NETWORK ID          HOSTS       BROADCAST
eno1    192.168.115.80  192.168.115.0/24    1-124       192.168.115.255

*---- Local Devices -------------------------------------------------------------*
IP ADDRESS      MAC                 MANUFACTURER    PROTOCOLS   IS YOU  LAST SEEN
192.168.115.76  de:ad:be:ef:12:34   Cisco Systems   dns, http   Yes     4 min

*---- External Devices ----------------------------------------------------------*
IP ADDRESS      VIA MAC             MANUFACTURER    PROTOCOLS   IS YOU  LAST SEEN
10.34.32.11     de:ad:be:ef:12:34   Cisco Systems   dns, http   Yes     4 min
"""