from zulu_time import ZuluTime

class DataCollection():
    def __init__(self):
        self.collect = {}

    def get_local_networks(self):
        networks = list(self.collect['local_networks'].keys()) if 'local_networks' in self.collect else []
        return networks

    def get_local_network_devices(self, network_id):
        #make a copy so we don't iterate over data as it is being collected
        data = self.collect.copy()
        time_stamp = ZuluTime.get_timestamp()
        if network_id in data['local_networks']:
            devices = data['local_networks'][network_id]['devices'].items()
            device_list = sorted([
                        [x[1]['ip_address'],
                        x[1]['mac_address'],
                        x[1]['manufacturer'],
                        x[1]['host_name'],
                        'Yes' if x[1]['is_you'] else 'No',
                        self._get_time_diff(time_stamp, x[1]['last_seen'])
                        ] for x in devices], key=lambda x: self.ip_to_int(x[0]))

            return device_list
        else:
            return []

    def get_local_device_tcp_ports(self, network_id, mac_address):
        try:
            device = self.collect['local_networks'][network_id]['devices'][mac_address]
            tcp_ports = ', '.join([str(x) for x in device['open_tcp_ports']])
            return tcp_ports
        except:
            return 'no tcp'

    def get_local_device_udp_ports(self, network_id, mac_address):
        #try:
        device = self.collect['local_networks'][network_id]['devices'][mac_address]
        udp_ports = ', '.join([str(x) for x in device['open_udp_ports']])
        return udp_ports
        #except:
        #    return 'no udp'

    def get_local_device_protocols(self, network_id, mac_address):
        try:
            device = self.collect['local_networks'][network_id]['devices'][mac_address]
            protocols = ', '.join(device['protocols_seen'])
            return protocols
        except:
            return ''

    def get_local_device_data(self, network_id, mac_address):
        try:
            device = self.collect['local_networks'][network_id]['devices'][mac_address]
            data_collect = '; '.join(device['data_collect'])
            return data_collect
        except:
            return ''

    def get_local_device_summary(self, network_id, mac_address):
        protocols = self.get_local_device_protocols(network_id, mac_address)
        tcp_ports = self.get_local_device_tcp_ports(network_id, mac_address)
        udp_ports = self.get_local_device_udp_ports(network_id, mac_address)
        device_data = self.get_local_device_data(network_id, mac_address)

        summary = f'Protocols: {protocols}\nTCP Ports: {tcp_ports}\nUDP Ports: {udp_ports}\nDevice Data: {device_data}'

        return summary

    @staticmethod
    def _get_time_diff(start_time, stop_time):
        try:
            time_diff = str(start_time - stop_time).split('.')[0]
            val = int(str(time_diff.replace(':', '')))
            if val < 100:
                return str(time_diff).split(':')[-1] + 's'
            elif val < 10000:
                return str(time_diff).split(':')[-2] + 'm'
            else:
                return str(time_diff).split(':')[-3] + 'h'
        except Exception as ex:
            return '????'

    @staticmethod
    #https://stackoverflow.com/questions/5619685/conversion-from-ip-string-to-integer-and-backward-in-python
    def ip_to_int(ip):
        if ip is not None:
            o = list(map(int, ip.split('.')))
            ip_int = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
            return ip_int
        else:
            return 0
