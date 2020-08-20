import threading
import time
import os
from ipaddress import IPv4Interface, IPv4Network, IPv4Address
from zulu_time import ZuluTime
from oui_lookup import OUILookup


class NetworkInfo(threading.Thread):
    def __init__(self, interface, oui_lookup, poll_interval=1):
        threading.Thread.__init__(self)

        self.interface_name = interface
        self.oui_lookup = oui_lookup
        self.poll_interval = poll_interval

        # make sure interface exists
        if not self.get_interface_exists():
            raise Exception("Interface doesn't exist")

        self.interface_up = None
        self.mac = None
        self.ip = None
        self.hostname = None
        self.network = None
        self. network_string = None
        self.network_broadcast = None
        self.is_private = None
        self.manufacturer = None
        self.network_hosts = None
        self.network_hosts_string = None

        self.update_values()

        self._running = True  # setting the thread running to true

    def run(self):
        while self._running:
            self.update_values()

            time.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    def update_values(self):
        self.interface_up = self.get_interface_up()
        self.mac = self.get_mac()
        self.ip = self.get_ip()
        self.hostname = self.get_hostname()
        self.network = self.get_network()
        self.network_string = str(self.network)
        self.network_broadcast = self.network.broadcast_address
        self.is_private = self.get_isprivate(self.network)
        self.manufacturer = self.oui_lookup.get_manufacturer(self.mac)
        self.network_hosts = list(self.network.hosts())
        self.network_hosts_string = self.get_network_hosts_string(str(self.network_hosts[0]),
                                                                  str(self.network_hosts[-1]))

    def get_interface_exists(self):
        return True if os.path.isdir(f'/sys/class/net/{self.interface_name}') else False

    def get_interface_up(self):
        return True if os.popen(f'cat /sys/class/net/{self.interface_name}/operstate').read().strip() == 'up' else False

    def get_mac(self):
        return os.popen(f'cat /sys/class/net/{self.interface_name}/address').read().strip()

    def get_ip(self):
        return os.popen(f'ip addr show {self.interface_name}').read().split("inet ")[1].split("/")[0]

    def get_network(self):
        addr = os.popen(f'ip addr show {self.interface_name}').read().split("inet ")[1].split()[0]
        ip_interface = IPv4Interface(addr)
        return ip_interface.network

    def get_hostname(self):
        return os.popen(f'hostname').read().strip()

    def ip_in_network(self, ip):
        address = IPv4Address(ip)
        return address in self.network_hosts

    def get_interface_string(self):
        description = f'IP: {self.ip}\t\tMAC: {self.mac}\t\tNetwork ID: {self.network_string}\t\tHosts: {self.network_hosts_string}\t\tBroadcasts: {self.network_broadcast}'
        return description

    @staticmethod
    def get_isprivate(network):
        return True if IPv4Network(network).is_private else False

    @staticmethod
    def get_network_hosts_string(s1, s2):
        min_len = len(s1) if len(s1) > len(s2) else len(s2)
        index = 0
        while index < min_len:
            if s1[index] != s2[index]:
                break
            index += 1

        return f"{s1[index:]}-{s2[index:]}"


def main():
    oui_lookup = OUILookup()
    network_info = NetworkInfo('eno1', oui_lookup)
    network_info.start()
    while True:
        print(network_info.get_interface_string())
        time.sleep(2)


if __name__ == "__main__":
    main()