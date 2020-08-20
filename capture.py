from scapy.all import *
from zulu_time import ZuluTime

load_contrib("cdp")
load_contrib("lldp")


class Capture(threading.Thread):
    def __init__(self, interface, data_collection, network_info, oui_lookup, port_lookup, description=''):

        threading.Thread.__init__(self)

        self.oui_lookup = oui_lookup
        self.port_lookup = port_lookup
        self.network_info = network_info
        self.interface = interface
        self.data_collection = data_collection
        self.description = description

        self._running = False

        self.data_collection.collect = self.get_network_stub()
        self.current_network = self.network_info.network_string

    def run(self):
        self._running = True
        sniff(iface=self.interface, prn=self._packet_handler, store=0, count=0)

    def stop(self):
        self._running = False

    def _stop_filter(self, pkt):
        return self._running

    def _packet_handler(self, pkt):

        if pkt.haslayer(IP):
            #check source IP
            if self.network_info.ip_in_network(pkt[IP].src):
                # IP is in local network
                self._process_local_device(pkt)
            else:
                # source IP is not in local network
                self._process_external_device(pkt)

            #
            #if self.network_info.ip_in_network(pkt[IP].dst):
            #    # IP is in local network
            #    self._process_local_device(pkt, 'dst')

            #don't process destination IP's out of the network
            #else:
            #    # source IP is not in local network
            #    self._process_external_device(pkt, 'dst')
        else:
            #no IP, so process source and destination as local devices
            self._process_local_device(pkt)
            #self._process_local_device(pkt, 'dst')


            # 01:00:0c:cc:cc:cc -> CDP

        """
        if pkt.haslayer(EAPOL):
            print(f"EAPOL - {str(timestamp)}")
            record = self._create_record(pkt, timestamp)
            record['record_type'] = 'eapol'
            eapol = []
            for x in pkt.getlayer(Raw):
                eapol.append(x.load.hex())
            if len(eapol) > 0:
                record['eapol'] = ''.join(eapol)

        elif self.mode == 'target-list':
            target = self._target_found(pkt)
            if target and _allow_collect(target, timestamp):
                record = self._create_record(pkt, timestamp)
                record['record_type'] = 'target-hit'
                record['target_hit'] = {}
                record['target_hit']['target'] = target

        elif self.mode == 'all-selectors':
            record = self._create_record(pkt, timestamp)
            record['record_type'] = 'selector-collect'

            collect = False
            for identifier in record['macs']:
                if self._allow_collect(identifier, timestamp):
                    collect = True
            if not collect:
                record = None

        if record:
            self.api.queue_record(record)
        """

    def _process_local_device(self, pkt):
        # only processing data from the source side
        # local devices may not have IP information
        #check for LLMNR -> ip o

        mac = pkt.src
        ip = pkt[IP].src if pkt.haslayer(IP) else None
        if ip is None:
            # check if it's arp
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                ip = pkt[ARP].psrc

        if mac in self.data_collection.collect['local_networks'][self.current_network]['devices']:
            # already in there; so check for updated info
            dev = self.data_collection.collect['local_networks'][self.current_network]['devices'][mac]

            # check if there's already an IP for this device
            current_ip = dev['ip_address']

            # if the new_ip value isn't null and it doesn't match the previous ip, then update the record
            if ip is not None and ip != current_ip:
                dev['ip_address'] = ip

            dev['last_seen'] = ZuluTime.get_timestamp()
        else:
            # new device
            dev = self.get_device_stub()

            dev['mac_address'] = mac
            dev['ip_address'] = ip
            dev['manufacturer'] = self.oui_lookup.get_manufacturer(mac)
            dev['is_you'] = True if mac == self.network_info.mac else False
            dev['last_seen'] = ZuluTime.get_timestamp()

        if pkt.haslayer(TCP):
            port = pkt[TCP].sport

            service = self.port_lookup.get_service_by_port(port, 'tcp')
            if service:
                if service not in dev['protocols_seen']:
                    dev['protocols_seen'].append(service)
                if port not in dev['open_tcp_ports']:
                    dev['open_tcp_ports'].append(port)

        if pkt.haslayer(UDP):
            port = pkt[UDP].sport

            service = self.port_lookup.get_service_by_port(port, 'udp')
            if service:
                if service not in dev['protocols_seen']:
                    dev['protocols_seen'].append(service)
                if port not in dev['open_udp_ports']:
                    dev['open_udp_ports'].append(port)

            #check for mDNS or DNS replies
            if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
                for x in range(pkt[DNS].ancount):
                    # if the response IP matches the packet source IP, then append the hostname of the device
                    if pkt[DNS].an[x].rdata == ip:
                        dev['host_name'] = pkt[DNS].an[x].rrname.decode()
                        break

            #check for TivoConnect Discovery Protocol (on Netgear devices)
            if pkt[UDP].sport == 2190:
                tcdp = self._extract_tcdp(pkt)
                if tcdp is not None and tcdp not in dev['data_collect']:
                    dev['data_collect'].append(tcdp)

        # check for CDP data
        if pkt.dst == '01:00:0c:cc:cc:cc':
            hostname, cdp_data = self._extract_cdp(pkt)
            if hostname is not None:
                dev['host_name'] = hostname
            if cdp_data is not None and cdp_data not in dev['data_collect']:
                dev['data_collect'].append(cdp_data)

        # check for LLDP
        if pkt.haslayer(LLDPDU):
            lldp_data = self._extract_lldp(pkt)
            if lldp_data is not None and lldp_data not in dev['data_collect']:
                dev['data_collect'].append(lldp_data)

        self.data_collection.collect['local_networks'][self.current_network]['devices'][mac] = dev

    def _process_external_device(self, pkt):
        # only process from source side

        mac = pkt.src
        ip = pkt[IP].src

        if ip not in self.data_collection.collect['external_devices']:
            dev = self.get_device_stub()
            dev['mac_address'] = mac
            dev['ip_address'] = ip
            dev['manufacturer'] = self.oui_lookup.get_manufacturer(mac)
            dev['is_you'] = False
            dev['last_seen'] = ZuluTime.get_timestamp()
        else:
            dev = self.data_collection.collect['external_devices'][ip]
            dev['last_seen'] = ZuluTime.get_timestamp()

        if pkt.haslayer(TCP):
            port = pkt[TCP].sport
            service = self.port_lookup.get_service_by_port(port, 'tcp')
            if service:
                if service not in dev['protocols_seen']:
                    dev['protocols_seen'].append(service)
                if port not in dev['open_tcp_ports']:
                    dev['open_tcp_ports'].append(port)
        if pkt.haslayer(UDP):
            port = pkt[UDP].sport
            service = self.port_lookup.get_service_by_port(port, 'udp')
            if service:
                if service not in dev['protocols_seen']:
                    dev['protocols_seen'].append(service)
                if port not in dev['open_udp_ports']:
                    dev['open_udp_ports'].append(port)

        self.data_collection.collect['external_devices'][ip] = dev

    def _extract_cdp(self, pkt):
        #print('****FOUND CDP****')
        # CDPv2HDR
        #if pkt.haslayer(CDPv2_HDR):
        #    cdp = pkt[CDPv2_HDR]
        hostname = None
        data = []

        #device ID / hostname
        if pkt.haslayer(CDPMsgDeviceID):
            hostname = pkt[CDPMsgDeviceID].val.decode()
            #device_id = pkt[CDPMsgDeviceID].val.decode()
            #data.append(f'device id: {device_id}')

        #platform
        if pkt.haslayer(CDPMsgPlatform):
            platform = pkt[CDPMsgPlatform].val.decode().upper().replace('CISCO', '')
            data.append(f'platform: {platform}')

        #software version
        if pkt.haslayer(CDPMsgSoftwareVersion):
            version_values = pkt[CDPMsgSoftwareVersion].val.decode()
            software_version = [x for x in version_values.split(',') if 'VERSION' in x.upper()]
            if len(software_version) > 0:
                data.append(f'version: {software_version[0].strip().upper().replace("VERSION", "")}')

        #management address
        if pkt.haslayer(CDPMsgMgmtAddr):
            management_address = pkt[CDPMsgMgmtAddr].addr
            for x in management_address:
                pass
            addresses = ', '.join([x.addr for x in management_address])
            data.append(f'management address: {addresses}')

        #capabilities
        if pkt.haslayer(CDPMsgCapabilities):
            capabilities = str(pkt[CDPMsgCapabilities].cap)
            data.append(f'capabilities: {capabilities}')

        #native vlan
        if pkt.haslayer(CDPMsgNativeVLAN):
            vlan = pkt[CDPMsgNativeVLAN].vlan
            data.append(f'native vlan: {vlan}')
        """
        if pkt.haslayer(CDPMsgAddr):
            address = pkt[CDPMsgAddr].addr
        if pkt.haslayer(CDPMsgPortID):
            port_id = pkt[CDPMsgPortID].iface.decode()
        
        if pkt.haslayer(CDPMsgProtoHello):
            proto_hello = pkt[CDPMsgProtoHello].fields
        if pkt.haslayer(CDPMsg):
            message = pkt[CDPMsg].val.decode()
        # if pkt.haslayer(CDPMsgGeneric):
        #    msg_gen = pkt[CDPMsgGeneric].val.decode()
        """

        if len(data) > 0:
            cdp_data = 'CDP - (' + '; '.join(data) + ')'
            return hostname, cdp_data
        else:
            return None, None

    def _extract_lldp(self, pkt):
        # need to build out
        return None

    def _extract_tcdp(self, pkt):
        try:
            tcdp = pkt[Raw].load.decode().replace('\n', '; ').strip()
            tcdp = f'TCDP - ({tcdp})'
            return tcdp
        except:
            return None


    def get_network_stub(self):
        network_id = self.network_info.network_string
        mac = self.network_info.mac
        ip = self.network_info.ip
        interface_name = self.network_info.interface_name
        manufacturer = self.network_info.manufacturer
        host_name = self.network_info.hostname
        
        stub = {'local_networks': {}, 'external_devices': {}}

        stub['local_networks'][network_id] = {}
        stub['local_networks'][network_id]['network_id'] = network_id
        stub['local_networks'][network_id]['interface'] = interface_name
        stub['local_networks'][network_id]['ip_address'] = ip
        stub['local_networks'][network_id]['mac_address'] = mac
        stub['local_networks'][network_id]['devices'] = {}
        stub['local_networks'][network_id]['devices'][mac] = {}

        stub['local_networks'][network_id]['devices'][mac]['mac_address'] = mac
        stub['local_networks'][network_id]['devices'][mac]['ip_address'] = ip
        stub['local_networks'][network_id]['devices'][mac]['manufacturer'] = manufacturer
        stub['local_networks'][network_id]['devices'][mac]['host_name'] = host_name
        stub['local_networks'][network_id]['devices'][mac]['connection_type'] = ''
        stub['local_networks'][network_id]['devices'][mac]['is_you'] = True
        stub['local_networks'][network_id]['devices'][mac]['protocols_seen'] = []
        stub['local_networks'][network_id]['devices'][mac]['open_tcp_ports'] = []
        stub['local_networks'][network_id]['devices'][mac]['open_udp_ports'] = []
        stub['local_networks'][network_id]['devices'][mac]['data_collect'] = []
        stub['local_networks'][network_id]['devices'][mac]['last_seen'] = ZuluTime.get_timestamp()

        return stub

    def get_device_stub(self):

        dev = {}
        dev['mac_address'] = None
        dev['ip_address'] = None
        dev['host_name'] = None
        dev['manufacturer'] = None
        dev['connection_type'] = None
        dev['is_you'] = None
        dev['protocols_seen'] = []
        dev['open_tcp_ports'] = []
        dev['open_udp_ports'] = []
        dev['data_collect'] = []
        dev['last_seen'] = None

        return dev