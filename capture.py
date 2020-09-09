from scapy.all import *
from zulu_time import ZuluTime

load_contrib("cdp")
load_contrib("lldp")


class Capture(threading.Thread):
    def __init__(self, interface, data_collection, network_info, oui_lookup, port_lookup, description=''):

        threading.Thread.__init__(self)

        self.interface = interface
        self.data_collection = data_collection
        self.network_info = network_info
        self.oui_lookup = oui_lookup
        self.port_lookup = port_lookup
        self.description = description

        self._running = False

        self.data_collection.collect = self._get_collection_stub()
        self.current_network = None

    def run(self):
        while not self.network_info.interface_up:
            time.sleep(1)

        self._running = True
        sniff(iface=self.interface, prn=self._packet_handler, store=0, count=0)

    def stop(self):
        self._running = False

    def _stop_filter(self, pkt):
        return self._running

    def _packet_handler(self, pkt):
        # check if device network switched
        self._check_current_network()

        if pkt.haslayer(IP):
            # check source IP
            if self.current_network is not None and self.network_info.ip_in_network(pkt[IP].src):
                # source IP is in local network
                self._process_local_device(pkt)
            elif self._is_private_ip(pkt[IP].src):
                # source IP not in local network, but is a private IP
                self._process_private_device(pkt)
            else:
                # source IP is not in local network
                self._process_external_device(pkt)
        elif self.current_network is not None:
            # no IP, so process as local devices
            self._process_local_device(pkt)

    def _check_current_network(self):
        interface_network_string = self.network_info.network_string
        if self.current_network != interface_network_string and interface_network_string != 'None':
            # set current network to network value of the interface
            self.current_network = interface_network_string
            # if this network isn't in collection, then add it
            if self.current_network is not None and self.current_network not in self.data_collection.collect['local_networks']:
                network_stub = self._get_network_stub()
                self.data_collection.collect['local_networks'][self.current_network] = network_stub[self.current_network]

    def _process_private_device(self, pkt):
        mac = pkt.src
        ip = pkt[IP].src

        block = ''
        if ip.split('.')[0] == '10':
            block = '10.0.0.0'
        if ip.split('.')[0] == '172':
            block = '.'.join(ip.split('.')[2]) + '.0.0'
        elif '.'.join(ip.split('.')[:2]) == '192.168':
            block = '192.168.0.0'

        # add block to collection if not in already
        if block not in self.data_collection.collect['local_networks']:
            self.data_collection.collect['local_networks'][block] = {}
            self.data_collection.collect['local_networks'][block]['devices'] = {}


        if mac in self.data_collection.collect['local_networks'][block]['devices']:
            # already in there; so check for updated info
            dev = self.data_collection.collect['local_networks'][block]['devices'][mac]

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
            flags = str(pkt[TCP].flags)
            port = pkt[TCP].sport
            if 'R' not in flags:
                # don't process if it's a reset flag
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
                try:
                    for x in range(pkt[DNS].ancount):
                        # if the response IP matches the packet source IP, then append the hostname of the device
                        if pkt[DNS].an[x].rdata == ip:
                            dev['host_name'] = pkt[DNS].an[x].rrname.decode()
                        break
                except:  # got 'non-iterable' exception for 'pkt[DNS].an[x].rdata == ip:'
                    pass

            #check for TivoConnect Discovery Protocol (on Netgear devices)
            if pkt[UDP].sport == 2190:
                tcdp = self._extract_tcdp(pkt)
                if tcdp is not None and tcdp not in dev['data_collect']:
                    dev['data_collect'].append(tcdp)


            #check for MNDP
            if pkt[UDP].sport == 5678:
                mndp = self._extract_mndp(pkt)
                if mndp is not None and mndp not in dev['data_collect']:
                    dev['data_collect'].append(mndp)


        # check for CDP data
        if pkt.dst == '01:00:0c:cc:cc:cc':
            hostname, cdp_data = self._extract_cdp(pkt)
            if hostname is not None:
                dev['host_name'] = hostname
            if cdp_data is not None and cdp_data not in dev['data_collect']:
                dev['data_collect'].append(cdp_data)

        # check for LLDP
        if pkt.haslayer(LLDPDU):
            hostname, lldp_data = self._extract_lldp(pkt)
            if hostname is not None:
                dev['host_name'] = hostname
            if lldp_data is not None and lldp_data not in dev['data_collect']:
                dev['data_collect'].append(lldp_data)

        self.data_collection.collect['local_networks'][block]['devices'][mac] = dev

        # check for EAPOL
        """
        if pkt.haslayer(EAPOL):
            eapol = []
            for x in pkt.getlayer(Raw):
                eapol.append(x.load.hex())
            if len(eapol) > 0:
                record['eapol'] = ''.join(eapol)
        """

    def _process_local_device(self, pkt):
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
            dev = self._get_device_stub()

            dev['mac_address'] = mac
            dev['ip_address'] = ip
            dev['manufacturer'] = self.oui_lookup.get_manufacturer(mac)
            dev['is_you'] = True if mac == self.network_info.original_mac else False
            dev['last_seen'] = ZuluTime.get_timestamp()

        if pkt.haslayer(TCP):
            flags = str(pkt[TCP].flags)
            port = pkt[TCP].sport
            if 'R' not in flags:
                # don't process if it's a reset flag
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
                try:
                    for x in range(pkt[DNS].ancount):
                        # if the response IP matches the packet source IP, then append the hostname of the device
                        if pkt[DNS].an[x].rdata == ip:
                            dev['host_name'] = pkt[DNS].an[x].rrname.decode()
                        break
                except:  # got 'non-iterable' exception for 'pkt[DNS].an[x].rdata == ip:'
                    pass

            #check for TivoConnect Discovery Protocol (on Netgear devices)
            if pkt[UDP].sport == 2190:
                tcdp = self._extract_tcdp(pkt)
                if tcdp is not None and tcdp not in dev['data_collect']:
                    dev['data_collect'].append(tcdp)

            # check for MNDP
            if pkt[UDP].sport == 5678:
                mndp = self._extract_mndp(pkt)
                if mndp is not None and mndp not in dev['data_collect']:
                    dev['data_collect'].append(mndp)


        # check for CDP data
        if pkt.dst == '01:00:0c:cc:cc:cc':
            hostname, cdp_data = self._extract_cdp(pkt)
            if hostname is not None:
                dev['host_name'] = hostname
            if cdp_data is not None and cdp_data not in dev['data_collect']:
                dev['data_collect'].append(cdp_data)

        # check for LLDP
        if pkt.haslayer(LLDPDU):
            hostname, lldp_data = self._extract_lldp(pkt)
            if hostname is not None:
                dev['host_name'] = hostname
            if lldp_data is not None and lldp_data not in dev['data_collect']:
                dev['data_collect'].append(lldp_data)



        self.data_collection.collect['local_networks'][self.current_network]['devices'][mac] = dev

        # check for EAPOL
        """
        if pkt.haslayer(EAPOL):
            eapol = []
            for x in pkt.getlayer(Raw):
                eapol.append(x.load.hex())
            if len(eapol) > 0:
                record['eapol'] = ''.join(eapol)
        """

    def _process_external_device(self, pkt):
        # only process from source side

        mac = pkt.src
        ip = pkt[IP].src

        if ip not in self.data_collection.collect['external_devices']:
            dev = self._get_device_stub()
            dev['mac_address'] = mac
            dev['ip_address'] = ip
            dev['manufacturer'] = self.oui_lookup.get_manufacturer(mac)
            dev['is_you'] = False
            dev['last_seen'] = ZuluTime.get_timestamp()
        else:
            dev = self.data_collection.collect['external_devices'][ip]
            dev['last_seen'] = ZuluTime.get_timestamp()

        if pkt.haslayer(TCP):
            flags = str(pkt[TCP].flags)
            port = pkt[TCP].sport
            if 'R' not in flags:
                # don't process if it's a reset
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
        #print(dev)

    def _extract_cdp(self, pkt):
        hostname = None
        data = []

        # device ID / hostname
        if pkt.haslayer(CDPMsgDeviceID):
            hostname = pkt[CDPMsgDeviceID].val.decode()
            #device_id = pkt[CDPMsgDeviceID].val.decode()
            #data.append(f'device id: {device_id}')

        # platform
        if pkt.haslayer(CDPMsgPlatform):
            platform = pkt[CDPMsgPlatform].val.decode().upper().replace('CISCO', '')
            data.append(f'platform: {platform}')

        # software version
        if pkt.haslayer(CDPMsgSoftwareVersion):
            version = pkt[CDPMsgSoftwareVersion].val.decode()
            data.append(f'version: {version}')
            #version_values = pkt[CDPMsgSoftwareVersion].val.decode()
            #software_version = [x for x in version_values.split(',') if 'VERSION' in x.upper()]
            #if len(software_version) > 0:
            #    data.append(f'version: {software_version[0].strip().upper().replace("VERSION", "")}')

        # management address
        if pkt.haslayer(CDPMsgMgmtAddr):
            management_address = pkt[CDPMsgMgmtAddr].addr
            for x in management_address:
                pass
            addresses = ', '.join([x.addr for x in management_address])
            data.append(f'management address: {addresses}')

        # addresses
        if pkt.haslayer(CDPMsgAddr):
            address = pkt[CDPMsgAddr].addr
            for x in address:
                pass
            addresses = ', '.join([x.addr for x in address])
            data.append(f'addresses: {addresses}')

        # capabilities
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
            cdp_data = 'CDP {' + '; '.join(data) + '}'
            return hostname, cdp_data
        else:
            return None, None

    def _extract_lldp(self, pkt):
        hostname = None
        data = []

        '''
        # LLDPConfiguration
        if pkt.haslayer(LLDPConfiguration):
            config = pkt[LLDPConfiguration]
            data.append(f'config: {config}')

        # LLDPDUChassisID
        if pkt.haslayer(LLDPDUChassisID):
            chassis_id = pkt[LLDPDUChassisID]
            data.append(f'chassis id: {chassis_id}')

        # LLDPDUManagementAddress
        if pkt.haslayer(LLDPDUManagementAddress):
            mngt = pkt[LLDPDUManagementAddress]
            data.append(f'mngt add: {mngt}')

        # LLDPDUSystemCapabilities
        if pkt.haslayer(LLDPDUSystemCapabilities):
            capabilities = pkt[LLDPDUSystemCapabilities]
            data.append(f'capabilities: {capabilities}')
        '''
        # LLDPDUSystemDescription
        if pkt.haslayer(LLDPDUSystemDescription):
            desc = pkt[LLDPDUSystemDescription].description.decode()
            desc_str = str(desc)
            data.append(f'system: {desc}')
        '''
        # LLDPDUSystemName
        if pkt.haslayer(LLDPDUSystemName):
            name = pkt[LLDPDUSystemName]
            data.append(f'name: {name}')
            hostname = name
        
            LLDPDUEndOfLLDPDU
            LLDPDUGenericOrganisationSpecific
            LLDPDUManagementAddress
                SUBTYPE_MANAGEMENT_ADDRESS_IPV4
            LLDPDUPortDescription
            LLDPDUPortID
            LLDPDUSystemCapabilities
            LLDPDUSystemDescription
            LLDPDUSystemName
        '''
        if len(data) > 0:
            llpd_data = 'LLDP {' + '; '.join(data) + '}'
            return hostname, llpd_data
        else:
            return None, None

    def _extract_tcdp(self, pkt):
        try:
            tcdp = pkt[Raw].load.decode().replace('\n', '; ').strip()
            tcdp = f'TCDP {{{tcdp}}}'
            return tcdp
        except:
            return None

    def _extract_mndp(self, pkt):
        try:
            mndp = pkt[Raw].load.decode().strip()
            mndp = f'MNDP {{{mndp}}}'
            return mndp
        except:
            return None

    def _get_collection_stub(self):
        stub = {'local_networks': {}, 'external_devices': {}}

        return stub

    def _get_network_stub(self):
        network_id = self.network_info.network_string
        mac = self.network_info.mac
        ip = self.network_info.ip
        interface_name = self.network_info.interface_name
        manufacturer = self.network_info.manufacturer
        host_name = self.network_info.hostname

        stub = {}

        stub[network_id] = {}
        stub[network_id]['network_id'] = network_id
        stub[network_id]['interface'] = interface_name
        stub[network_id]['ip_address'] = ip
        stub[network_id]['mac_address'] = mac
        stub[network_id]['devices'] = {}
        stub[network_id]['devices'][mac] = {}

        stub[network_id]['devices'][mac]['mac_address'] = mac
        stub[network_id]['devices'][mac]['ip_address'] = ip
        stub[network_id]['devices'][mac]['manufacturer'] = manufacturer
        stub[network_id]['devices'][mac]['host_name'] = host_name
        stub[network_id]['devices'][mac]['connection_type'] = ''
        stub[network_id]['devices'][mac]['is_you'] = True
        stub[network_id]['devices'][mac]['protocols_seen'] = []
        stub[network_id]['devices'][mac]['open_tcp_ports'] = []
        stub[network_id]['devices'][mac]['open_udp_ports'] = []
        stub[network_id]['devices'][mac]['data_collect'] = []
        stub[network_id]['devices'][mac]['last_seen'] = ZuluTime.get_timestamp()

        return stub

    def _get_device_stub(self):

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

    def _is_private_ip(self, ip):
        is_private = False

        if ip.split('.')[0] == '10':
            is_private = True
        elif ip.split('.')[0] == '172' and str(ip.split('.')[1]) in range(16, 32):
            is_private = True
        elif '.'.join(ip.split('.')[:2]) == '192.168':
            is_private = True

        return is_private