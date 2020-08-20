
# list of service names and ports from
# https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml


class PortLookup:
    def __init__(self):
        self.tcp_ports = {}
        self.udp_ports = {}

        with open("service-names-port-numbers.csv", "r") as file:
            for line in file:
                values = line.strip().split(',')
                if values and len(values) > 1 and values[0] != '':
                    if 'udp' in values:
                        self.udp_ports[values[1]] = values[0]
                    elif 'tcp' in values:
                        self.tcp_ports[values[1]] = values[0]

    def get_service_by_port(self, port, protocol):
        try:
            if protocol == 'tcp':
                service = self.tcp_ports[str(port)]
            elif protocol == 'udp':
                service = self.udp_ports[str(port)]

            return service
        except KeyError as ex:
            return None

