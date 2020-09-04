import subprocess


class ActiveScanner:

    @staticmethod
    def arp_scan(device, network_id):
        subprocess.Popen(
            ['arp-scan', f'--interface={device}', network_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    @staticmethod
    def arp_scan_local():
        subprocess.Popen(
            ['arp-scan', '-l'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    @staticmethod
    def nmap_1000(ip):
        # nmap --top-ports 1000 ip
        subprocess.Popen(
            ['nmap', '--top-ports', '1000', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    @staticmethod
    def nmap_100(ip):
        # nmap --top-ports 100 ip
        subprocess.Popen(
            ['nmap', '--top-ports', '100', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    @staticmethod
    def nmap_topports_udp(ip):
        # nmap -sTU --top-ports
        subprocess.Popen(
            ['nmap', '-sU', '--top-ports', '1000', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    @staticmethod
    def nmap_mikrotik(ip):
        # nmap -nn -p80,8080,443,8291,8292,9281
        # nmap -sTU --top-ports
        subprocess.Popen(
            ['nmap', '-sTU', '-p80,8080,443,8291,8292,9281', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    @staticmethod
    def nmap_OS(ip):
        pass


def main():
    ActiveScanner.arp_scan_local()
    ActiveScanner.arp_scan('eno1', '172.27.162.0/26')


if __name__ == "__main__":
    main()