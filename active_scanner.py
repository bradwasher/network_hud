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


def main():
    ActiveScanner.arp_scan_local()
    ActiveScanner.arp_scan('eno1', '172.27.162.0/26')


if __name__ == "__main__":
    main()