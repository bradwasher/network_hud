import threading
import time
import subprocess
from active_scanner import ActiveScanner


class AutoScanner(threading.Thread):
    def __init__(self, data_collection, network_info, scan_interval):
        threading.Thread.__init__(self)

        self.data_collection = data_collection
        self.network_info = network_info
        self.scan_interval = scan_interval

        self._running = True  # setting the thread running to true

    def run(self):
        while self._running:

            # run scans if interface up
            if self.network_info.interface_up:
                ActiveScanner.arp_scan_local()

            time.sleep(self.scan_interval)

    def stop(self):
        self._running = False

