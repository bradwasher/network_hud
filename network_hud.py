# global modules
import argparse
import time
import sys

# local modules
from capture import Capture
from data_collection import DataCollection
from network_info import NetworkInfo
from oui_lookup import OUILookup
from port_lookup import PortLookup
from tui import TUIApp
from auto_scanner import AutoScanner


def main():
    # get and validate command-line arguments
    args = get_args()

    try:
        oui_lookup = OUILookup()
        port_lookup = PortLookup()
        data_collection = DataCollection()
        network_info = NetworkInfo(args["monitor_interface"], oui_lookup)
        network_info.start()

        # only start auto scanner if value is not 0
        if args['auto_scan_interval'] != 0:
            auto_scanner = AutoScanner(data_collection, network_info, args['auto_scan_interval'])
            auto_scanner.start()

        capture = Capture(args["monitor_interface"], data_collection, network_info, oui_lookup, port_lookup)
        capture.start()

        tui = TUIApp(data_collection, network_info, args['report_interval'])
        tui.run()

    except (KeyboardInterrupt, SystemExit):  # when you press ctrl+c
        capture.stop()
        network_info.stop()

        if tui is not None:
            tui.stop()

        if auto_scanner is not None:
            auto_scanner.stop()


def get_args():
    """
    Get and validate command line arguments and return dictionary of those key/values
    :return:
    """
    ap = argparse.ArgumentParser()

    ap.add_argument("-n", "--report-interval", required=False,
                    help="interval in seconds between when records output to screen; defaults to 2")

    ap.add_argument("-a", "--auto-scan-interval", required=False,
                    help="interval in seconds between when auto scans are run against the network; defaults to 0 or never")

    ap.add_argument("-i", "--monitor-interface", required=True,
                    help="network interface the sensor is using to collect data")

    args = vars(ap.parse_args())
    # print(args)

    # validate report interval
    if args['report_interval'] is not None:
        try:
            args['report_interval'] = int(args['report_interval'])
        except ValueError:
            sys.exit(f"Exiting - Invalid Report Interval: {args['report_interval']}")
    else:
        args['report_interval'] = 2

    # validate ARP interval
    if args['auto_scan_interval'] is not None:
        try:
            args['auto_scan_interval'] = int(args['auto_scan_interval'])
        except ValueError:
            sys.exit(f"Exiting - Invalid Auto Scan Interval: {args['auto_scan_interval']}")
    else:
        args['auto_scan_interval'] = 0


    return args


if __name__ == "__main__":
    main()

