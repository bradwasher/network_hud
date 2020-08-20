# network_hud
A python/linux based network heads up display.

Required Python3 Modules:
1. npyscreen -> pip3 install npyscreen
2. scapy -> pip3 install scapy

Required Linux Tools
1. apr-scan -> apt install arp-scan

Usage:
python3 network_hud.py -i <interface_name> -n <display_interval> -a <auto_scan_interval> 
python3 network_hud.py -i eno1 -n 1 -a 0

In Tool Usage:
arp-scan -> enter the menu using ctrl-x while the Network HUD is running and select "Execute 'arp-scan -l'" and press enter
view collected device data -> select device from the list of network devices and open tcp ports, open udp ports, protocols observed, and discovery protocols will be displayed in information box

Discovery Protocols Collected:
1. Cisco Discovery Protocol
2. TivoConnect Discovery Protocol
3. MikroTik Discovery Protocol (in development)
4. Link Layer Discovery Protocol (in development)
