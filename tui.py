import npyscreen
import re
from zulu_time import ZuluTime
from active_scanner import ActiveScanner
import time


class TUIApp(npyscreen.StandardApp):
    def __init__(self, data_collection, network_info, interval, *args, **keywords):
        super(TUIApp, self).__init__(*args, **keywords)
        self.data_collection = data_collection
        self.network_info = network_info
        self.interval = interval

    def onStart(self):
        self.addForm("MAIN", MainForm, name="sneakyPETE")

    def while_waiting(self):
        pass
        #print(self.network_info.get_interface_string())

        #F = self.getForm('MAIN')
        #F.name = 'I'm a form'
        #F.display()

    def stop(self):
        exit(0)


class NetworkList(npyscreen.MultiLineAction):
    def __init__(self, *args, **keywords):
        super(NetworkList, self).__init__(*args, **keywords)

        self.networks = []
        self.values = self.networks

    def actionHighlighted(self, act_on_this, key_press):
        self.parent.current_network_id = act_on_this
        self.parent.display_data()


class NetworkListBox(npyscreen.BoxTitle):
    _contained_widget = NetworkList


class NetworkDevices(npyscreen.GridColTitles):
    default_column_number = 6
    always_show_cursor = True
    select_whole_line = True
    additional_x_offset = 0

    columns = ['IP Address', 'MAC Address', 'Host Name', 'Make', 'Is You', 'Last Seen']

    def custom_print_cell(self, actual_cell, cell_display_value):

        # check for devices not seen in a while
        if re.search("[0-9][0-9]m", cell_display_value):
            actual_cell.color = 'CAUTION'
        elif re.search("[0-9]h", cell_display_value):
            actual_cell.color = 'DANGER'
        elif cell_display_value == 'Yes':
            actual_cell.color = 'GOOD'

        # check for network devices
        elif cell_display_value == 'Mikrotik' or cell_display_value[:5] == 'Cisco' or cell_display_value == 'Netgear' or cell_display_value == 'Linksys' or cell_display_value[:7] == 'Tp-Link' or cell_display_value == 'Synology':
            actual_cell.color = 'GOOD'

        # check for 'None' in ip address
        elif cell_display_value == 'None':
            actual_cell.value = '------------'

        # default settings
        else:
            actual_cell.color = 'DEFAULT'


class InterfaceInfo(npyscreen.BoxTitle):
    _contained_widget = npyscreen.Textfield


class DeviceInfo(npyscreen.BoxTitle):
    _contained_widget = npyscreen.MultiLineEdit


class MainForm(npyscreen.FormBaseNewWithMenus):

    def __init__(self, *args, **keywords):
        super(MainForm, self).__init__(*args, **keywords)
        self.time_stamp = ZuluTime.get_timestamp()
        self.current_network_id = None

    def create(self):
        new_handlers = {
            # Set ctrl+Q to exit
            "^Q": self.exit_func
        }
        self.add_handlers(new_handlers)

        #the size of the terminal
        y, x = self.useable_space()

        # add modules
        self.interface_info = self.add(InterfaceInfo, name='Interface Info', relx=2, rely=2, max_height=3)

        self.device_info = self.add(DeviceInfo, name='Device Info', relx=2, rely=5, max_height=8)

        self.network_list = self.add(NetworkListBox, name='Networks', relx=2, rely=13, max_width=22)

        self.network_devices = self.add(NetworkDevices, name='Local Devices', relx=27, rely=13,
                                        select_whole_line=True,
                                        default_column_number=6,
                                        col_titles=['IP', 'MAC', 'Make', 'Host Name', 'Is You', 'Last Seen'])

        # create menu
        mac_address = self.parentApp.network_info.original_mac
        self.menu = self.add_menu(name='Menu')
        self.menu.addItemsFromList([
            ("Run - 'arp-scan -l'", self.arp_scan),
            ("Run - 'nmap --top-ports 1000'", self.nmap_1000),
            ("Run - 'nmap -sU --top-ports 1000'", self.nmap_topports_udp),
            ("Run - 'nmap -sTU -p80,8080,443,8291,8292,9281'", self.nmap_mikrotik),
            ("Switch MAC", self.change_mac),
            (f"Revert MAC - {mac_address}", self.revert_mac),
            ("Cancel", self.menu_cancel)
        ])


        #add handler for grid
        #self.network_devices.add_handlers({curses.ascii.NL: self.grid_selection})
        #self.network_devices.when_cursor_moved = curses.beep

        # display collected data
        self.current_network_id = None
        self.display_data()

    # menu event handlers
    def arp_scan(self):
        ActiveScanner.arp_scan_local()
        message = f"Ran: 'arp-scan -l'"
        npyscreen.notify(message, title='Notification')
        time.sleep(1.2)  # needed to have it show up for a visible amount of time

    def nmap_1000(self):
        ip = self.get_selected_ip()
        message = 'Error: Invalid IP Address'
        if ip is not None:
            ActiveScanner.nmap_1000(ip)
            message = f"Ran: 'nmap -nn --top-ports 1000 {ip}'"

        npyscreen.notify(message, title='Notification')
        time.sleep(1.2)  # needed to have it show up for a visible amount of time

    def nmap_topports_udp(self):
        ip = self.get_selected_ip()
        message = 'Error: Invalid IP Address'
        if ip is not None:
            ActiveScanner.nmap_topports_udp(ip)
            message = f"Ran: 'nmap -nn -sU --top-ports 1000 {ip}'"

        npyscreen.notify(message, title='Notification')
        time.sleep(1.2)  # needed to have it show up for a visible amount of time

    def nmap_mikrotik(self):
        ip = self.get_selected_ip()
        message = 'Error: Invalid IP Address'
        if ip is not None:
            ActiveScanner.nmap_mikrotik(ip)
            message = f"Ran: 'nmap - nn - p80, 8080, 443, 8291, 8292, 9281 {ip}'"

        npyscreen.notify(message, title='Notification')
        time.sleep(1.2)  # needed to have it show up for a visible amount of time

    def change_mac(self):
        mac = self.get_selected_mac()
        message = 'Error: Invalid MAC Address'
        if mac is not None:
            self.parentApp.network_info.change_mac(mac)
            message = f"MAC changed to: {mac}"

        npyscreen.notify(message, title='Notification')
        time.sleep(1.2)  # needed to have it show up for a visible amount of time

    def revert_mac(self):
        self.parentApp.network_info.revert_mac()

    def menu_cancel(self):
        pass

    # form loop
    def while_waiting(self):
        now = ZuluTime.get_timestamp()

        if (now - self.time_stamp).total_seconds() >= self.parentApp.interval:
            self.time_stamp = now
            self.display_data()
            self.update_menu()

    # display collected data in widgets
    def display_data(self):
        #display network interface data
        self.interface_info.name = self.parentApp.network_info.interface_name
        self.interface_info.value = self.parentApp.network_info.get_interface_string()
        self.interface_info.display()

        #display network list
        networks = self.parentApp.data_collection.get_local_networks()
        networks.append('External Devices')
        self.network_list.values = networks

        self.network_list.display()

        if self.current_network_id is None and len(self.network_list.values) > 0:
            self.current_network_id = self.network_list.values[0]

        #display network devices
        if self.current_network_id is not None:
            if self.current_network_id == 'External Devices':
                self.network_devices.values = self.parentApp.data_collection.get_external_devices()
            else:
                self.network_devices.values = self.parentApp.data_collection.get_local_network_devices(self.current_network_id)
            self.network_devices.display()

        #display captured data for device
        xy = self.network_devices.edit_cell
        if xy is not None:
            try:
                row = xy[0]
                mac_address = self.network_devices.values[row][1]
                manufacturer = self.network_devices.values[row][2]
                host_name = self.network_devices.values[row][3]
                self.device_info.name = f'{mac_address} - {manufacturer}' if host_name is None else f'{mac_address} - {host_name}'
                if self.current_network_id == 'External Devices':
                    ip_address = self.network_devices.values[row][0]
                    self.device_info.name = ip_address
                    self.device_info.value = self.parentApp.data_collection.get_external_device_summary(ip_address)
                else:
                    self.device_info.value = self.parentApp.data_collection.get_local_device_summary(self.current_network_id, mac_address)
                self.device_info.display()
            except:
                pass

    def get_selected_ip(self):
        ip_address = None
        xy = self.network_devices.edit_cell
        if xy is not None:
            row = xy[0]
            #ip_value = str(self.network_devices.values[row][0]).replace('-', '').strip()
            ip_value = self.network_devices.values[row][0]

            ip_address = ip_value

        return ip_address

    def get_selected_mac(self):
        mac_address = None
        xy = self.network_devices.edit_cell
        if xy is not None:
            row = xy[0]
            mac_value = self.network_devices.values[row][1]

            mac_address = mac_value

        return mac_address

    def update_menu(self):
        self.menu.items = None

    # exit TUI
    def exit_func(self, _input):
        exit(0)

