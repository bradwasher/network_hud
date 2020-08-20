# OUI database from https://gitlab.com/wireshark/wireshark/raw/master/manuf
# saved in local directory as oui.txt

class OUILookup:
    def __init__(self):
        self.oui_list = {}

        with open("oui.txt", "r") as file:
            for line in file:
                line = line.strip()
                if line and line.strip()[0] != "#":
                    oui = line[:8].upper().replace(':', '')
                    manufacturer = line[8:].strip().split('\t')[0]
                    self.oui_list[oui] = manufacturer

    def get_manufacturer(self, mac):
        try:
            oui = mac.upper().replace(':', '')[:6]
            manufacturer = self.oui_list[oui]
            return manufacturer
        except:
            return 'unknown'

