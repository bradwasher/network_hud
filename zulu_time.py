from datetime import datetime


class ZuluTime:
    def __init__(self):
        pass

    @staticmethod
    def get_timestamp():
        return datetime.utcnow()

    @staticmethod
    def get_timestamp_string():
        ts = datetime.utcnow()
        ts_str = str(ts).split('.')[0] + 'Z'
        return ts_str