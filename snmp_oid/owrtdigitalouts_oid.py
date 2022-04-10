
from journal import journal
import sys

class owrtdigitalouts(object):
    def __init__(self):
        self.number_nodes = 64
        self.resources = [
            {'oid': '.1.3.6.1.4.1.25728.8900.1.1.3', 'type': 'integer', 'rd': self.get_state, 'wr': self.set_state},
            {'oid': '.1.3.6.1.4.1.25728.8900.1.1.6', 'type': 'string', 'rd': self.get_memo, 'wr': self.set_memo},
            {'oid': '.1.3.6.1.4.1.25728.8900.1.1.15', 'type': 'integer', 'rd': self.get_status, 'wr': None}
        ]


    def get_state_status(self, id_relay):
        state = -1
        status = -1
        try:
            import ubus
        except ImportError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "owrtdigitalouts_oid Error import ubus")
            return state, status

        if not ubus.connect("/var/run/ubus.sock"):
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "owrtdigitalouts_oid Failed connect to ubus")
            return state, status

        result = ubus.call("owrt-digital-outs", "get_state", {"id_relay": str(id_relay), "ubus_rpc_session": "String"})
        ubus.disconnect()
        try:
            state = int(result[0]['state'])
            status = int(result[0]['status'])
        except ValueError:
            state = -1
            status = -1

        return state, status


    def get_state(self, id_relay):
        state, status = self.get_state_status(id_relay)
        return state


    def get_status(self, id_relay):
        state, status = self.get_state_status(id_relay)
        return status

    def get_memo(self, id_relay):
        ret_val = ""
        try:
            import ubus
        except ImportError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "owrtdigitalouts_oid Error import ubus")
            return ret_val

        if not ubus.connect("/var/run/ubus.sock"):
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "owrtdigitalouts_oid Failed connect to ubus")
            return ret_val

        result = ubus.call("owrt-digital-outs", "get_memo", {"id_relay": str(id_relay), "ubus_rpc_session": "String"})
        ubus.disconnect()
        ret_val = result[0]['memo']

        return ret_val

    def set_state(self, id_relay, value):
        ret_val = -1
        try:
            import ubus
        except ImportError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "owrtdigitalouts_oid Error import ubus")
            return ret_val

        if not ubus.connect("/var/run/ubus.sock"):
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "owrtdigitalouts_oid Failed connect to ubus")
            return ret_val

        try:
            value = int(value)
        except ValueError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", f"owrtdigitalouts_oid Value for set not integer: {value}")
            return ret_val

        if value == 1:
            result = ubus.call("owrt-digital-outs", "on_relay", {"id_relay": str(id_relay), "ubus_rpc_session": "String"})
        elif value == 0:
            result = ubus.call("owrt-digital-outs", "off_relay", {"id_relay": str(id_relay), "ubus_rpc_session": "String"})
        else:
            return ret_val
        ubus.disconnect()

        ret_val = result[0]['result']
        try:
            ret_val = int(ret_val)
        except ValueError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "owrtdigitalouts_oid: Error return value from set_state()")
            return -1

        return ret_val

    def set_memo(self, id_relay, value):
        uci_config_digital = "owrt-digital-outs"
        ret_val = -1

        try:
            import ubus
        except ImportError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "owrtdigitalouts_oid Error import ubus")
            return ret_val

        if not ubus.connect("/var/run/ubus.sock"):
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "owrtdigitalouts_oid Failed connect to ubus")
            return ret_val

        try:
            confvalues = ubus.call("uci", "get", {"config": uci_config_digital})
        except RuntimeError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err", f"set_memo() error get config uci {uci_config_digital}")
            return ret_val

        for confdict in list(confvalues[0]['values'].values()):
            if confdict['.type'] == "info" and confdict['.name'] == str(id_relay):
                ubus.call("uci", "set", {"config": uci_config_digital, "section": confdict['.name'], "values": {"memo": value}})
                ubus.call("uci", "commit", {"config": uci_config_digital})
                ubus.send("commit", {"config": uci_config_digital})
                ret_val = 0
                break

        ubus.disconnect()
        return ret_val
