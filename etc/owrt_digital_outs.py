#!/usr/bin/env python3

import sys
from owrt_snmp_protocol import snmp_protocol
from threading import Thread, Lock

try:
    import ubus
except ImportError:
    logger.error('Failed import ubus.')
    sys.exit(-1)

fl_run_main = True
curr_relays = {}
snmp_pr = snmp_protocol()
uci_config_snmp = "owrt_digital_outs"
lock_curr_relays = Lock()

def ubus_init():
    def get_state_callback(event, data):
        ret_val = {}
        sect = data['id_relay']
        lock_curr_relays.acquire()
        try:
            relay_dict = curr_relays[sect]
        except KeyError:
            # poll relay with id_relay not found
            ret_val["state"] = '-1'
            ret_val["status"] = '-2'
        else:
            ret_val["state"] = relay_dict['state']
            ret_val["status"] = relay_dict['status']
        finally:
            lock_curr_relays.release()
            event.reply(ret_val)

    ubus.add(
        'owrt_digital_outs', {
            'get_state': {
                'method': get_state_callback,
                'signature': {
                    'id_relay': ubus.BLOBMSG_TYPE_STRING
                }
            }
        }
    )


def check_param_relay(param):
    try:
        address = param['address']
        port = param['port']
        oid = param['oid']
        period = param['period']
        community = param['community']
        timeout = param['timeout']
    except KeyError:
        return False
    return True


def parseconfig():
    lock_curr_relays.acquire()
    curr_relays.clear()
    lock_curr_relays.release()
    try:
        confvalues = ubus.call("uci", "get", {"config": uci_config_snmp})
    except RuntimeError:
        sys.exit(-1)

    for confdict in list(confvalues[0]['values'].values()):
        if confdict['.type'] == "relay":
            if confdict['.name'] != "relay_prototype_snmp":
                if confdict['proto'] == "SNMP":
                    if not check_param_relay(confdict):
                        continue

                    confdict['status'] = '-1'
                    confdict['state'] = '-1'
                    lock_curr_relays.acquire()
                    curr_relays[confdict['id_relay']] = confdict
                    lock_curr_relays.release()


def diff_param_poll_snmp(config, protodict):
    try:
        if config['address'] == protodict['address'] and config['community'] == protodict['community'] and \
            config['oid'] == protodict['oid'] and config['port'] == protodict['port'] and \
            config['timeout'] == protodict['timeout'] and config['period'] == protodict['period']:
            return False
        else:
            return True
    except KeyError:
        return True


def reparseconfig(event, data):
    global fl_run_main
    if data['config'] == uci_config_snmp:
        try:
            conf_proto = ubus.call("uci", "get", {"config": uci_config_snmp})
        except RuntimeError:
            print("RuntimeError: uci get {0}".format(uci_config_snmp))
            fl_run_main = False
            return

        # Add & edit relay
        for protodict in list(conf_proto[0]['values'].values()):
            if protodict['.type'] == "relay":
                if protodict['.name'] != "relay_prototype_snmp":
                    if protodict['proto'] == "SNMP":

                        lock_curr_relays.acquire()
                        config = curr_relays.get(protodict['id_relay'])
                        if config is None:
                            # Add new relay
                            protodict['status'] = '-1'
                            protodict['state'] = '-1'
                            curr_relays[protodict['id_relay']] = protodict
                            lock_curr_relays.release()

                        else:
                            # Edit relay
                            if diff_param_poll_snmp(config, protodict):
                                snmp_pr.stop_snmp_poll(config['id_task'])
                                del curr_relays[config['id_relay']]

                                if check_param_relay(protodict):
                                    protodict['status'] = '-1'
                                    protodict['state'] = '-1'
                                    curr_relays[protodict['id_relay']] = protodict

                                lock_curr_relays.release()

                            else:
                                lock_curr_relays.release()
                                continue

                        # Run polling thread on SNMP
                        thrd = Thread(target=run_poll_relay, args=(protodict['id_relay'], ))
                        thrd.start()

        # Deleting relay
        lock_curr_relays.acquire()
        relays = list(curr_relays.keys())
        lock_curr_relays.release()
        for relay in relays:
            relay_exists = False
            for protodict in list(conf_proto[0]['values'].values()):
                if protodict['.type'] == "relay":
                    if protodict['.name'] != "relay_prototype_snmp":
                        if protodict['proto'] == "SNMP":
                            try:
                                if protodict['id_relay'] == relay:
                                    relay_exists = True
                                    break
                            except KeyError:
                                pass

            if relay_exists == False:
                lock_curr_relays.acquire()
                try:
                    config = curr_relays.pop(relay)
                    snmp_pr.stop_snmp_poll(config['id_task'])
                except KeyError:
                    lock_curr_relays.release()
                    continue
                else:
                    lock_curr_relays.release()


def run_poll_relay(relay):
    lock_curr_relays.acquire()
    config_relay = curr_relays.get(relay)
    if config_relay is None:
        # relay delete
        lock_curr_relays.release()
        return

    if not check_param_relay(config_relay):
        del curr_relays[relay]
        lock_curr_relays.release()
        return

    id_poll = snmp_pr.start_snmp_poll(config_relay['address'], config_relay['community'], config_relay['oid'],
                                      config_relay['port'], config_relay['timeout'], config_relay['period'])
    config_relay['id_task'] = id_poll
    tmp_cnfg_relay = config_relay.copy()
    lock_curr_relays.release()

    if tmp_cnfg_relay['start_state'] != 'NO':
        id_set = snmp_pr.set_snmp_value(tmp_cnfg_relay['address'], tmp_cnfg_relay['community'], tmp_cnfg_relay['oid'],
                                        tmp_cnfg_relay['port'], tmp_cnfg_relay['timeout'], tmp_cnfg_relay['start_state'])
        res_set = "-1"
        while res_set == "-1":
            res_set = snmp_pr.res_set_snmp_value(id_set)
        # TODO: handling error set_snmp_value()


def poll_state_changed(relay):
    lock_curr_relays.acquire()
    config_relay = curr_relays.get(relay)
    if config_relay is None:
        # relay delete
        lock_curr_relays.release()
        return

    try:
        id_poll = config_relay['id_task']
        old_state = config_relay['state']
        id_relay = config_relay['id_relay']
    except KeyError:
        lock_curr_relays.release()
        return

    state, status = snmp_pr.get_snmp_poll(id_poll)
    if status == "0":
        # Checking change state
        if state != old_state:
            ubus.send("signal", {"event": "statechanged", "id": id_relay, "state": state})

    try:
        config_relay['state'] = state
        config_relay['status'] = status
    except KeyError:
        pass

    lock_curr_relays.release()


if __name__ == '__main__':
    if not ubus.connect("/var/run/ubus.sock"):
        sys.stderr.write('Failed connect to ubus\n')
        sys.exit(-1)

    ubus_init()
    parseconfig()

    lock_curr_relays.acquire()
    relays = list(curr_relays.keys())
    lock_curr_relays.release()
    for relay in relays:
        th = Thread(target=run_poll_relay, args=(relay, ))
        th.start()

    ubus.listen(("commit", reparseconfig))

    try:
        while fl_run_main:
            ubus.loop(1)
            lock_curr_relays.acquire()
            relays = list(curr_relays.keys())
            lock_curr_relays.release()
            for relay in relays:
                poll_state_changed(relay)
                ubus.loop(1)
    except KeyboardInterrupt:
        print("__main__ === KeyboardInterrupt")
    finally:
        lock_curr_relays.acquire()
        relays = list(curr_relays.keys())
        for relay in relays:
            try:
                config = curr_relays.pop(relay)
                snmp_pr.stop_snmp_poll(config['id_task'])
            except KeyError:
                continue
        lock_curr_relays.release()

    ubus.disconnect()
