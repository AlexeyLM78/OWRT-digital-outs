#!/usr/bin/env python3

import sys
from owrt_snmp_protocol import snmp_protocol
from threading import Thread

try:
    import ubus
except ImportError:
    logger.error('Failed import ubus.')
    sys.exit(-1)

curr_relays = {}
snmp_pr = snmp_protocol()


def ubus_init():
    ubus.add(
        'owrt_digital_outs', {
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
    curr_relays.clear()
    try:
        confvalues = ubus.call("uci", "get", {"config": "owrt_digital_outs"})
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
                    curr_relays[confdict['id_relay']] = confdict


def run_poll_relay(config_relay):
    if config_relay['start_state'] != 'NO':
        id_set = snmp_pr.set_snmp_value(config_relay['address'], config_relay['community'], config_relay['oid'],
                                        config_relay['port'], config_relay['timeout'], config_relay['start_state'])
        res_set = "-1"
        while res_set == "-1":
            res_set = snmp_pr.res_set_snmp_value(id_set)
        # TODO: handling error set_snmp_value()

    id_poll = snmp_pr.start_snmp_poll(config_relay['address'], config_relay['community'], config_relay['oid'],
                                      config_relay['port'], config_relay['timeout'], config_relay['period'])
    config_relay['id_task'] = id_poll


if __name__ == '__main__':
    if not ubus.connect("/var/run/ubus.sock"):
        sys.stderr.write('Failed connect to ubus\n')
        sys.exit(-1)

    ubus_init()
    parseconfig()

    relays = list(curr_relays.keys())
    for relay in relays:
        config = curr_relays.get(relay)
        if not check_param_relay(config):
            del curr_relays[relay]
            continue

        th = Thread(target=run_poll_relay, args=(config, ))
        th.start()

    try:
        while True:
            ubus.loop(1)
    except KeyboardInterrupt:
        print("__main__ === KeyboardInterrupt")
        for relay, config in curr_relays.items():
            snmp_pr.stop_snmp_poll(config['id_task'])

    ubus.disconnect()
