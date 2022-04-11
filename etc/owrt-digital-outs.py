#!/usr/bin/env python3

import sys
import signal
from owrt_snmp_protocol import snmp_protocol
from threading import Thread, Lock
import time
from journal import journal

try:
    import ubus
except ImportError:
    logger.error('Failed import ubus.')
    sys.exit(-1)

fl_run_main = True
curr_relays = {}
snmp_pr = snmp_protocol()
uci_config_digital = "owrt-digital-outs"
lock_curr_relays = Lock()

def stop_run(signum, frame):
    global fl_run_main
    journal.WriteLog("OWRT_Digital_outs", "Normal", "notice", "Received termination signal!")
    fl_run_main = False

signal.signal(signal.SIGTERM, stop_run)

def ubus_init():
    def get_state_callback(event, data):
        ret_val = {}
        sect = data['id_relay']
        lock_curr_relays.acquire()
        try:
            relay_dict = curr_relays[sect]
        except KeyError:
            # poll relay with id_relay not found
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "get_state_callback() id_relay " + sect + " not found")
            ret_val["state"] = '-1'
            ret_val["status"] = '-2'
        else:
            ret_val["state"] = relay_dict['state']
            ret_val["status"] = relay_dict['status']
        finally:
            lock_curr_relays.release()
            event.reply(ret_val)

    def set_val_snmp(config_relay, value):
        id_set = snmp_pr.set_snmp_value(config_relay['address'], config_relay['community'], config_relay['oid'],
                                        config_relay['port'], config_relay['timeout'], value)
        res_set = "-1"
        while res_set == "-1":
            res_set = snmp_pr.res_set_snmp_value(id_set)

        return res_set

    def on_relay_callback(event, data):
        ret_val = {}
        sect = data['id_relay']
        journal.WriteLog("OWRT_Digital_outs", "Normal", "notice", "ubus call on_relay " + sect)
        lock_curr_relays.acquire()
        try:
            relay_dict = curr_relays[sect]
        except KeyError:
            # poll relay with id_relay not found
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "on_relay_callback() id_relay " + sect + " not found")
            ret_val["result"] = '-2'
            lock_curr_relays.release()
        else:
            tmp_cnfg_relay = relay_dict.copy()
            lock_curr_relays.release()

            ret_val["result"] = set_val_snmp(tmp_cnfg_relay, '1')

        finally:
            event.reply(ret_val)

    def off_relay_callback(event, data):
        ret_val = {}
        sect = data['id_relay']
        journal.WriteLog("OWRT_Digital_outs", "Normal", "notice", "ubus call off_relay " + sect)
        lock_curr_relays.acquire()
        try:
            relay_dict = curr_relays[sect]
        except KeyError:
            # poll relay with id_relay not found
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "off_relay_callback() id_relay " + sect + " not found")
            ret_val["result"] = '-2'
            lock_curr_relays.release()
        else:
            tmp_cnfg_relay = relay_dict.copy()
            lock_curr_relays.release()

            ret_val["result"] = set_val_snmp(tmp_cnfg_relay, '0')

        finally:
            event.reply(ret_val)

    def switch_relay_callback(event, data):
        ret_val = {}
        sect = data['id_relay']
        journal.WriteLog("OWRT_Digital_outs", "Normal", "notice", "ubus call switch_relay " + sect)
        lock_curr_relays.acquire()
        try:
            relay_dict = curr_relays[sect]
        except KeyError:
            # poll relay with id_relay not found
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "switch_relay_callback() id_relay " + sect + " not found")
            ret_val["result"] = '-2'
            lock_curr_relays.release()
            event.reply(ret_val)

        tmp_cnfg_relay = relay_dict.copy()
        lock_curr_relays.release()

        try:
            cur_state = tmp_cnfg_relay['state']
        except KeyError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "switch_relay_callback() id_relay " + sect + " no value state")
            ret_val["result"] = '-1'
            event.reply(ret_val)

        if cur_state == '0':
            val = '1'
        elif cur_state == '1':
            val = '0'
        else:
            ret_val["result"] = '-1'
            event.reply(ret_val)

        res_set = set_val_snmp(tmp_cnfg_relay, val)
        ret_val["result"] = res_set
        event.reply(ret_val)

    def impuls_on_relay_callback(event, data):
        ret_val = {}
        sect = data['id_relay']
        pause = data['time']
        journal.WriteLog("OWRT_Digital_outs", "Normal", "notice",
                         "ubus call impuls_on_relay " + sect + " on " + pause + " sec")
        lock_curr_relays.acquire()
        try:
            relay_dict = curr_relays[sect]
        except KeyError:
            # poll relay with id_relay not found
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "impuls_on_relay_callback() id_relay " + sect + " not found")
            ret_val["result"] = '-2'
            lock_curr_relays.release()
        else:
            tmp_cnfg_relay = relay_dict.copy()
            lock_curr_relays.release()

            res = set_val_snmp(tmp_cnfg_relay, '1')
            if res == '0':
                time.sleep(float(pause))
                ret_val["result"] = set_val_snmp(tmp_cnfg_relay, '0')
            else:
                ret_val["result"] = res

        finally:
            event.reply(ret_val)

    def impuls_off_relay_callback(event, data):
        ret_val = {}
        sect = data['id_relay']
        pause = data['time']
        journal.WriteLog("OWRT_Digital_outs", "Normal", "notice",
                         "ubus call impuls_off_relay " + sect + " on " + pause + " sec")
        lock_curr_relays.acquire()
        try:
            relay_dict = curr_relays[sect]
        except KeyError:
            # poll relay with id_relay not found
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "impuls_off_relay_callback() id_relay " + sect + " not found")
            ret_val["result"] = '-2'
            lock_curr_relays.release()
        else:
            tmp_cnfg_relay = relay_dict.copy()
            lock_curr_relays.release()

            res = set_val_snmp(tmp_cnfg_relay, '0')
            if res == '0':
                time.sleep(float(pause))
                ret_val["result"] = set_val_snmp(tmp_cnfg_relay, '1')
            else:
                ret_val["result"] = res

        finally:
            event.reply(ret_val)

    def get_memo_callback(event, data):
        ret_val = {}
        sect = data['id_relay']
        lock_curr_relays.acquire()
        try:
            relay_dict = curr_relays[sect]
        except KeyError:
            # poll relay with id_relay not found
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "get_memo_callback() id_relay " + sect + " not found")
            ret_val["memo"] = ''
            lock_curr_relays.release()
            event.reply(ret_val)
            return

        try:
            ret_val["memo"] = relay_dict['memo']
        except KeyError:
            # memo for poll relay not found
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "get_memo_callback() id_relay " + sect + " memo not found")
            ret_val["memo"] = ''
        finally:
            lock_curr_relays.release()
            event.reply(ret_val)

    def get_free_id_callback(event, data):
        list_id = []
        ret_val = {}

        try:
            confvalues = ubus.call("uci", "get", {"config": uci_config_digital})
        except RuntimeError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "get_free_id_callback() error get " + uci_config_digital)
            ret_val["free_id"] = ''
            event.reply(ret_val)
            return

        for confdict in list(confvalues[0]['values'].values()):
            if confdict['.type'] == "info":
                try:
                    id_r = int(confdict['.name'])
                    if id_r == 0:
                        continue
                except:
                    continue
                list_id.append(id_r)

        list_id.sort()
        try:
            list_id.index(1)
        except ValueError:
            ret_val["free_id"] = '1'
            event.reply(ret_val)
            return

        next_id = 1
        for curr_id in list_id:
            if curr_id == next_id:
                next_id += 1
                continue
            else:
                break

        ret_val["free_id"] = str(next_id)
        event.reply(ret_val)

    ubus.add(
        'owrt-digital-outs', {
            'get_state': {
                'method': get_state_callback,
                'signature': {
                    'id_relay': ubus.BLOBMSG_TYPE_STRING,
                    'ubus_rpc_session': ubus.BLOBMSG_TYPE_STRING
                }
            },
            'on_relay': {
                'method': on_relay_callback,
                'signature': {
                    'id_relay': ubus.BLOBMSG_TYPE_STRING,
                    'ubus_rpc_session': ubus.BLOBMSG_TYPE_STRING
                }
            },
            'off_relay': {
                'method': off_relay_callback,
                'signature': {
                    'id_relay': ubus.BLOBMSG_TYPE_STRING,
                    'ubus_rpc_session': ubus.BLOBMSG_TYPE_STRING
                }
            },
            'switch_relay': {
                'method': switch_relay_callback,
                'signature': {
                    'id_relay': ubus.BLOBMSG_TYPE_STRING,
                    'ubus_rpc_session': ubus.BLOBMSG_TYPE_STRING
                }
            },
            'impuls_on_relay': {
                'method': impuls_on_relay_callback,
                'signature': {
                    'id_relay': ubus.BLOBMSG_TYPE_STRING,
                    'time': ubus.BLOBMSG_TYPE_STRING,
                    'ubus_rpc_session': ubus.BLOBMSG_TYPE_STRING
                }
            },
            'impuls_off_relay': {
                'method': impuls_off_relay_callback,
                'signature': {
                    'id_relay': ubus.BLOBMSG_TYPE_STRING,
                    'time': ubus.BLOBMSG_TYPE_STRING,
                    'ubus_rpc_session': ubus.BLOBMSG_TYPE_STRING
                }
            },
            'get_memo': {
                'method': get_memo_callback,
                'signature': {
                    'id_relay': ubus.BLOBMSG_TYPE_STRING,
                    'ubus_rpc_session': ubus.BLOBMSG_TYPE_STRING
                }
            },
            'get_free_id': {
                'method': get_free_id_callback,
                'signature': {
                    'ubus_rpc_session': ubus.BLOBMSG_TYPE_STRING
                }
            }
        }
    )


def check_param_basic(param):
    res = True

    try:
        start_state = param['start_state']
    except KeyError:
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                         "check_param_basic() id_relay: " + param['.name'] + " not found 'start_state'")
        res = False

    try:
        proto = param['proto']
    except KeyError:
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                         "check_param_basic() id_relay: " + param['.name'] + " not found 'proto'")
        res = False

    return res


def check_param_snmp(param):
    res = True

    try:
        community = param['community']
    except KeyError:
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                         "check_param_snmp() id_relay: " + param['.name'] + " not found 'community'")
        res = False

    try:
        address = param['address']
    except KeyError:
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                         "check_param_snmp() id_relay: " + param['.name'] + " not found 'address'")
        res = False

    try:
        port = param['port']
    except KeyError:
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                         "check_param_snmp() id_relay: " + param['.name'] + " not found 'port'")
        res = False

    try:
        oid = param['oid']
    except KeyError:
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                         "check_param_snmp() id_relay: " + param['.name'] + " not found 'oid'")
        res = False

    try:
        period = param['period']
    except KeyError:
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                         "check_param_snmp() id_relay: " + param['.name'] + " not found 'period'")
        res = False

    try:
        timeout = param['timeout']
    except KeyError:
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                         "check_param_snmp() id_relay: " + param['.name'] + " not found 'timeout'")
        res = False

    return res


def parseconfig():
    lock_curr_relays.acquire()
    curr_relays.clear()
    lock_curr_relays.release()
    try:
        confvalues = ubus.call("uci", "get", {"config": uci_config_digital})
    except RuntimeError:
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                         "parseconfig() error get " + uci_config_digital)
        sys.exit(-1)

    for confdict in list(confvalues[0]['values'].values()):
        if confdict['.type'] == "info":
            if not check_param_basic(confdict):
                journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                                 "parseconfig() error parameters basic " + confdict['.name'])
                continue
            if confdict['proto'] == "SNMP":
                if not check_param_snmp(confdict):
                    journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                                     "parseconfig() error parameters SNMP " + confdict['.name'])
                    continue

                confdict['status'] = '-1'
                confdict['state'] = '-1'
                lock_curr_relays.acquire()
                curr_relays[confdict['.name']] = confdict
                lock_curr_relays.release()


def diff_param_relay(config, protodict):
    # since polling relay in run, start_state parameter not checked,
    # but will be taken into account when changing other parameters

    try:
        config['memo'] = protodict['memo']

        if config['proto'] == protodict['proto']:
            return False
        else:
            return True
    except KeyError:
        return True


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


def check_add_relay(conf_proto):
    for protodict in list(conf_proto[0]['values'].values()):
        if protodict['.type'] == "info":
            config = curr_relays.get(protodict['.name'])
            if config is None:
                # Add new relay
                if not check_param_basic(protodict):
                    journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                                     "check_add_relay() error parameters basic " + protodict['.name'])
                    continue

                if protodict['proto'] == "SNMP":
                    if not check_param_snmp(protodict):
                        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                                         "check_add_relay() error parameters SNMP " + protodict['.name'])
                        continue

                    lock_curr_relays.acquire()
                    protodict['status'] = '-1'
                    protodict['state'] = '-1'
                    curr_relays[protodict['.name']] = protodict
                    lock_curr_relays.release()

                    # Run polling thread on SNMP
                    thrd = Thread(target=run_poll_relay, args=(protodict['.name'], ))
                    thrd.start()


def check_edit_relay(conf_proto):
    for protodict in list(conf_proto[0]['values'].values()):
        if protodict['.type'] == "info":
            config = curr_relays.get(protodict['.name'])
            if config is not None:
                lock_curr_relays.acquire()
                if not diff_param_relay(config, protodict):
                    if protodict['proto'] == "SNMP":
                        if not diff_param_poll_snmp(config, protodict):
                            lock_curr_relays.release()
                            continue
                    else:
                        lock_curr_relays.release()
                        continue

                # Edit relay
                if config['proto'] == "SNMP":
                    snmp_pr.stop_snmp_poll(config['id_task'])
                    journal.WriteLog("OWRT_Digital_outs", "Normal", "notice",
                                     "Edit relay: stop polling relay " + config['.name'])
                    del curr_relays[config['.name']]

                if not check_param_basic(protodict):
                    lock_curr_relays.release()
                    journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                                     "check_edit_relay() error parameters basic " + protodict['.name'])
                    continue

                if protodict['proto'] == "SNMP":
                    if not check_param_snmp(protodict):
                        lock_curr_relays.release()
                        journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                                         "check_edit_relay() error parameters SNMP " + protodict['.name'])
                        continue

                    protodict['status'] = '-1'
                    protodict['state'] = '-1'
                    curr_relays[protodict['.name']] = protodict
                    lock_curr_relays.release()

                    # Run polling thread on SNMP
                    thrd = Thread(target=run_poll_relay, args=(protodict['.name'], ))
                    thrd.start()
                else:
                    lock_curr_relays.release()


def check_del_relay(conf_proto):
    lock_curr_relays.acquire()
    relays = list(curr_relays.keys())
    for relay in relays:
        relay_exists = False
        for protodict in list(conf_proto[0]['values'].values()):
            if protodict['.type'] == "info":
                try:
                    if protodict['.name'] == relay:
                        relay_exists = True
                        break
                except KeyError:
                    pass

        if relay_exists == False:
            try:
                # Deleting relay
                config = curr_relays.pop(relay)
                snmp_pr.stop_snmp_poll(config['id_task'])
                journal.WriteLog("OWRT_Digital_outs", "Normal", "notice",
                                 "Deleting relay: stop polling relay " + config['.name'])
            except KeyError:
                journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                                 "reparseconfig(): Deleting relay:  not found " + relay)
                continue
    lock_curr_relays.release()


def reparseconfig(event, data):
    global fl_run_main
    if data['config'] == uci_config_digital:
        try:
            conf_proto = ubus.call("uci", "get", {"config": uci_config_digital})
        except RuntimeError:
            journal.WriteLog("OWRT_Digital_outs", "Normal", "err",
                             "reparseconfig() error get " + uci_config_digital)
            fl_run_main = False
            return

        check_add_relay(conf_proto)
        check_edit_relay(conf_proto)
        check_del_relay(conf_proto)


def run_poll_relay(relay):
    lock_curr_relays.acquire()
    config_relay = curr_relays.get(relay)
    if config_relay is None:
        # relay delete
        lock_curr_relays.release()
        return

    if config_relay['proto'] == "SNMP":
        id_poll = snmp_pr.start_snmp_poll(config_relay['address'], config_relay['community'], config_relay['oid'],
                                          config_relay['port'], config_relay['timeout'], config_relay['period'])
        config_relay['id_task'] = id_poll
        tmp_cnfg_relay = config_relay.copy()
        lock_curr_relays.release()
        journal.WriteLog("OWRT_Digital_outs", "Normal", "notice", "start polling relay " + relay)

        if tmp_cnfg_relay['start_state'] != 'NO':
            id_set = snmp_pr.set_snmp_value(tmp_cnfg_relay['address'], tmp_cnfg_relay['community'], tmp_cnfg_relay['oid'],
                                            tmp_cnfg_relay['port'], tmp_cnfg_relay['timeout'], tmp_cnfg_relay['start_state'])
            res_set = "-1"
            while res_set == "-1":
                res_set = snmp_pr.res_set_snmp_value(id_set)
            # TODO: handling error set_snmp_value()
    else:
        lock_curr_relays.release()


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
        id_relay = config_relay['.name']
    except KeyError:
        lock_curr_relays.release()
        return

    state, status = snmp_pr.get_snmp_poll(id_poll)
    if status == "0":
        # Checking change state
        if state != old_state:
            ubus.send("signal", {"event": "statechanged", "id": id_relay, "state": state})
            journal.WriteLog("OWRT_Digital_outs", "Normal", "notice",
                             "state changed relay " + relay + " set to " + state)

    config_relay['state'] = state
    config_relay['status'] = status

    lock_curr_relays.release()


if __name__ == '__main__':
    if not ubus.connect("/var/run/ubus.sock"):
        journal.WriteLog("OWRT_Digital_outs", "Normal", "err", "Failed connect to ubus")
        sys.exit(-1)

    journal.WriteLog("OWRT_Digital_outs", "Normal", "notice", "Start module!")

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
        journal.WriteLog("OWRT_Digital_outs", "Normal", "notice", "Finish module!")
    finally:
        if not lock_curr_relays.locked():
            lock_curr_relays.acquire()
        relays = list(curr_relays.keys())
        for relay in relays:
            try:
                config = curr_relays.pop(relay)
                snmp_pr.stop_snmp_poll(config['id_task'])
                journal.WriteLog("OWRT_Digital_outs", "Normal", "notice", "stop polling relay " + relay)
            except KeyError:
                continue
        lock_curr_relays.release()

    ubus.disconnect()
