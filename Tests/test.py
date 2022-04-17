#!/usr/bin/python3
import ubus
import os
import time

# config info
config = "owrt-digital-outs"
config_path = "/etc/config/"

# ubus methods info
test_ubus_objects = [
    {
        'uobj': 'owrt-digital-outs',
        'umethods': [
            {
                'umethod': 'get_state',
                'inparams': {
                    "id_relay":"2",
                    "ubus_rpc_session":"0101"
                },
                'outparams': {
                    'state': ["__contains__", [str(x) for x in range(-1,2)]],
                    'status': ["__contains__", [str(x) for x in range(-2,3)]]
                }
            },
            {
                'umethod': 'on_relay',
                'inparams': {
                    "id_relay":"2",
                    "ubus_rpc_session":"0101"
                },
                'outparams': {
                    'result': ["__contains__", [str(x) for x in range(-2,3)]]
                }
            },
            {
                'umethod': 'off_relay',
                'inparams': {
                    "id_relay":"2",
                    "ubus_rpc_session":"0101"
                },
                'outparams': {
                    'result': ["__contains__", [str(x) for x in range(-2,3)]]
                }
            },
            {
                'umethod': 'switch_relay',
                'inparams': {
                    "id_relay":"2",
                    "ubus_rpc_session":"0101"
                },
                'outparams': {
                    'result': ["__contains__", [str(x) for x in range(-2,3)]]
                }
            },
            {
                'umethod': 'impuls_on_relay',
                'inparams': {
                    "id_relay":"2",
                    "time":"3",
                    "ubus_rpc_session":"0101"
                },
                'outparams': {
                    'result': ["__contains__", [str(x) for x in range(-2,3)]]
                }
            },
            {
                'umethod': 'impuls_off_relay',
                'inparams': {
                    "id_relay":"2",
                    "time":"3",
                    "ubus_rpc_session":"0101"
                },
                'outparams': {
                    'result': ["__contains__", [str(x) for x in range(-2,3)]]
                }
            },
            {
                'umethod': 'get_memo',
                'inparams': {
                    "id_relay":"2",
                    "ubus_rpc_session":"0101"
                },
                'outparams': {
                    'memo': ["__eq__", ""]
                }
            },
            {
                'umethod': 'get_free_id',
                'inparams': {
                    "ubus_rpc_session":"0101"
                },
                'outparams': {
                    'free_id': ["__eq__", ""]
                }
            },
        ]
    },
]

try:
    ubus.connect()
except:
    print("Can't connect to ubus")


def test_conf_existance():
    ret = False

    try:
        ret = os.path.isfile(f"{config_path}{config}")
    except:
        assert ret

    assert ret


def test_conf_valid():
    ret = False

    try:
        confvalues = ubus.call("uci", "get", {"config": config})
        for confdict in list(confvalues[0]['values'].values()):
            # check globals
            if confdict['.type'] == 'globals' and confdict['.name'] == 'globals':
                assert confdict['default_memo'] == 'Relay'
                assert confdict['default_start_state'] == 'NO'
                assert confdict['default_state'] == ['0.Выключено', '1.Включено']
                assert confdict['status'] == ['0.Норма', '1.Таймаут', '2.Ошибка']
                assert confdict['default_timeout'] == '5'
                assert confdict['default_period'] == '1'
            # check relay_prototype_snmp
            if confdict['.type'] == 'relay' and confdict['.name'] == 'relay_prototype_snmp':
                assert confdict['memo'] == 'Relay'
                assert confdict['start_state'] == 'NO'
                assert confdict['state_alias_0'] == 'Выключено'
                assert confdict['state_alias_1'] == 'Включено'
                assert confdict['proto'] == 'SNMP'
                assert confdict['community'] == '0'
                assert confdict['address'] == '0'
                assert confdict['port'] == '0'
                assert confdict['oid'] == '0'
                assert confdict['type_oid'] == '0'
                assert confdict['timeout'] == '5'
                assert confdict['period'] == '1'
    except:
        assert ret


def test_ubus_methods_existance():
    ret = False

    try:
        test_uobj_list = [x['uobj'] for x in test_ubus_objects]
        test_uobj_list.sort()
        uobj_list = []
        for l in list(ubus.objects().keys()):
            if l in test_uobj_list:
                uobj_list.append(l)
        uobj_list.sort()
        assert test_uobj_list == uobj_list
    except:
        assert ret


def test_ubus_api():
    ret = False

    try:
        test_uobjs = [x for x in test_ubus_objects]
        for uobj in test_uobjs:
            test_uobj_methods = [x for x in uobj['umethods']]
            for method in test_uobj_methods:
                print(method['umethod'])
                res = ubus.call(uobj['uobj'], method['umethod'], method['inparams'])
                assert type(method['outparams']) == type(res[0])
                if isinstance(method['outparams'], dict):
                    for key in method['outparams']:
                        assert key in res[0]
                        if key in res[0]:
                            if method['outparams'][key][0] == '__contains__':
                                assert getattr(method['outparams'][key][1], method['outparams'][key][0])(res[0][key])
                            elif method['outparams'][key][0] == '__eq__':
                                eq = getattr(method['outparams'][key][1], method['outparams'][key][0])(res[0][key])
                                assert not isinstance(eq, type(NotImplemented))
    except:
        assert ret
