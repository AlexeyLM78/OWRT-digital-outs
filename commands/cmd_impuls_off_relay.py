import click
import sys

@click.command()
@click.option('-r', '--relay', default='', help='Unique identifier of the relay')
@click.option('-t', '--time', default='', help='Pulse time in seconds')
def main(relay, time):
    '''Set relay to OFF position on X seconds, after switches to ON state'''
    try:
        import ubus
    except ImportError:
        print('Failed import ubus.')
        sys.exit(-1)

    if not ubus.connect("/var/run/ubus.sock"):
        print("Failed connect to ubus")
        sys.exit(-1)

    print(ubus.call("owrt-digital-outs", "impuls_off_relay", {"id_relay":relay,"time":time,"ubus_rpc_session":"String"}))

if __name__ == "__main__":
    main()
