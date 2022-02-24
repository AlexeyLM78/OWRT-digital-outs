import click
import sys

@click.command()
@click.option('-r', '--relay', default='', help='Unique identifier of the relay')
def main(relay):
    '''Set reverse state for relay'''
    try:
        import ubus
    except ImportError:
        print('Failed import ubus.')
        sys.exit(-1)

    if not ubus.connect("/var/run/ubus.sock"):
        print("Failed connect to ubus")
        sys.exit(-1)

    print(ubus.call("owrt-digital-outs", "switch_relay", {"id_relay":relay, "ubus_rpc_session":"String"}))

if __name__ == "__main__":
    main()
