import click
import sys

@click.command()
def main():
    '''Get free id for config struct'''
    try:
        import ubus
    except ImportError:
        print('Failed import ubus.')
        sys.exit(-1)

    if not ubus.connect("/var/run/ubus.sock"):
        print("Failed connect to ubus")
        sys.exit(-1)

    print(ubus.call("owrt-digital-outs", "get_free_id", {"ubus_rpc_session":"String"}))

if __name__ == "__main__":
    main()
