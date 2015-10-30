#!/usr/bin/env python3
import os
import sys
import logging
from asyncio import get_event_loop
from configparser import ConfigParser

from .server import Server
from .auth import AuthUserDict, AuthRadius


def _read_config():
    if len(sys.argv) != 3 or sys.argv[1] != '-c':
        print('Usage: %s -c CONFIG-FILE' % sys.argv[0], file=sys.stderr)
        sys.exit(2)
    if not os.path.isfile(sys.argv[2]):
        sys.exit('Config file not exist on %s.' % sys.argv[2])
    config = ConfigParser()
    config.read(sys.argv[2])
    return config


def main():
    if sys.version_info[:2] < (3, 4):
        sys.exit('Support Python 3.4 or above only.')
    config = _read_config()
    default = config['DEFAULT']
    log_level = default.getint('log level', logging.DEBUG)
    log_format = default.get('log format',
                             '%(asctime)s %(levelname)-s: %(message)s')
    logging.basicConfig(level=log_level, format=log_format)

    bind = (default.get('bind address', '0.0.0.0'),
            default.getint('bind port', 8080))

    timeout = default.getint('idle timeout', 300)

    auth = default.get('auth', 'no')
    if auth == 'file':
        auth_method = AuthUserDict(config['Users'])
    elif auth == 'radius':
        radius = config['Radius Auth']
        auth_method = AuthRadius(radius.get('host', '127.0.0.1'),
                                 radius.getint('port', 1812),
                                 radius.get('secret', 'test123'),
                                 radius.getfloat('timeout', 2),
                                 radius.getint('max tries', 3))
    else:
        auth_method = None

    udp = config['UDP Relay']
    disable_udp = not udp.getboolean('enable', False)
    if disable_udp:
        udp_bind = udp_ports = None
    else:
        udp_bind = udp.get('address')
        udp_ports = (udp.getint('port from'), udp.getint('port to'))
        if None in udp_ports:
            udp_ports = None

    loop = get_event_loop()
    server = Server(bind, udp_ports,
                    auth_method=auth_method,
                    disable_udp=disable_udp,
                    udp_bind=udp_bind,
                    timeout=timeout)
    loop.run_until_complete(server.run())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info("Exit by user.")

if __name__ == '__main__':
    main()

