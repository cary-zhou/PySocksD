#!/usr/bin/env python3
import logging
from asyncio import start_server, get_event_loop, coroutine

from conn import Connection
from pool import PortPool


class Server:

    def __init__(self, host, port, udp_ports=None, auth_method=None):
        """Listen on host:port.

        udp_ports is a tuple of (min, max) port numbers which client send
        UDP to. If not specify, use system-assigned ones.
        """
        self.host = host
        self.port = port
        if udp_ports is not None:
            self._port_pool = PortPool(udp_ports[0],
                                       udp_ports[1] - udp_ports[0] + 1)
        else:
            self._port_pool = None
        self._auth_method = auth_method


    @coroutine
    def run(self):
        self.server = yield from start_server(self._connected,
                                              self.host, self.port)


    @coroutine
    def _connected(self, reader, writer):
        """Callback invoked when income connection establish."""
        peername = writer.get_extra_info('peername')[:2]
        logging.debug("TCP established with %s:%s." % peername)

        conn = Connection(reader, writer, udp_port_pool=self._port_pool,
                          auth_method=self._auth_method)
        yield from conn.run()


def main():
    from auth import auth_test
    logging.basicConfig(level=logging.DEBUG)

    loop = get_event_loop()
    auth = auth_test
    server = Server('0.0.0.0', 10080, (60015, 60020), auth)
    loop.run_until_complete(server.run())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info('Exit')


if __name__ == '__main__':
    main()

