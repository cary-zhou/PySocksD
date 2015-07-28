#!/usr/bin/env python3
import logging
from asyncio import start_server, get_event_loop, coroutine

from .conn import Connection
from .pool import PortPool


class Server:

    def __init__(self, bind, udp_ports, **kwargs):
        """Bind is a tuple of (address, port) which the server bind to.

        udp_ports is a tuple of (min, max) port numbers which client send
        UDP to. If not specify, use system-assigned ones.

        Ohter kwargs will be passed to Connection.
        """
        self.host, self.port = bind
        self._conn_kwargs = kwargs
        if udp_ports is not None:
            self._port_pool = PortPool(udp_ports[0],
                                       udp_ports[1] - udp_ports[0] + 1)
        else:
            self._port_pool = None


    @coroutine
    def run(self):
        self.server = yield from start_server(self._connected,
                                              self.host, self.port)
        logging.info('Listening on %s:%s...', self.host, self.port)


    @coroutine
    def _connected(self, reader, writer):
        """Callback invoked when income connection establish."""
        peername = writer.get_extra_info('peername')[:2]
        logging.debug("TCP established with %s:%s." % peername)

        conn = Connection(reader, writer, udp_port_pool=self._port_pool,
                          **self._conn_kwargs)
        yield from conn.run()


