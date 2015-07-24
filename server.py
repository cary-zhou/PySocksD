#!/usr/bin/env python3
import logging
from asyncio import start_server, get_event_loop, coroutine

from conn import Connection


class Server:

    def __init__(self, host, port):
        self.host = host
        self.port = port


    @coroutine
    def run(self):
        self.server = yield from start_server(self._connected,
                                              self.host, self.port)


    @coroutine
    def _connected(self, reader, writer):
        """Callback invoked when income connection establish."""
        peername = writer.get_extra_info('peername')[:2]
        logging.debug("TCP established with %s:%s." % peername)

        conn = Connection(reader, writer)
        yield from conn.run()


def main():
    logging.basicConfig(level=logging.DEBUG)

    loop = get_event_loop()
    server = Server('0.0.0.0', 10080)
    loop.run_until_complete(server.run())

    loop.run_forever()


if __name__ == '__main__':
    main()

