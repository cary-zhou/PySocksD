import logging
from asyncio import coroutine
from struct import pack, unpack
from ipaddress import IPv4Address, IPv6Address


AUTH_METHOD_NONE = 0x00
AUTH_METHOD_USERNAME = 0x02
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03
ATYPE_IPV4 = 0x01
ATYPE_NAME = 0x03
ATYPE_IPV6 = 0x04

class Connection:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    @coroutine
    def run(self):
        yield from self._auth()


    @coroutine
    def _auth(self):
        read = self.reader.readexactly
        ver, nmethods = unpack('!BB', (yield from read(2)))
        if ver != 0x05:
            logging.warning('Protocol version not match.')
            self.close()
            return
        methods = yield from read(nmethods)
        if AUTH_METHOD_NONE not in methods:
            logging.warning('No acceptable auth methods.')
            self.close()
            return
        self.writer.write(pack('!BB', 0x05, AUTH_METHOD_NONE))

        ver, cmd, rsv, atype = unpack('!BBBB', (yield from read(4)))
        if atype == ATYPE_IPV4:
            addr = IPv4Address((yield from read(4)))
        elif atype == ATYPE_IPV6:
            addr = IPv6Address((yield from read(16)))
        elif atype == ATYPE_NAME:
            length = ord((yield from read(1)))
            addr = (yield from read(length)).decode()
        else:
            logging.warning('Unknown address type.')
            self.close()
            return
        port, = unpack('!H', (yield from read(2)))
        logging.debug('Request to %s:%s', addr, port)


    def close(self):
        self.reader.feed_eof()
        self.writer.close()
