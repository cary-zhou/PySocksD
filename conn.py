import logging
from asyncio import coroutine, open_connection, get_event_loop
from struct import pack, unpack
from ipaddress import IPv4Address, IPv6Address, ip_address


VERSION = 0x05
AUTH_METHOD_NONE = 0x00
AUTH_METHOD_USERNAME = 0x02
AUTH_METHOD_NO_ACCEPTABLE = 0xff
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03
ATYPE_IPV4 = 0x01
ATYPE_NAME = 0x03
ATYPE_IPV6 = 0x04
REP_SUCCESSED = 0x00
REP_SERVER_FAIL = 0X01
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYPE_NOT_SUPPORTED = 0x08

class Connection:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self._loop = get_event_loop()

    @coroutine
    def run(self):
        yield from self._auth()


    def _reply_fail(self, rep, reason=''):
        if reason:
            logging.warning('Reject request. %s', reason)
        self.writer.write(pack('!BB', VERSION, rep))
        # RSV(1) ATYPE(1) ADDR(4) PORT(2)
        self.writer.write(b'\x00\x01' + b'\x00' * 6)
        self.write_eof()


    @coroutine
    def _auth(self):
        read = self.reader.readexactly
        ver, nmethods = unpack('!BB', (yield from read(2)))
        if ver != VERSION:
            logging.warning('Protocol version not match.')
            self.close()
            return
        methods = yield from read(nmethods)
        if AUTH_METHOD_NONE not in methods:
            logging.warning('No acceptable auth methods.')
            self.writer.write(pack('!BB', VERSION, AUTH_METHOD_NO_ACCEPTABLE))
            self.writer.write_eof()
            return
        self.writer.write(pack('!BB', VERSION, AUTH_METHOD_NONE))

        ver, cmd, rsv, atype = unpack('!BBBB', (yield from read(4)))
        if atype == ATYPE_IPV4:
            addr = IPv4Address((yield from read(4)))
        elif atype == ATYPE_IPV6:
            addr = IPv6Address((yield from read(16)))
        elif atype == ATYPE_NAME:
            length = ord((yield from read(1)))
            addr = (yield from read(length)).decode()
        else:
            self._reply_fail(REP_ATYPE_NOT_SUPPORTED,
                             'Unknown address type.')
            return
        port, = unpack('!H', (yield from read(2)))
        logging.debug('Request to %s:%s', addr, port)
        if cmd == CMD_CONNECT:
            yield from self._cmd_connect(addr, port)
        elif cmd == CMD_BIND:
            yield from self._cmd_bind(addr, port)
        elif cmd == CMD_UDP_ASSOCIATE:
            yield from self._cmd_udp_associate(addr, port)
        else:
            self._reply_fail(REP_CMD_NOT_SUPPORTED,
                             'Unknown CMD.')

    @coroutine
    def _cmd_connect(self, addr, port):
        logging.info('Connecting %s:%s...', addr, port)
        reader, writer = yield from open_connection(str(addr), port)
        bind_addr, bind_port = writer.get_extra_info('sockname')[:2]
        bind_addr = ip_address(bind_addr)
        self.writer.write(pack('!BB', VERSION, REP_SUCCESSED))
        if isinstance(bind_addr, IPv4Address):
            self.writer.write(pack('!B4sH',
                                   ATYPE_IPV4, bind_addr.packed, bind_port))
        else:
            self.writer.write(pack('!B16sH',
                                   ATYPE_IPV6, bind_addr.packed, bind_port))
        logging.debug('Start piping.')
        self._forward_to_remote = \
                self._loop.create_task(self._pipe(self.reader, writer))
        self._forward_to_local = \
                self._loop.create_task(self._pipe(reader, self.writer))


    @coroutine
    def _pipe(self, reader, writer):
        try:
            data = yield from reader.read()
            while data:
                writer.write(data)
                yield from writer.drain()
                data = yield from reader.read()
        except ConnectionError as e:
            logging.warning('Exception on read: %s.', e)
            writer.close()
        else:
            logging.debug('EOF')
            if hasattr(writer, '_sock'):
                writer.write_eof()


    @coroutine
    def _cmd_bind(self, addr, port):
        self._reply_fail(REP_CMD_NOT_SUPPORTED,
                         "BIND haven't been implemented.")


    @coroutine
    def _cmd_udp_associate(self, addr, port):
        pass


    def close(self):
        self.reader.feed_eof()
        self.writer.close()

