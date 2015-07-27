import logging
from struct import pack, unpack
from socket import inet_aton
from asyncio import coroutine, open_connection, get_event_loop
from ipaddress import IPv4Address, IPv6Address, ip_address

from relay import UDPRelay
from pool import PoolUnderflowError


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
    def __init__(self, reader, writer, udp_bind=None, udp_port_pool=None,
                 auth_method=None, disable_udp=False):
        """Handshake with SOCKS client, handle TCP connect or create UDP relay.

        udp_bind is the address which client send UDP to. Guess it if None.
        """
        self._loop = get_event_loop()
        self.reader = reader
        self.writer = writer
        self._disable_udp = disable_udp

        if not self._disable_udp:
            if udp_bind is not None:
                self._udp_bind = udp_bind
            else:
                self._udp_bind = self.writer.get_extra_info('sockname')[0]
            self._port_pool = udp_port_pool
            self._auth_method = auth_method


    @coroutine
    def run(self):
        try:
            if not (yield from self._auth()):
                return

            cmd, (addr, port) = yield from self._parse_request()
            if cmd == CMD_CONNECT:
                yield from self._cmd_connect(addr, port)
            elif cmd == CMD_BIND:
                yield from self._cmd_bind(addr, port)
            elif cmd == CMD_UDP_ASSOCIATE:
                if self._disable_udp:
                    logging.warning('UDP associate disabled. Reject request.')
                    resp = pack('!BB8s', VERSION, REP_CMD_NOT_SUPPORTED,
                                b'\x00\x01' + b'\x00' * 6)
                    self.writer.write(resp)
                    self.writer.write_eof()
                    return
                yield from self._cmd_udp_associate(addr, port)
            else:
                resp = pack('!BB8s', VERSION, REP_CMD_NOT_SUPPORTED,
                            b'\x00\x01' + b'\x00' * 6)
                raise ProtocolError('Unknown CMD.', resp=resp)

        except ProtocolError as e:
            logging.warning('Protocol error. %s', str(e))
            if e.resp is not None:
                self.writer.write(e.resp)
                self.writer.write_eof()
            else:
                self.writer.close()

        except PoolUnderflowError:
            logging.warn('No available ports. Reject UDP request.')
            self.writer.close()

        except OSError as e:
            logging.warn('OS error occurs. %s.', e)
            self.writer.close()


    @coroutine
    def _auth(self):
        read = self.reader.readexactly
        ver, nmethods = unpack('!BB', (yield from read(2)))
        if ver != VERSION:
            raise ProtocolError('Protocol version not match.')
        methods = yield from read(nmethods)

        if self._auth_method is None:
            method = AUTH_METHOD_NONE
        else:
            method = AUTH_METHOD_USERNAME
        if method not in methods:
            resp = pack('!BB', VERSION, AUTH_METHOD_NO_ACCEPTABLE)
            raise ProtocolError('No acceptable auth methdos.', resp=resp)

        self.writer.write(pack('!BB', VERSION, method))
        if method == AUTH_METHOD_USERNAME:
            return (yield from self._auth_username_password())
        else:
            return True


    @coroutine
    def _auth_username_password(self):
        read = self.reader.readexactly
        ver, ulen = unpack('!BB', (yield from read(2)))
        if ver != 0x01:
            raise ProtocolError('Auth protocol version not match.')
        user, plen = unpack('!%ssB' % ulen, (yield from read(ulen + 1)))
        pwd, = unpack('!%ss' % plen, (yield from read(plen)))
        user, pwd = user.decode(), pwd.decode()
        result = self._auth_method(user, pwd)
        if not isinstance(result, bool):
            result = yield from result
        if result:
            logging.info('User <%s> is authenticated.', user)
            self.writer.write(pack('!BB', 0x01, 0x00))
        else:
            logging.warning('User <%s> fail to authenticate, rejected.', user)
            self.writer.write(pack('!BB', 0x01, 0x01))
            self.writer.write_eof()
        return result


    @coroutine
    def _parse_request(self):
        read = self.reader.readexactly
        ver, cmd, rsv, atype = unpack('!BBBB', (yield from read(4)))
        if atype == ATYPE_IPV4:
            addr = IPv4Address((yield from read(4)))
        elif atype == ATYPE_IPV6:
            addr = IPv6Address((yield from read(16)))
        elif atype == ATYPE_NAME:
            length = ord((yield from read(1)))
            addr = (yield from read(length)).decode()
        else:
            resp = pack('!BB8s', VERSION, REP_ATYPE_NOT_SUPPORTED,
                        b'\x00\x01' + b'\x00' * 6)
            raise ProtocolError('Unknown address type.', resp=resp)
        port, = unpack('!H', (yield from read(2)))
        logging.debug('Request to %s:%s', addr, port)
        return cmd, (addr, port)


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
        resp = pack('!BB8s', VERSION, REP_CMD_NOT_SUPPORTED,
                    b'\x00\x01' + b'\x00' * 6)
        raise ProtocolError("BIND haven't been implemented.", resp=resp)


    @coroutine
    def _cmd_udp_associate(self, addr, port):
        if port and str(addr) != '0.0.0.0':
            client = (str(addr), port)
        else:
            client = None
        if self._port_pool is None:
            bind = (self._udp_bind, 0)
        else:
            bind = (self._udp_bind, self._port_pool.next())
        self._relay = UDPRelay(bind, client)
        self._relay.start()
        addr, port = self._relay.getsockname()
        rsp = pack('!BBBB4sH', VERSION, REP_SUCCESSED, 0x00, ATYPE_IPV4,
                   inet_aton(addr), port)
        self.writer.write(rsp)
        logging.info('UDP relay started.')
        try:
            data = yield from self.reader.read()
        except ConnectionError as e:
            logging.debug('Connection error: %s', e)
        self._relay.stop()
        self._relay.close()
        logging.info('UDP relay stopped.')
        if self._port_pool is not None:
            self._port_pool.put(port)


class ProtocolError(Exception):
    def __init__(self, *args, resp=None):
        super().__init__(*args)
        self.resp = resp

