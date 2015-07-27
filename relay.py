import socket
import logging
from socket import socket, inet_aton, SOCK_DGRAM
from struct import pack, unpack
from asyncio import coroutine, get_event_loop


class UDPRelay:
    def __init__(self, bind=('0.0.0.0', 0), client=None):
        self._loop = get_event_loop()
        self._client = client
        self._remote = socket(type=SOCK_DGRAM)
        self._remote.setblocking(False)
        self._remote.bind(('0.0.0.0', 0))

        self._local = socket(type=SOCK_DGRAM)
        self._local.setblocking(False)
        self._local.bind(bind)
        if client is not None:
            self._loop.sock_connect(self._local, client)


    def getsockname(self):
        return self._local.getsockname()


    def start(self):
        self._loop.add_reader(self._local, self._local_income)
        self._loop.add_reader(self._remote, self._remote_income)


    def stop(self):
        self._loop.remove_reader(self._local)
        self._loop.remove_reader(self._remote)


    def close(self):
        self._local.close()
        self._remote.close()


    def _remote_income(self):
        data, (addr, port) = self._remote.recvfrom(2048)
        head = pack('!HBB4sH', 0x0000, 0x00, 0x01, inet_aton(addr), port)
        self._local.write(head + data)


    def _local_income(self):
        data, addr = self._local.recvfrom(2048)
        if client is None:
            self._local.connect(client)

        rsv, frag, atype = unpack('!HBB', data[:4])
        if frag != 0x00:
            logging.warning("Fragmentation not implementated, droppping.")
            return
        if atype != 0x01:
            logging.warning("Other than IPv4 not implemeneated, dropping.")
            return
        addr, port = unpack('!4sH', data[4:10])
        data = data[10:]
        self._remote.sendto(data, (addr, port))

