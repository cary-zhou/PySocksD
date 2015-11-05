#!/usr/bin/env python3
from subprocess import Popen
from struct import pack, unpack
import socket
import time

ARGS = ['python', '-m', 'pysocksd', '-c']
LISTEN = ('127.0.0.1', 12345)

def test_udp():
    time.sleep(1)
    conn = socket.create_connection(LISTEN)

    # Auth
    conn.sendall(pack('!BBB', 5, 1, 0x02))
    data = conn.recv(2)
    assert data == b'\x05\x02'
    conn.sendall(pack('!B5p8p', 1, b'test', b'test123'))
    data = conn.recv(2)
    assert data == b'\x01\x00'

    # Send request
    req = pack('!BBBB4sH', 5, 3, 0, 1, b'\x00' * 4, 0)
    conn.sendall(req)

    # Recv response
    resp = conn.recv(256)
    ver, rep, rsv, atyp, addr, port = unpack('!BBBB4sH', resp)
    addr = socket.inet_ntoa(addr)
    assert addr == '1.2.3.4'

    # Send UDP request
    udp = socket.socket(type=socket.SOCK_DGRAM)
    udp.bind(('127.0.0.1', 12345))
    head = pack('!HBB4sH', 0, 0, 1, socket.inet_aton('127.0.0.1'), 12345)
    udp.sendto(head + b'abc123', ('127.0.0.1', port))
    data, _ = udp.recvfrom(1024)
    assert data == b'abc123'


def main():
    process = Popen(ARGS + ['tests/test-auth-file.ini'])
    try:
        test_udp()
    finally:
        process.terminate()


if __name__ == '__main__':
    main()
