#!/usr/bin/env python3
from subprocess import Popen
from struct import pack, unpack
import socket
import time

ARGS = ['python', '-m', 'pysocksd', '-c']
LISTEN = ('127.0.0.1', 12345)


def connect_with_auth():
    print('Connect with auth...')
    conn = socket.create_connection(LISTEN)
    conn.sendall(pack('!BBB', 5, 1, 0x02))
    data = conn.recv(2)
    assert data == b'\x05\x02'
    conn.sendall(pack('!B5p8p', 1, b'test', b'test123'))
    data = conn.recv(2)
    assert data == b'\x01\x00'
    print('Connected')
    return conn


def test_tcp():
    conn = connect_with_auth()

    # Send request
    req = pack('!BBBB6pH', 5, 1, 0, 3, b'ip.cn', 80)
    conn.sendall(req)

    # Recv request
    f = conn.makefile('rwb')
    resp = f.read(10)
    ver, rep, rsv, atyp, addr, port = unpack('!BBBB4sH', resp)
    assert ver == 5
    assert rep == 0
    assert rsv == 0

    # Send HTTP reqeust
    f.write(b'HEAD / HTTP/1.1\r\nHost: ip.cn\r\nUser-Agent: curl/7\r\n\r\n')
    f.flush()
    resp = f.readline()
    assert resp == b'HTTP/1.1 200 OK\r\n'

    f.close()
    conn.close()


def test_udp():
    conn = connect_with_auth()

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

    udp.close()
    conn.close()


def main():
    process = Popen(ARGS + ['tests/test-auth-file.ini'])
    time.sleep(1)
    try:
        test_tcp()
        test_udp()
    finally:
        process.terminate()


if __name__ == '__main__':
    main()
