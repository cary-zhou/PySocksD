#!/usr/bin/env python3
import os
import socket
import codecs
import logging
from itertools import zip_longest
from hashlib import md5
from asyncio import coroutine, get_event_loop, wait_for, shield, sleep
from asyncio import TimeoutError, Task
from struct import pack, unpack


MAX_RETRIES = 3
TIMEOUT = 1

def _encode(s):
    if isinstance(s, str):
        return s.encode()
    else:
        return s


class FrameType:
    ECHO = 0x01
    ECHO_REPLY = 0x02
    IP = 0x03
    AUTH = 0x04
    AUTH_ACCEPT = 0x05
    AUTH_ACCEPT_NO_CHANGE = 0x06
    AUTH_REJECT = 0x07
    DISCONNECT = 0x08


class RadiusCode:
    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5


class RadiusType:
    USER_NAME = 1
    USER_PASSWORD = 2
    NAS_IP_ADDRESS = 4
    NAS_PORT = 5
    CALLED_STATION_ID = 30
    CALLING_STATION_ID = 31
    NAS_IDENTIFIER = 32


class RadiusClient:
    def __init__(self, address, port, secret, loop=None):
        if loop is None:
            self.loop = get_event_loop()
        else:
            self.loop = loop
        self.address = address
        self.port = port
        self.secret = _encode(secret)

        self._id = 0
        self._received_ids = set()
        self.sock = socket.socket(type=socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        self.sock.connect((address, port))
        self.nas_ip = _encode(self.sock.getsockname()[0])


    def _encode_password(self, password):
        password = _encode(password)
        result = bytearray()
        salt = self.nonce
        while password:
            m = md5()
            m.update(self.secret)
            m.update(salt)
            m = m.digest()
            part = (x ^ y for x, y in zip_longest(password[:16], m, fillvalue=0))
            part = bytearray(part)
            result.extend(part)
            salt = part
            password = password[16:]
        return result


    @coroutine
    def _send_access_request(self, username, password, caller_id=None):
        username = _encode(username)
        password = self._encode_password(password)
        caller_id = _encode(caller_id)


        attrs = pack('!BB', RadiusType.USER_NAME, len(username) + 2) + username
        attrs += pack('!BB', RadiusType.USER_PASSWORD, len(password) + 2) + password
        if self.nas_ip is not None:
            attrs += pack('!BB', RadiusType.NAS_IP_ADDRESS, 
                          len(self.nas_ip) + 2) + self.nas_ip
        if caller_id is not None:
            attrs += pack('!BB', RadiusType.CALLING_STATION_ID,
                          len(caller_id) + 2) + caller_id

        length = 4 + 16 + len(attrs)
        buffer = pack('!BBH', RadiusCode.ACCESS_REQUEST, self._id, length)
        buffer += self.nonce + attrs

        logging.debug("Sending RADIUS Access-Request packet.")
        yield from self.loop.sock_sendall(self.sock, buffer)


    @coroutine
    def _recv_response(self):
        while True:
            data = yield from self.loop.sock_recv(self.sock, 4096)
            code, pid, length, auth = unpack('!BBH16s', data)
            attrs = data[20:]

            if pid in self._received_ids:
                logging.info("Repeat RADIUS packet (ID %s) received, ignored." % pid)
            else:
                self._received_ids.add(pid)
                break

        m = md5()
        m.update(data[:4])
        m.update(self.nonce)
        m.update(attrs)
        m.update(self.secret)
        if m.digest() != auth:
            raise ValueError("Wrong response authenticator.")
        return code, attrs


    @coroutine
    def auth(self, username, password, caller_id=None):
        self._id += 1
        self.nonce = os.urandom(16)

        fut_recv = Task(self._recv_response())
        code = None
        for i in range(MAX_RETRIES):
            try:
                yield from self._send_access_request(username, password, caller_id)
            except ConnectionError as e:
                logging.warn("Failed to send RADIUS request: %s" % e)
                yield from sleep(TIMEOUT, loop=self.loop)
                continue

            try:
                code, attrs = yield from wait_for(shield(fut_recv), TIMEOUT, loop=self.loop)
                break
            except TimeoutError:
                # No need to restart task, since it is protected by shield().
                logging.warning("Timeout, re-send RADIUS request.")
            except ValueError as e:
                logging.warning("Malformed RADIUS packet received: %s" % e)
                logging.info("Please check the shared secret.")
                fut_recv = Task(self._recv_response())
            except ConnectionError as e:
                logging.warn("Failed to receive RADIUS response: %s" % e)
                yield from sleep(TIMEOUT, loop=self.loop)
                fut_recv = Task(self._recv_response())


        if code is None:
            logging.warning("Timeout. No valid RADIUS response.")
            fut_recv.cancel()
        elif code == RadiusCode.ACCESS_ACCEPT:
            logging.debug("RADIUS Access-Accept packet received.")
            return True
        elif code == RadiusCode.ACCESS_REJECT:
            logging.debug("RADIUS Access-Reject packet received.")
            return False
        else:
            logging.warning("Unknown RADIUS packet received. Code %s." % code)


def main():
    import sys
    if len(sys.argv) != 5:
        print("Usage: %s <RADIUS-Host> <Secret> "
              "<Username> <Password>" % sys.argv[0])
        return
    logging.basicConfig(level=logging.DEBUG)
    loop = get_event_loop()
    client = RadiusClient(sys.argv[1], 1812, 
                          sys.argv[2])
    result = client.auth(sys.argv[3], sys.argv[4])
    print(loop.run_until_complete(result))


if __name__ == '__main__':
    main()

