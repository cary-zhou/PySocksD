#!/usr/bin/env python3
import os
import socket
import codecs
import logging
from itertools import zip_longest
from functools import partial
from hashlib import md5
from asyncio import coroutine, get_event_loop, wait_for, shield, sleep
from asyncio import TimeoutError, Task
from struct import pack, unpack
from base64 import b64encode
from uuid import uuid4


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
    ACCT_STATUS_TYPE = 40
    ACCT_DELAY_TIME = 41
    ACCT_INPUT_OCTETS = 42
    ACCT_OUTPUT_OCTETS = 43
    ACCT_SESSION_ID = 44
    ACCT_AUTHENTIC = 45
    ACCT_SESSION_TIME = 46


def _encode(s):
    if isinstance(s, str):
        return s.encode()
    else:
        return s


def _packattr(key, value):
    if isinstance(value, str):
        value = value.encode()
    elif isinstance(value, int):
        value = pack('!I', value)
    elif isinstance(value, bytearray):
        value = bytes(value)
    elif not isinstance(value, bytes):
        raise ValueError('Unknown type of attribute.')
    return pack('!BB', key, len(value) + 2) + value


class RadiusClient:
    timeout = 2
    max_tries = 3
    _caller_id = None

    def __init__(self, secret, address, port=1812,
                 acct_addr=None, acct_port=1813):
        self.loop = get_event_loop()
        self.secret = _encode(secret)
        self.auth_server = (address, port)
        if acct_addr is None:
            acct_addr = address
        self.acct_server = (acct_addr, acct_port)

        self._id = 0
        self._received_ids = set()
        self._session_id = _encode(b64encode(uuid4().bytes)[:-2])
        self.sock = socket.socket(type=socket.SOCK_DGRAM)
        self.sock.setblocking(False)
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
        password = self._encode_password(password)
        self._caller_id = _encode(caller_id)

        attrs = _packattr(RadiusType.USER_NAME, username)
        attrs += _packattr(RadiusType.USER_PASSWORD, password)
        if self.nas_ip is not None:
            attrs += _packattr(RadiusType.NAS_IP_ADDRESS, self.nas_ip)
        if self._caller_id is not None:
            attrs += _packattr(RadiusType.CALLING_STATION_ID, self._caller_id)

        length = 4 + 16 + len(attrs)
        buffer = pack('!BBH', RadiusCode.ACCESS_REQUEST, self._id, length)
        buffer += self.nonce + attrs

        logging.debug("Sending RADIUS Access-Request packet.")
        self.sock.sendto(buffer, self.auth_server)


    @coroutine
    def _send_accounting_request(self, status, delay=0, input=0, output=0):
        attrs = _packattr(RadiusType.ACCT_STATUS_TYPE, status)
        attrs += _packattr(RadiusType.ACCT_SESSION_ID, self._session_id)
        if self._caller_id is not None:
            attrs += _packattr(RadiusType.CALLING_STATION_ID, self._caller_id)
        if self.nas_ip is not None:
            attrs += _packattr(RadiusType.NAS_IP_ADDRESS, self.nas_ip)
        if delay:
            attrs += _packattr(RadiusType.ACCT_DELAY_TIME, delay)
        if input:
            attrs += _packattr(RadiusType.ACCT_INPUT_OCTETS, input)
        if output:
            attrs += _packattr(RadiusType.ACCT_OUTPUT_OCTETS, output)

        length = 4 + 16 + len(attrs)
        buffer = pack('!BBH', RadiusCode.ACCOUNTING_REQUEST, self._id, length)

        m = md5()
        m.update(buffer)
        m.update(b'\x00' * 16)
        m.update(attrs)
        m.update(self.secret)
        auth = m.digest()

        self.nonce = auth  # Will be used in _recv_response().
        buffer += m.digest() + attrs

        logging.debug("Sending RADIUS Accounting-Request packet.")
        self.sock.sendto(buffer, self.acct_server)


    @coroutine
    def _recv_response(self):
        while True:
            data = yield from self.loop.sock_recv(self.sock, 4096)
            code, pid, length, auth = unpack('!BBH16s', data[:20])
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
    def _send_then_recv(self, send, recv):
        fut_recv = Task(recv())
        result = None
        for i in range(self.max_tries):
            try:
                yield from send()
            except ConnectionError as e:
                logging.warn("Failed to send RADIUS request: %s" % e)
                yield from sleep(TIMEOUT, loop=self.loop)
                continue

            try:
                result = yield from wait_for(shield(fut_recv), self.timeout)
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

        if result is None:
            logging.warning("Timeout. No valid RADIUS response.")
            fut_recv.cancel()
        return result


    @coroutine
    def auth(self, username, password, caller_id=None):
        self._id += 1
        self.nonce = os.urandom(16)

        send = partial(self._send_access_request, username, password, caller_id)
        code_attrs = yield from self._send_then_recv(send, self._recv_response)
        if code_attrs is None:
            return
        code, attrs = code_attrs

        if code == RadiusCode.ACCESS_ACCEPT:
            logging.debug("RADIUS Access-Accept packet received.")
            return True
        elif code == RadiusCode.ACCESS_REJECT:
            logging.debug("RADIUS Access-Reject packet received.")
            return False
        else:
            logging.warning("Unknown RADIUS packet received. Code %s." % code)


    @coroutine
    def _session(self, status, input=None, output=None):
        self._id += 1
        send = partial(self._send_accounting_request, status=status,
                       input=input, output=output)
        code_attrs = yield from self._send_then_recv(send, self._recv_response)
        code, attrs = code_attrs

        if code == RadiusCode.ACCOUNTING_RESPONSE:
            logging.debug("RADIUS Accounting-Response packet received.")
        else:
            logging.warning("Unknown RADIUS packet received. Code %s." % code)


    @coroutine
    def session_start(self):
        yield from self._session(1)

    @coroutine
    def session_stop(self, input, output):
        yield from self._session(2, input, output)


def main():
    import sys, time
    if len(sys.argv) != 5:
        print("Usage: %s <RADIUS-Host> <Secret> "
              "<Username> <Password>" % sys.argv[0])
        return
    logging.basicConfig(level=logging.DEBUG)
    loop = get_event_loop()
    client = RadiusClient(sys.argv[2], sys.argv[1])
    result = client.auth(sys.argv[3], sys.argv[4])
    print(loop.run_until_complete(result))
    result = client.session_start()
    print(loop.run_until_complete(result))
    time.sleep(3)
    result = client.session_stop(1234, 5678)
    print(loop.run_until_complete(result))




if __name__ == '__main__':
    main()

