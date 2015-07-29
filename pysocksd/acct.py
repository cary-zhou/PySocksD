import time
from asyncio import get_event_loop
from functools import partial


class Session:
    """A timer which keep the number of connections of a session (unquie 
    username/IP pair). Invoke callback in sometime (timeout seconds) after
    there is no connection.
    """
    _conn_counter = 1
    _handle = None

    def __init__(self, key, callback, timeout=300):
        self._loop = get_event_loop()
        self.key = key
        self._callback = callback
        self.timeout = timeout


    def __hash__(self):
        return hash(self.key)


    def __str__(self):
        return str(hash(self))


    def conn_open(self):
        if self._handle is not None:
            self._handle.cancel()
        self._conn_counter += 1


    def conn_close(self):
        self._conn_counter -= 1
        if self._conn_counter <= 0:
            if self._handle is not None:
                self._handle.cancel()
            self._loop.call_later(self.timeout, partial(self._callback, self))

