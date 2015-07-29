#!/usr/bin/env python3
import logging
from asyncio import start_server, get_event_loop, coroutine
from functools import partial

from .conn import Connection
from .pool import PortPool
from .acct import Session


class Server:

    def __init__(self, bind, udp_ports, auth_method, **kwargs):
        """Bind is a tuple of (address, port) which the server bind to.

        udp_ports is a tuple of (min, max) port numbers which client send
        UDP to. If not specify, use system-assigned ones.

        Ohter kwargs will be passed to Connection.
        """
        self.host, self.port = bind
        self._conn_kwargs = kwargs
        if udp_ports is not None:
            self._port_pool = PortPool(udp_ports[0],
                                       udp_ports[1] - udp_ports[0] + 1)
        else:
            self._port_pool = None

        if hasattr(auth_method, 'session') and auth_method.session:
            self._auth_method = partial(self._auth_session, auth_method)
            self._sessions = {}
        else:
            self._auth_method = auth_method


    @coroutine
    def run(self):
        self.server = yield from start_server(self._connected,
                                              self.host, self.port)
        logging.info('Listening on %s:%s...', self.host, self.port)


    @coroutine
    def _connected(self, reader, writer):
        """Callback invoked when income connection establish."""
        peername = writer.get_extra_info('peername')[:2]
        logging.debug("TCP established with %s:%s." % peername)

        conn = Connection(reader, writer, udp_port_pool=self._port_pool,
                          auth_method=self._auth_method, **self._conn_kwargs)
        yield from conn.run()


    @coroutine
    def _auth_session(self, auth_method, user, pwd, **kwargs):
        """Simulate sessions and do authentication only for new session."""
        key = (user, pwd, kwargs['host'][0])
        if key in self._sessions:
            self._sessions[key].conn_open()
            return True
        else:
            result = yield from auth_method(user, pwd, **kwargs)
            if result:
                session = Session(key, self._session_close, 300)
                kwargs['conn'].disconnect.add_done_callback(
                        lambda fn: session.conn_close())
                self._sessions[key] = session
                logging.debug('Session (%s) opened.', session)
            return result


    def _session_close(self, session):
        """Invoked after a session is closed."""
        del self._sessions[session.key]
        logging.debug('Session (%s) closed.', session)

