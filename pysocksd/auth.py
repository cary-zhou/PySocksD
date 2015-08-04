from asyncio import coroutine

from .radius import RadiusClient


def auth_test(user, pwd, **kwargs):
    return user == pwd


class AuthUserDict:
    def __init__(self, user_passwords):
        self._dict = user_passwords


    def __call__(self, user, pwd, **kwargs):
        return self._dict.get(user) == pwd


class AuthRadius:
    session = True

    def __init__(self, addr, port, secret, timeout=2, max_tries=3):
        self._args = (secret, addr, port)
        self._timeout = timeout
        self._max_tries = max_tries


    @coroutine
    def __call__(self, user, pwd, **kwargs):
        radius = RadiusClient(*self._args)
        radius.timeout = self._timeout
        radius._max_tries = self._max_tries
        caller = '%s:%s' % kwargs['host']
        return (yield from radius.auth(user, pwd, caller))

