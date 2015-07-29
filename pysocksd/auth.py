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
        self._radius = RadiusClient(addr, port, secret)
        self._radius.timeout = timeout
        self._radius.max_tries = max_tries


    @coroutine
    def __call__(self, user, pwd, **kwargs):
        caller = '%s:%s' % kwargs['host']
        return (yield from self._radius.auth(user, pwd, caller))

