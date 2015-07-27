from asyncio import coroutine

from radius import RadiusClient


def auth_test(user, pwd):
    return user == pwd


class AuthUserDict:
    def __init__(self, user_passwords):
        self._dict = user_passwords


    def __call__(self, user, pwd):
        return self._dict.get(user) == pwd


class AuthRadius:
    def __init__(self, addr, port, secret):
        self._radius = RadiusClient(addr, port, secret)


    @coroutine
    def __call__(self, user, pwd):
        return (yield from self._radius.auth(user, pwd))

