class PortPool:
    def __init__(self, start, size):
        assert start > 0
        assert size > 0
        assert start + size < 65536
        self._size = size
        self._pool = set()

        def _cycle():
            while True:
                for i in range(start, start + size):
                    yield i
        self._cycle = _cycle()


    def next(self):
        if len(self._pool) >= self._size:
            raise PoolUnderflowError()

        port = next(self._cycle)
        while port in self._pool:
            port = next(self._cycle)

        self._pool.add(port)
        return port


    def put(self, port):
        self._pool.discard(port)


    def take(self, port):
        self._pool.add(port)


class PoolUnderflowError(LookupError):
    pass
