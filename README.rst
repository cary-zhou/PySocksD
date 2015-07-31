PySocksD
========

A (toy) proxy server who say SOCKSv5.


Features
--------

* UDP associate.
* Authentication (RFC 1929).
* RADIUS authentication.
* Asynchronous (based on asyncio).
* Pure Python, standard library only.


Usage
-----

::

    git clone https://github.com/sorz/PySocksD
    cd PySocksD
    python3 -m pysocksd -c config.ini


TODOs
-----

* RADIUS accounting
* IPv6
* TCP bind
* more...
