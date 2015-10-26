FROM python:3-onbuild

ONBUILD COPY config.ini /usr/src/app/

EXPOSE 8080 3000-3010/udp
CMD [ "python", "-m", "pysocksd", "-c", "config.ini" ]
