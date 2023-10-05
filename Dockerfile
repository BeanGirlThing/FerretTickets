FROM tiangolo/uwsgi-nginx-flask:python3.11

RUN apt-get install bash

COPY ./app /app
RUN pip install -r /app/requirements.txt