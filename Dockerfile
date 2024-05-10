FROM python:3.12-bookworm

WORKDIR /app
COPY . /app

RUN pip install .

WORKDIR /

RUN rm -rf /app