FROM alpine:3.5

RUN apk update
RUN apk add bash
RUN apk add git
RUN apk add curl
RUN apk add readline
RUN apk add vim
RUN apk add python3=3.5.2-r9
RUN pip3 install --upgrade pip setuptools

COPY . /tmp/imposter
EXPOSE 80

# TODO: fix netifaces failure
RUN pip3 install /tmp/imposter


