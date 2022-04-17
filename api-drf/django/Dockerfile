FROM python:3.9-buster

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ARG DEBIAN_FRONTEND=noninteractive

# Install required packages and set locale
RUN apt-get -y update          \
    && apt-get install -y      \
        locales locales-all    \
        git curl unzip jq vim  \
        bsdmainutils dumb-init \
        python-apt libldap2-dev libsasl2-dev openssl 

ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

# Install Python packages
COPY ./requirements.txt /tmp/requirements.txt
COPY ./requirements-bbot.txt /tmp/requirements-bbot.txt
RUN pip3 install --upgrade pip                                  \
    && pip3 install -r /tmp/requirements-bbot.txt               \
    && pip3 install -r /tmp/requirements.txt

WORKDIR /app
