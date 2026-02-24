FROM python:3.11-slim

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off
ENV PATH="/root/.bbot/tools:${PATH}"

WORKDIR /usr/src/bbot

RUN apt-get update && apt-get install -y \
    openssl \
    gcc \
    g++ \
    git \
    make \
    pkg-config \
    zlib1g-dev \
    chromium \
    unzip \
    curl \
    wget \
    vim \
    nano \
    sudo

COPY . .

RUN pip install .
RUN bbot -n deps-warmup -p /usr/src/bbot/my_bbot/all-but-intense-http.yml --allow-deadly -y -t example.com --force-deps --force --dry-run || true

# Web App Dependencies
COPY web_app/requirements.txt /tmp/webapp_requirements.txt
RUN pip install -r /tmp/webapp_requirements.txt

WORKDIR /usr/src/bbot

# Expose Web Interface Port
EXPOSE 8765

# Start Web App
CMD ["python3", "web_app/app.py"]

# ENTRYPOINT [ "bbot" ]
