# What is it?

BBOT is a system of modules that interchange data **recursively**. Okay, but like, **_what is it?_**

## What It **_Isn't_**

BBOT's discovery process does not have "phases", or "stages". I.e. it does not work like this:

![how_it_doesnt_work](https://github.com/blacklanternsecurity/bbot/assets/20261699/67c4e332-f181-47e7-b884-2112bda347a4)

This is a traditional OSINT process, where you start with a target and you work in stages. Each stage gets you a little more data and requires more cleaning/deduplication, until finally you reach the end. The problem with this approach is that it **misses things**. 

Imagine if on the last step of this process, you discovered a new subdomain. Awesome! But wait, shouldn't you go back and check that one the same way you did the others? Shouldn't you port-scan it and SSL-mine it and so on? Maybe you're a thorough, hard-working human, and you do all that. Maybe by doing that, you find another subdomain! _Sigh._ What about this time? Should you start over again for that one? You see the dilemma.

![traditional-workflow](https://github.com/blacklanternsecurity/bbot/assets/20261699/aa7cb6ac-6f88-464a-8069-0d534cecfd2b)

## What It **_Is_**

Instead, BBOT works recursively, treating each new individual piece of data as an opportunity to find even more. When it finds something, it feeds it back into the machine and uses it to fuel the discovery process. It continues to churn like this until there is no new data to discover.

![bbot-workflow](https://github.com/blacklanternsecurity/bbot/assets/20261699/1b56c472-c2c4-41b5-b711-4b7296ec7b20)

## Module Example

As a simple example, let's run a BBOT scan with **three modules**: `nmap`, `sslcert`, and `httpx`. Each of these modules "consume" a certain type of data:

- **`nmap`** consumes `DNS_NAME`s, port-scans them, and outputs `OPEN_TCP_PORT`s
- **`sslcert`** consumes `OPEN_TCP_PORT`s, grabs certs, and extracts `DNS_NAME`s
- **`httpx`** consumes `OPEN_TCP_PORT`s and visits any web services, extracting new `URL`s and `HTTP_RESPONSE`s.


