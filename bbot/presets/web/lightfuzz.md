description: Discovery web parameters and lightly fuzz them for vulnerabilities, with more intense discovery techniques

modules:
  - httpx
  - lightfuzz
  - badsecrets

config:
  url_querystring_remove: False
  web_spider_distance: 4
  web_spider_depth: 5
  modules:
    lightfuzz:
      submodules_enabled: [cmdi,crypto,sqli,ssti,xss]
