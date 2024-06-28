description: Discovery web parameters and lightly fuzz them for vulnerabilities, with more intense discovery techniques

flags:
  - web-paramminer

modules:
  - httpx
  - lightfuzz
  - robots
  - badsecrets

config:
  url_querystring_remove: False
  url_querystring_collapse: False
  web_spider_distance: 4
  web_spider_depth: 5
  modules:
    lightfuzz:
      force_common_headers: True
      retain_querystring: True