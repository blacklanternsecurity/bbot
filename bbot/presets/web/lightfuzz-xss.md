description: Discovery web parameters and lightly fuzz them for xss vulnerabilities
modules:
  - httpx
  - lightfuzz
  - paramminer_getparams

config:
  url_querystring_remove: False
  url_querystring_collapse: False
  web_spider_distance: 4
  web_spider_depth: 5
  modules:
    lightfuzz:
      submodules_enabled: [xss]