## Install dependencies
~~~bash
pip install pymongo fastapi
~~~

## Start mongo
~~~bash
docker run --rm -p 27017:27017 -e MONGO_INITDB_ROOT_USERNAME=bbot -e MONGO_INITDB_ROOT_PASSWORD=bbotislife mongo
~~~

## Start API
~~~bash
uvicorn api:app --reload
~~~

## Test API
Check out the web UI at http://127.0.0.1:8000/docs
~~~bash
# insert events
$ cat test_scan.json | while read event; do curl -s -X PUT -H 'Content-Type: application/json' --data "$event" http://127.0.0.1:8000/events; echo; done

# get events
$ curl -s http://127.0.0.1:8000/events | jq
~~~