# go-artisanal-integers-proxy

Go proxy for artisanal integer services.

## Install

You will need to have both `Go` and the `make` programs installed on your computer. Assuming you do just type:

```
make tools
```

All of this package's dependencies are bundled with the code in the `vendor` directory.

## Tools

### proxy-server

Proxy, pre-load and buffer requests to one or more artisanal integer services "create an integer" API endpoints. No, really.

```
> ./bin/proxy-server -h
Usage of ./bin/proxy-server:
  -brooklyn-integers
	Use Brooklyn Integers as an artisanal integer source. (default false)
  -host string
    	Host to listen on. (default "localhost")
  -httptest.serve string
    		  if non-empty, httptest.NewServer serves on this address and blocks
  -loglevel string
    	    Log level. (default "info")
  -london-integers
	Use London Integers as an artisanal integer source. (default false)
  -min int
       The minimum number of artisanal integers to keep on hand at all times. (default 5)
  -mission-integers
	Use Mission Integers as an artisanal integer source. (default false)
  -port int
    	Port to listen on. (default 8080)
  -protocol string
    	    The protocol to use for the proxy server. (default "http")
```

As in:

```
./bin/proxy-server -brooklyn-integers -min 100
[proxy-server] 02:47:44.029143 [error] failed to create new integer, because invalid character '<' looking for beginning of value
...remaining errors excluded for brevity

[proxy-server] 02:47:45.431095 [info] time to refill the pool with 100 integers (success: 70 failed: 30): 1.728106507s (pool length is now 61)
[proxy-server] 02:47:48.703314 [status] pool length: 61
[proxy-server] 02:47:53.704234 [status] pool length: 61
[proxy-server] 02:47:54.144543 [info] time to refill the pool with 39 integers (success: 39 failed: 0): 441.226293ms (pool length is now 81)
[proxy-server] 02:47:58.704465 [status] pool length: 81
[proxy-server] 02:48:03.704680 [status] pool length: 81
[proxy-server] 02:48:06.929803 [info] time to refill the pool with 19 integers (success: 19 failed: 0): 3.226286242s (pool length is now 94)
[proxy-server] 02:48:08.704911 [status] pool length: 94
[proxy-server] 02:48:13.705098 [status] pool length: 94
[proxy-server] 02:48:13.904573 [info] time to refill the pool with 6 integers (success: 6 failed: 0): 200.858368ms (pool length is now 100)
[proxy-server] 02:48:18.705313 [status] pool length: 100
[proxy-server] 02:48:23.705487 [status] pool length: 100
[proxy-server] 02:48:28.705684 [status] pool length: 100
```

And then:

```
$> curl http://localhost:8080
404733361
$> curl http://localhost:8080
404733359
```

And then:

```
[proxy-server] 02:48:33.705859 [status] pool length: 98
[proxy-server] 02:48:33.886058 [info] time to refill the pool with 2 integers (success: 2 failed: 0): 181.959167ms (pool length is now 100)
[proxy-server] 02:48:38.706063 [status] pool length: 100
[proxy-server] 02:48:43.706231 [status] pool length: 100
```

For event more reporting set the `-loglevel` flag to `debug`.

## Alternative (integer) pools

By default the `proxy-server` uses an in-memory pool to store integers. There are alternative proxy server implementations that use persistent datastores for integer pools. They are:

* https://github.com/aaronland/go-artisanal-integers-proxy-redis
* https://github.com/aaronland/go-artisanal-integers-proxy-sqlite
* https://github.com/aaronland/go-artisanal-integers-proxy-boltdb

## TO DO

* AWS Lambda support

## See also

* https://brooklynintegers.com/
* https://missionintegers.com/
* http://londonintegers.com/
* https://github.com/aaronland/go-brooklynintegers-api
* https://github.com/aaronland/go-londonintegers-api
* https://github.com/aaronland/go-missionintegers-api
* https://github.com/aaronland/go-artisanal-integers
* https://github.com/whosonfirst/go-whosonfirst-pool
