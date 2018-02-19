[![Build Status](https://travis-ci.org/ChandraNarreddy/sillyproxy.svg?branch=master)](https://travis-ci.org/ChandraNarreddy/sillyproxy)

# SillyProxy

SillyProxy is an advanced SNI (Server Name Indication) based reverse proxy for terminating and proxying HTTPS connections to multiple domains.

* SNI based TLS termination
* Favors ECDSA over RSA by default. ECDSA is in orders of magnitude cheaper than RSA.
* Supports both RSA and ECDSA type certificates for each domain it serves.
* Has ability to dynamically load SNI configuration. Currently it loads Hostname+Cert config from keystore every 30 mins.
* Makes use of [httprouter](https://github.com/julienschmidt/httprouter) to proxy connections to backend.
* Allows to define Routes using a flexible JSON map.
* Supports TLS versions 1.0, 1.1 and 1.2

## Getting Started

You can build SillyProxy for your platform using Go-1.8 or above.
```
go get https://github.com/ChandraNarreddy/sillyproxy
```
Once installed, sillyproxy can be invoked by passing these parameters -

* keystore - location of the keystore file. More on how to generate one below.
* keypass - password to open the keystore file
* minTLSVer - minimum version of TLS to support. Defaults to TLSv1.0
* bind - address to bind on the host
* routes - routemap for SillyProxy to follow

```
./sillyProxy -keypass changeme -keystore myKeyStore.ks -minTLSVer 1 -bind :8443 -routes myroutes.json
```

### Generating the keystore

SillyProxy reads certificates and keys from the keystore file. You can generate a keystore using the 'keystore' argument and following parameters - 

* keystore - location of the keystore file. If this keystore does not exist, a new one is created.
* keypass - password to secure the keystore. Must match the previous password for an existing keystore
* pemCert - location of the certificate file. PEM is only supported. Certificate types supported are RSA and ECDSA
* pemKey - location of the corresponding private key file. PEM is only supported
* hostname - SNI alias against which this certificate needs to get associated

A keystore can be used to store keys and certificates for multiple hostnames. Each host can have an ECDSA and an RSA certificate entry. Attempting to load a new certificate+pvtKey pair for an existing host+certType combination overwrites the existing entry. Please note that silly supports PEM format alone.

##### Default Alias
Please note that Silly needs atleast one cert+pvtkey entry (ECDSA or RSA type) to be associated using a "default" alias. This default entry will be used to serve clients that do not support SNI extension or those with an unknown Hostname in SNI extension. If there is a primary domain that you want to serve using Silly, the primary domain's certificate is best suited as "Default" entry. You are free to load the same certificate under the "Default" alias and under an actual alias too.

```
./sillyProxy -keystore myKeyStore.ks -pemCert certificatteFile -pemKey pvtKeyFile -keypass changeme -hostname myExternalDomainName KeyStore
``` 

### Defining Routes

Silly requires routes in a JSON format. Routes are defined as JSON arrays and are composed of 'Host' to RoutePaths combinations. The 'Host' corresponds to the 'Host' header value of an incoming request. Please note that Silly cannot override an inbound request's method when it proxies a request. The Method and Path attributes act as filters to capture inbound requests.

Silly uses [httprouter](https://github.com/julienschmidt/httprouter) under the hood, it requires the path element to be defined using HTTPRouter's syntax.

The Route attribute needs an array composed of a combination of strings and numbers in the exact sequence that makes up the proxy path for inbound request. The numbers (indexed from 0) correspond to respective parameter values that Silly extracts based on the Path that you defined for the route. Silly does a plain concatenation in order as defined in the sequence and constructs the proxy path it needs to follow. Please note that Silly does a URL escape over parameters it extracts from the incoming request before composing the proxy path. String values defined in the Route attribute are not escaped.
 
```
{	
"Routes":[
	{
	 "Host":"www.MyPrimaryDomain.com",
         "MethodPathMaps": 
			[
	                 {
                          "Method": "GET",
                          "Path"  : "/wildRoute/:internalDomain/*end",
                          "Route" : [ "https://www.",0,"/.com/", 1 ]
	                 },
	                 {   
                          "Method": "GET",
	                  "Path"  : "/search/*query",
	                  "Route" : ["https://internalSearchAPI/search?q=", 0]
	                 },
                         {
	                  "Method": "POST",
	                  "Path"  : "/authenticate/",
	                  "Route" : ["https://kerberos.mydomain.com/login/"]
	                 },
	                ]
	},
	{
	"Host":"www.MySecondDomain.com",
	"MethodPathMaps":
			[
			 {
			  "Method": "POST",
			  "Path"  : "/API/:category/:item",
			  "Route" : ["http://internalRestEndpoint/",1]
			 }
			]
	}
	 ]
}
```

## Contributing
Please submit issues for suggestions. Pull requests are welcome too.

## Benchmarks

Target platform:

* GCE n1-standard-1 (1 vCPU, 3.75 GB memory) running ubuntu-1710-artful-v20180126
* Linux instance-2 4.13.0-32-generic #35-Ubuntu SMP Thu Jan 25 09:13:46 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
* GO version go1.9.1 linux/amd64

To minimize network induced variations, I used:
* A backend HTTP server implementation (using GO 1.9.1) serving a minimum payload on the target machine. 
* Go-WRK run from the target machine.
* Silly was configured with RSA and ECDSA entries for connections to the localhost.

#### SillyProxy Curve P-256 ECDSA performance

###### 40 connections 2 threads

```
./go-wrk -c=40 -t=2 -n=10000 -m="GET" -i=true https://127.0.0.1:8443/p
ath2/path3/hello
==========================BENCHMARK==========================
URL:                            https://127.0.0.1:8443/path2/path3/hello

Used Connections:               40
Used Threads:                   2
Total number of calls:          10000

===========================TIMINGS===========================
Total time passed:              15.67s
Avg time per request:           62.41ms
Requests per second:            638.18
Median time per request:        61.97ms
99th percentile time:           102.92ms
Slowest time for request:       145.00ms

=============================DATA=============================
Total response body sizes:              50000
Avg response body per request:          5.00 Byte
Transfer rate per second:               3190.90 Byte/s (0.00 MByte/s)
==========================RESPONSES==========================
20X Responses:          10000   (100.00%)
30X Responses:          0       (0.00%)
40X Responses:          0       (0.00%)
50X Responses:          0       (0.00%)
Errors:                 0       (0.00%)
```

###### 100 connections 5 threads

```
./go-wrk -c=100 -t=5 -n=10000 -m="GET" -i=true https://127.0.0.1:8443/
path2/path3/hello
==========================BENCHMARK==========================
URL:                            https://127.0.0.1:8443/path2/path3/hello

Used Connections:               100
Used Threads:                   5
Total number of calls:          10000

===========================TIMINGS===========================
Total time passed:              17.52s
Avg time per request:           173.35ms
Requests per second:            570.93
Median time per request:        171.43ms
99th percentile time:           272.22ms
Slowest time for request:       331.00ms

=============================DATA=============================
Total response body sizes:              50000
Avg response body per request:          5.00 Byte
Transfer rate per second:               2854.67 Byte/s (0.00 MByte/s)
==========================RESPONSES==========================
20X Responses:          10000   (100.00%)
30X Responses:          0       (0.00%)
40X Responses:          0       (0.00%)
50X Responses:          0       (0.00%)
Errors:                 0       (0.00%)
```

#### SillyProxy RSA-2048 performance

###### 40 connections 2 threads

```
./go-wrk -c=40 -t=2 -n=10000 -m="GET" -i=true https://127.0.0.1:8443/p
ath2/path3/hello
==========================BENCHMARK==========================
URL:                            https://127.0.0.1:8443/path2/path3/hello

Used Connections:               40
Used Threads:                   2
Total number of calls:          10000

===========================TIMINGS===========================
Total time passed:              50.51s
Avg time per request:           201.27ms
Requests per second:            197.99
Median time per request:        196.90ms
99th percentile time:           363.46ms
Slowest time for request:       489.00ms

=============================DATA=============================
Total response body sizes:              50000
Avg response body per request:          5.00 Byte
Transfer rate per second:               989.96 Byte/s (0.00 MByte/s)
==========================RESPONSES==========================
20X Responses:          10000   (100.00%)
30X Responses:          0       (0.00%)
40X Responses:          0       (0.00%)
50X Responses:          0       (0.00%)
Errors:                 0       (0.00%)
```

###### 100 connections 5 threads

```
./go-wrk -c=100 -t=5 -n=10000 -m="GET" -i=true https://127.0.0.1:8443/
path2/path3/hello
==========================BENCHMARK==========================
URL:                            https://127.0.0.1:8443/path2/path3/hello

Used Connections:               100
Used Threads:                   5
Total number of calls:          10000

===========================TIMINGS===========================
Total time passed:              51.28s
Avg time per request:           508.29ms
Requests per second:            194.99
Median time per request:        507.46ms
99th percentile time:           803.28ms
Slowest time for request:       961.00ms

=============================DATA=============================
Total response body sizes:              50000
Avg response body per request:          5.00 Byte
Transfer rate per second:               974.97 Byte/s (0.00 MByte/s)
==========================RESPONSES==========================
20X Responses:          10000   (100.00%)
30X Responses:          0       (0.00%)
40X Responses:          0       (0.00%)
50X Responses:          0       (0.00%)
Errors:                 0       (0.00%)
```

Understandably, RSA numbers pale in comparison to those of ECDSA.

### Comparing with NGINX

For the inquisitive lot, below are NGINX' numbers under same settings. I used the same certificate entries and the same backend server, just replaced SillyProxy with NGINX.

nginx version: nginx/1.12.1 (Ubuntu)
built with OpenSSL 1.0.2g  1 Mar 2016
TLS SNI support enabled

#### NGINX Curve P-256 ECDSA performance

###### 40 connections 2 threads

```
./go-wrk -c=40 -t=2 -n=10000 -m="GET" -i=true https://127.0.0.1:443/pa
th2/path3/hello
==========================BENCHMARK==========================
URL:                            https://127.0.0.1:443/path2/path3/hello

Used Connections:               40
Used Threads:                   2
Total number of calls:          10000

===========================TIMINGS===========================
Total time passed:              14.59s
Avg time per request:           58.11ms
Requests per second:            685.34
Median time per request:        57.03ms
99th percentile time:           100.47ms
Slowest time for request:       168.00ms

=============================DATA=============================
Total response body sizes:              50000
Avg response body per request:          5.00 Byte
Transfer rate per second:               3426.69 Byte/s (0.00 MByte/s)
==========================RESPONSES==========================
20X Responses:          10000   (100.00%)
30X Responses:          0       (0.00%)
40X Responses:          0       (0.00%)
50X Responses:          0       (0.00%)
Errors:                 0       (0.00%)
```

###### 100 connections 5 threads

```
./go-wrk -c=100 -t=5 -n=10000 -m="GET" -i=true https://127.0.0.1:443/p
ath2/path3/hello
==========================BENCHMARK==========================
URL:                            https://127.0.0.1:443/path2/path3/hello

Used Connections:               100
Used Threads:                   5
Total number of calls:          10000

===========================TIMINGS===========================
Total time passed:              15.73s
Avg time per request:           154.07ms
Requests per second:            635.86
Median time per request:        144.82ms
99th percentile time:           363.58ms
Slowest time for request:       538.00ms

=============================DATA=============================
Total response body sizes:              50000
Avg response body per request:          5.00 Byte
Transfer rate per second:               3179.30 Byte/s (0.00 MByte/s)
==========================RESPONSES==========================
20X Responses:          10000   (100.00%)
30X Responses:          0       (0.00%)
40X Responses:          0       (0.00%)
50X Responses:          0       (0.00%)
Errors:                 0       (0.00%)
```

#### NGINX RSA-2048 performance

###### 40 connections 2 threads

```
/go-wrk -c=40 -t=2 -n=10000 -m="GET" -i=true https://localhost:443/pa
th2/path3/hello
==========================BENCHMARK==========================
URL:                            https://localhost:443/path2/path3/hello

Used Connections:               40
Used Threads:                   2
Total number of calls:          10000

===========================TIMINGS===========================
Total time passed:              27.21s
Avg time per request:           108.25ms
Requests per second:            367.58
Median time per request:        101.13ms
99th percentile time:           156.77ms
Slowest time for request:       172.00ms

=============================DATA=============================
Total response body sizes:              50000
Avg response body per request:          5.00 Byte
Transfer rate per second:               1837.89 Byte/s (0.00 MByte/s)
==========================RESPONSES==========================
20X Responses:          10000   (100.00%)
30X Responses:          0       (0.00%)
40X Responses:          0       (0.00%)
50X Responses:          0       (0.00%)
Errors:                 0       (0.00%)
```

###### 100 connections 5 threads

```
/go-wrk -c=100 -t=5 -n=10000 -m="GET" -i=true https://localhost:443/p
ath2/path3/hello
==========================BENCHMARK==========================
URL:                            https://localhost:443/path2/path3/hello

Used Connections:               100
Used Threads:                   5
Total number of calls:          10000

===========================TIMINGS===========================
Total time passed:              26.90s
Avg time per request:           265.14ms
Requests per second:            371.77
Median time per request:        261.31ms
99th percentile time:           388.29ms
Slowest time for request:       426.00ms

=============================DATA=============================
Total response body sizes:              50000
Avg response body per request:          5.00 Byte
Transfer rate per second:               1858.86 Byte/s (0.00 MByte/s)
==========================RESPONSES==========================
20X Responses:          10000   (100.00%)
30X Responses:          0       (0.00%)
40X Responses:          0       (0.00%)
50X Responses:          0       (0.00%)
Errors:                 0       (0.00%)
```

Silly's ECDSA performance is comparable to that of NGINX' whereas Silly's RSA performance compared to NGINX' is abysmal; this is expected as GO's Crypto library is not optimized for RSA. Ideally, you should use RSA certificate only as a fallback to serve clients that do not support ECDSA Signature Algorithm. Most modern browsers support ECDSA, so Silly's lacklustre RSA number should cause minimal concern.

## Author

* **Chandrakanth Narreddy**

## License

MIT License

## Acknowledgments

* Julien Schmidt for [httprouter](https://github.com/julienschmidt/httprouter)
* Pavel Chernykh for [keystore-go](https://github.com/pavel-v-chernykh/keystore-go)
* Awesome authors of Golang's TLS library
