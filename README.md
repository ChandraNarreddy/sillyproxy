# SillyProxy

SillyProxy is an advanced SNI (Server Name Indication) based TLS terminator for serving secure connections to multiple domains. It supports - 

* SNI based TLS termination
* Favors ECDSA over RSA by default. ECDSA is in orders of magnitude cheaper than RSA
* Supports both RSA and ECDSA type certificates for each domain it serves.
* Has ability to dynamically load SNI configuration. Currently it loads Hostname+Certificate configuration once every 30 mins.
* Makes use of [HTTPRouter](https://github.com/julienschmidt/httprouter) to route connections to proxy connections to backend.
* Allows to define Routes using a flexible JSON map.
* Supports TLS versions 1.0, 1.1 and 1.2

## Getting Started

You can build SillyProxy for your platform if you have Go-1.8 or above.
```
> go get https://github.com/ChandraNarreddy/sillyproxy
```
Once installed, sillyproxy can be invoked by passing these parameters -

* keystore - location of the keystore file. More on how to generate one later.
* keypass - password to open the keystore file
* minTLSVer - minimum version of TLS to support. Defaults to TLSv1.0
* bind - address to bind on the host
* routes - routemap for SillyProxy to follow

```
./sillyProxy -keypass changeme -keystore myKeyStore.ks -minTLSVer 1 -bind :8443 -routes myroutes.json
```

### Generating the keystore

SillyProxy allows you to generate a keystore using the 'keystore' argument and following parameters - 
* keystore - location of the keystore file. If this keystore does not exist, a new one is created.
* keypass - password to secure the keystore. Must match the previous password for an existing keystore
* pemCert - location of the certificate file. PEM is only supported. Certificate types supported are RSA and ECDSA
* pemKey - location of the corresponding private key file. PEM is only supported.
* hostname - SNI alias against which this certificate needs to get associated. 

##### Default Certificate
Please note that Silly needs atleast one cert (ECDSA or RSA) to be associated with "default" alias. The default certificate will be used to serve client connections that do not present an SNI extension or those with an unknown Hostname in SNI extension. If there was a primary domain that you served using Silly, the primary domain's certificate is best suited to be loaded under the "Default" alias. You are free to load the same set of certificates under the "Default" alias and under a different alias too.

```
./sillyProxy -keystore myKeyStore.ks -pemCert certificatteFile -pemKey pvtKeyFile -keypass changeme -hostname myExternalDomainName keystore
``` 

### Defining Routes

Silly requires routes in a JSON format. Routes are defined in JSON arrays composed of 'Host' and RoutePaths combinations. Currently, Silly cannot override an inbound request's method when it proxies it over. The Method and Path attributes act as filters to capture inbound requests.
Silly uses [HTTPRouter](https://github.com/julienschmidt/httprouter) under the hood, it requires the path element to be defined using HTTPRouter's syntax.
The Route attribute is an array allows a combination of strings and numbers to be defined in a sequence to make up the proxy path for captured request. The numbers (indexed from 0) represent the respective parameter values that Silly extracts based on the Path that is defined for the route. Silly does a plain concatenation of the sequence and constructs the proxy path to be followed.
 
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
Please submit issue for suggestion. Pull requests are welcome too.

## Versioning


## Authors

* **Chandrakanth Narreddy**

## License


## Acknowledgments

* Julien Schmidt for [HTTPRouter](https://github.com/julienschmidt/httprouter)
* Pavel Chernykh for [keystore-go](github.com/pavel-v-chernykh/keystore-go)
* Awesome folks at Golang
