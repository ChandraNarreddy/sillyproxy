package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/julienschmidt/httprouter"
	keystore "github.com/pavel-v-chernykh/keystore-go"
)

//proxyHanlderMap maps the host names to their http.Handlers
type proxyHanlderMap map[string]http.Handler

//certMap is a map of aliases and certificates in the form ("w.a.p:ECDSA",cert)
var certMap map[string]tls.Certificate

// keyStorePass is a pointer to the key store's password byte array
var keyStorePassBytes []byte

// keyStoreFile is a pointer to the keystore file's location string
var keyStoreFile *string

//MinTLSVer is the minimum version of TLS that Silly enforces for client
// connections. Defaults to TLSv1.0
var minVersionTLS uint16 = 0x0301

//declaring pointers to point at default cert to optimize for seeking default
var (
	//ECDSAdefaultExists is a boolean that represents whether a ECDSA cert for the
	//default alias exists or not
	ECDSAdefaultExists = false
	//ECDSAdefault is used to hold ECDSA cert for default alias. Certs of default
	//alias are optimized to be grabbed this way instead of being part of certMap
	ECDSAdefault = &tls.Certificate{}

	//RSAdefaultExists is a boolean that represents whether a RSA cert for the
	//default alias exists or not
	RSAdefaultExists = false
	//RSAdefault is used to hold RSA cert for default alias. Certs of default
	//alias are optimized to be grabbed this way instead of being part of certMap
	RSAdefault = &tls.Certificate{}
)

//ECDSA, RSA and DSA declared as enums
const (
	ECDSA = 1
	RSA   = 2
	//DSA   = 3
)

var (
	//CiphersECDSA lists cipherSuite (as per http://www.iana.org/assignments/tls-parameters/tls-parameters.xml)
	//that allow for ECDSA signature based server authentication in TLS handshake
	CiphersECDSA = []uint16{
		0xC007, 0xC009, 0xC00A, 0xC023,
		0xC02B, 0xC02C, 0xCCA9, 0xC02D,
		0xC02E, 0xC024, 0xC025, 0xC026,
		0xC008}

	//CiphersRSA lists cipherSuite (as per http://www.iana.org/assignments/tls-parameters/tls-parameters.xml)
	//that allow for RSA signature based server authentication in TLS handshake
	CiphersRSA = []uint16{
		0xc011, 0xc012, 0xc013, 0xc014,
		0xc02f, 0xc030, 0xC027, 0x009C,
		0x009D, 0x0035, 0x003C, 0xCCA8,
		0x002F, 0x000A, 0x0005, 0x003C,
		0xC027, 0xC028}

	/*****DSA certificates are not supported in TLS library
	//CiphersDSA lists cipherSuites (from http://www.iana.org/assignments/tls-parameters/tls-parameters.xml)
	//that allow for DSA signature based server authentication in TLS handshake
	CiphersDSA = []uint16{
		0x0040, 0x0038, 0x0032, 0x000D,
		0x0013}
	*****/
)

/*
const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
)
*/

//RouteMap is a collection of HostMap called Routes
type RouteMap struct {
	Routes []HostMap
}

//HostMap lists the MethodPathMaps to each Host
type HostMap struct {
	Host           string
	MethodPathMaps []MethodPathMap
}

//MethodPathMap maps each inbound method+path combination to backend route
type MethodPathMap struct {
	Method string
	Path   string
	Route  []interface{}
}

//SillyProxy sets up certMap, proxyMap from keystore, routesInfo and fires up
func SillyProxy(keyStoreFile *string, keyStorePass *string,
	minTLSVer *uint, bindAddr *string, routeMapFilePath *string) (*http.Server, error) {

	//build routeMap
	routeMap := &RouteMap{}
	buildRouteMapError := buildRouteMap(routeMapFilePath, routeMap)
	if buildRouteMapError != nil {
		return nil, fmt.Errorf("RouteMap build failed with error: %#v", buildRouteMapError)
	}

	//build proxyHandlerMap
	pHMap := make(proxyHanlderMap)
	assignRoutes(&pHMap, routeMap)

	// verify minTLSVer value supplied
	switch *minTLSVer {
	case 2:
		minVersionTLS = 0x0302
	case 3:
		minVersionTLS = 0x0303
	default:
		//log.Println("Minimum Version of TLS is set to 1")
		minVersionTLS = 0x0301
	}

	keyStorePassBytes = []byte(*keyStorePass)
	zeroString(keyStorePass)

	//load the keystore into the

	certMap = make(map[string]tls.Certificate)
	loadError := loadCertMap(keyStoreFile, keyStorePassBytes, &certMap)
	if loadError != nil {
		return nil, fmt.Errorf("Certificate load failed: %#v", loadError)
	}

	//use a goroutine to reload the certMap every 30 mins from the keyStore
	quitReloadChannel := make(chan struct{})
	go reloadCertMap(keyStoreFile, keyStorePassBytes, &certMap,
		quitReloadChannel, uint(60*30))

	//Graceful shutdown in case of interrupts
	sigChannel := make(chan os.Signal, 1)
	go func(sigChannel <-chan os.Signal) {
		for {
			select {
			case <-sigChannel:
				stopReloadKeyStore(quitReloadChannel)
				zeroBytes(keyStorePassBytes)
				for _, v := range certMap {
					clearOut(&v)
				}
				clearOut(ECDSAdefault)
				clearOut(RSAdefault)
				log.Printf("\nReceived %#v, purged keystore secret and certificate map. Goodbye!\n", sigChannel)
				pprof.StopCPUProfile()
				os.Exit(1)
			}
		}
	}(sigChannel)
	signal.Notify(sigChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT,
		syscall.SIGIOT, syscall.SIGABRT, syscall.SIGQUIT, syscall.SIGTSTP,
		os.Interrupt)

	//Declare server properties
	server := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
		Addr:         *bindAddr,
		TLSConfig: &tls.Config{
			MinVersion:     minVersionTLS,
			GetCertificate: returnCert,
		},
		Handler: pHMap,
	}

	return server, nil
}

func buildRouteMap(routeMapFilePath *string, routeMap *RouteMap) error {
	routeMapFile, fileErr := os.Open(*routeMapFilePath)
	if fileErr != nil {
		return fmt.Errorf("\nError while opening routeMapFile -%#v: %#v", *routeMapFilePath, fileErr.Error())
	}
	routeMapDecoder := json.NewDecoder(routeMapFile)
	decodeErr := routeMapDecoder.Decode(routeMap)
	if decodeErr != nil {
		return fmt.Errorf("\nError while decoding Json: %#v", decodeErr.Error())
	}
	return nil
}

func assignRoutes(pHMap *proxyHanlderMap, routeMap *RouteMap) {

	//creating a http client here that will be reused. The client
	// will not follow redirects hence redirects from downstreams are
	// passed onto the requestors.
	// We will define tight timeouts here as we don't expect much latencies from
	// downstreams.
	client := &http.Client{
		//first create a transport that is tolerant to SSL errors
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableKeepAlives:     false,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConnsPerHost:   10,
			MaxIdleConns:          100,
		},
		// we will not follow any redirect rather pass the instructions to
		// the client
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		//we will declare a reasonable timeout value here. Alternatively we
		// can look to parameterize this to fetch its value from routeMap
		Timeout: 15 * time.Second,
	}

	//let us now register the handlers iteratively for each HostMap entry
	for _, hostMap := range (*routeMap).Routes {
		// create a new router for each hostMap
		router := httprouter.New()
		for _, methodPathMap := range hostMap.MethodPathMaps {
			localMap := methodPathMap
			//now register the handler to the router using a closure
			router.Handle(localMap.Method, localMap.Path,
				func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

					//build a route from localMap.Route and httprouter.Params here
					route, routeBuildErr := routeBuilder(ps, localMap.Route)
					if routeBuildErr != nil {
						log.Printf("routeBuilder returned error: %#v", routeBuildErr)
						//fmt.Fprintf(w, "Request failed\n")
						writeErrorResponse(w, http.StatusBadRequest)
						return
					}
					/////debug////
					//log.Printf("Route built is: %#v", route)
					/////debug////

					//create a new HTTP request
					req, reqErr := http.NewRequest(localMap.Method, route, r.Body)
					if route == "" || reqErr != nil {
						log.Printf("Error when creating request to %s for inbound request %#v",
							route, r.RequestURI)
						writeErrorResponse(w, http.StatusBadRequest)
						return
					}

					// add all the headers from incoming request to the outgoing
					for requestHeaderKey, requestHeaderValues := range r.Header {
						requestHeaderValue := requestHeaderValues[0]
						for i := 1; i < len(requestHeaderValues); i++ {
							requestHeaderValue = requestHeaderValue + "," + requestHeaderValues[i]
						}
						req.Header.Add(requestHeaderKey, requestHeaderValue)
					}
					req.Header.Set("X-Forwarded-By", "SillyProxy")

					resp, respErr := client.Do(req)
					if respErr != nil {
						log.Printf("Error in obtaining response from %s for inbound request %#v",
							route, r.RequestURI)
						//fmt.Fprintf(w, "Request failed\n")
						writeErrorResponse(w, http.StatusBadRequest)
						return
					}
					if writeResponse(w, resp) != nil {
						writeErrorResponse(w, http.StatusInternalServerError)
					}
				})
			//router.Handle ended
		}
		(*pHMap)[hostMap.Host] = router
	}

}

func writeErrorResponse(w http.ResponseWriter, status int) error {
	w.WriteHeader(status)
	_, responseWriteErr := w.Write([]byte("Request Failed"))
	if responseWriteErr != nil {
		return fmt.Errorf("Response could not be written for inbound request")
	}
	return nil
}

func writeResponse(w http.ResponseWriter, resp *http.Response) error {
	for responseHeaderkey, responseHeaderValues := range resp.Header {
		responseHeaderValue := responseHeaderValues[0]
		for i := 1; i < len(responseHeaderValues); i++ {
			responseHeaderValue = responseHeaderValue + "," + responseHeaderValues[i]
		}
		w.Header().Add(responseHeaderkey, responseHeaderValue)
	}
	w.WriteHeader(resp.StatusCode)
	var respBodyBytes []byte
	if resp.Body != nil {
		respBodyBytes, _ = ioutil.ReadAll(resp.Body)
	}
	resp.Body.Close()
	_, responseWriteErr := w.Write(respBodyBytes)
	if responseWriteErr != nil {
		return fmt.Errorf("Response could not be written for inbound request")
	}
	return nil
}

//loadCertMap loads the certificate map from the keystore object
func loadCertMap(filePtr *string, password []byte,
	certMap *map[string]tls.Certificate) error {
	f, err := os.Open(*filePtr)
	if err != nil {
		err = errors.New("loadKeyStore failed with error: " + fmt.Sprintf("%v", err))
		return err
	}
	keyStore, err := keystore.Decode(f, password)
	if err != nil {
		err = errors.New("loadKeyStore failed with error: " + fmt.Sprintf("%v", err))
		return err
	}
	defer clearOut(&keyStore)

	// Check here if atleast "default" alias RSA or ECDSA exists
	if !aliasExists(&keyStore, "default:RSA") &&
		!aliasExists(&keyStore, "default:ECDSA") &&
		!aliasExists(&keyStore, "default:DSA") {
		//throw an error back that loadCertMap failed as there is no default cert
		return fmt.Errorf("No certificate exists with \"default\" alias. " +
			"Please load a cert with default alias into the keystore")
	}

	for k, v := range keyStore {
		certChain := v.(*keystore.PrivateKeyEntry).CertChain
		var keyPEMBlock []byte
		var keyDERBlock *pem.Block
		cert := tls.Certificate{}
		if len(certChain) == 0 {
			log.Printf("PrivateKeyEntry for alias %s does not contain a certificate chain", k)
		} else {
			for i := 0; i < len(certChain); i++ {
				cert.Certificate = append(cert.Certificate, certChain[i].Content)
			}
			keyPEMBlock = v.(*keystore.PrivateKeyEntry).PrivKey
			keyDERBlock, _ = pem.Decode(keyPEMBlock)
			cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
			if err != nil {
				log.Printf("Privatekey load failed for for alias %s", k)
			} else {

				if strings.HasPrefix(k, "default") {
					if strings.HasSuffix(k, ":ECDSA") {
						ECDSAdefaultExists = true
						*ECDSAdefault = cert
					} else {
						RSAdefaultExists = true
						*RSAdefault = cert
					}
				} else {
					(*certMap)[k] = cert
				}
				//log.Printf("Certificate successfully loaded for alias: %s", k)
			}
			zeroBytes(keyPEMBlock)
			clearOut(keyDERBlock)
		}
		clearOut(&cert)
	}
	f.Close()
	return nil
}

//reloadCertMap reloads the certMap once every 6 hours
func reloadCertMap(filePtr *string, password []byte,
	certMap *map[string]tls.Certificate, quit <-chan struct{}, n uint) {
	ticker := time.NewTicker(time.Duration(n) * time.Second)
	for {
		select {
		case <-quit:
			ticker.Stop()
			return
		case <-ticker.C:
			KSerror := loadCertMap(filePtr, password, certMap)
			if KSerror != nil {
				log.Printf("Keystore reload failed with error: %v", KSerror)
			}
		}
	}
}

func aliasExists(keyStore *keystore.KeyStore, alias string) bool {
	if _, exists := (*keyStore)[alias]; exists {
		return true
	}
	return false
}

//parsePrivateKey (borrowed shamelessly from golang's x509 package) converts
// a DER encoded Private key byte slice into a PrivateKey type.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type " +
				"in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("tls: failed to parse private key")
}

// returnCert will return the certificate based on the client's hello
// information. It will check if the certMap has a certificate matching up the
// servername. If found, it will favour ECDSA over RSA
func returnCert(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {

	//extract the server name from client hello. Look for supported certificates
	// from keyXchangeAlg. Return matching certificate in order of priority: ECDSA,
	// RSA and DSA. Note that if the cert entry does identify the cert type, it is
	// assumed to be of type RSA.
	var aliasToLookFor string
	if helloInfo.ServerName == "" {
		////////debug////////
		//log.Printf("SNI extension not enabled in request from %s at time %s."+
		//	" Will use the default host to fetch certificate",
		//	helloInfo.Conn.RemoteAddr().String(), time.Now().String())
		////////debug////////
		aliasToLookFor = "default"
	} else {
		aliasToLookFor = helloInfo.ServerName
	}

	var remoteSupportsECDSA, remoteSupportsRSA int = 0, 0

	if ecdsa, exists := certMap[aliasToLookFor+":ECDSA"]; exists {
		if isSigAlgSupported(helloInfo.CipherSuites, CiphersECDSA) {
			return &ecdsa, nil
		}
		remoteSupportsECDSA = -1
	}
	if rsa, exists := certMap[aliasToLookFor+":RSA"]; exists {
		if isSigAlgSupported(helloInfo.CipherSuites, CiphersRSA) {
			return &rsa, nil
		}
		remoteSupportsRSA = -1
	}
	/*****
	if dsa, exists := certMap[aliasToLookFor+":DSA"]; exists {
		if isSigAlgSupported(helloInfo.CipherSuites, CiphersDSA) {
			return &dsa, nil
		}
		remoteSupportsDSA = -1
	}
	*****/
	if ECDSAdefaultExists && (remoteSupportsECDSA != -1) {
		if isSigAlgSupported(helloInfo.CipherSuites, CiphersECDSA) {
			return ECDSAdefault, nil
		}
	}
	if RSAdefaultExists && (remoteSupportsRSA != -1) {
		if isSigAlgSupported(helloInfo.CipherSuites, CiphersRSA) {
			return RSAdefault, nil
		}
	}
	/**********
	if DSAdefaultExists && (remoteSupportsDSA != -1) {
		if isSigAlgSupported(helloInfo.CipherSuites, CiphersDSA) {
			return DSAdefault, nil
		}
	}
	***********/
	//return nil, fmt.Errorf("No certificate to serve for %#v", helloInfo.Conn.RemoteAddr().String())
	return nil, fmt.Errorf("No certificate to serve for %#v", helloInfo)
}

func (PHMap proxyHanlderMap) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if a http.Handler is registered for the given host.
	// If yes, use it to handle the request.
	//r.Host can return host value along with the port number as Host:Port.
	//hence splitting the value to obtain just the host value [0] at all times.
	if handler := PHMap[strings.Split(r.Host, ":")[0]]; handler != nil {
		handler.ServeHTTP(w, r)
	} else {
		// Handle host names for which no handler is registered
		http.Error(w, "Request Forbidden, this request for hostname: "+
			r.Host+" is in error. Please check your input", 403) // Or Redirect?
	}
}

func routeBuilder(ps httprouter.Params, route []interface{}) (string, error) {

	var URL string
	/******debug*******
	log.Printf("Parameters returned: %#v", ps)
	log.Printf("Route returned: %#v", route)
	******************/
	for _, element := range route {
		/*****debug***
		log.Printf("Element type is %#v", reflect.TypeOf(element))
		************/
		switch T := element.(type) {
		case string:
			if strings.HasPrefix(T, "/") {
				URL = URL + strings.TrimPrefix(T, "/")
			} else {
				URL = URL + T
			}
		case float64:
			if len(ps) > int(T) {
				if strings.HasPrefix(ps[int(T)].Value, "/") {
					URL = URL + url.PathEscape(strings.TrimPrefix(ps[int(T)].Value, "/"))
				} else {
					URL = URL + url.PathEscape(ps[int(T)].Value)
				}
			} else {
				return URL,
					fmt.Errorf("routeBuilder failed! Inbound request has fewer than %d params", int(T))
			}
		/********
		case int:
			if len(ps) > T {
				if strings.HasPrefix(ps[int(T)].Value, "/") {
					URL = URL + url.PathEscape(strings.TrimPrefix(ps[int(T)].Value, "/"))
				} else {
					URL = URL + url.PathEscape(ps[int(T)].Value)
				}
			} else {
				return URL,
					fmt.Errorf("routeBuilder failed! Inbound request has fewer than %d params", T)
			}
		*******/
		default:
			return URL,
				fmt.Errorf("routeBuilder failed! Element %#v neither string nor float64", T)
		}
	}
	return URL, nil
}

func isSigAlgSupported(cipherSuites []uint16, ciphersListToCompare []uint16) bool {
	for _, cipher := range cipherSuites {
		compared := cipher
		for _, cipherToCompare := range ciphersListToCompare {
			comparee := cipherToCompare
			if compared == comparee {
				return true
			}
		}
	}
	return false
}

func stopReloadKeyStore(quit chan<- struct{}) {
	quit <- struct{}{}
}

func zeroBytes(s []byte) {
	for i := 0; i < len(s); i++ {
		s[i] = 0
	}
}

func clearOut(v interface{}) {
	p := reflect.ValueOf(v).Elem()
	p.Set(reflect.Zero(p.Type()))
}

func zeroString(s *string) {
	len := len(*s)
	sHeader := (*reflect.StringHeader)(unsafe.Pointer(s))
	var a []byte
	for i := 0; i < len; i++ {
		a = append(a, 48)
	}
	dupe := string(a)
	dupeHeader := (*reflect.StringHeader)(unsafe.Pointer(&dupe))
	sHeader.Data = dupeHeader.Data
}
