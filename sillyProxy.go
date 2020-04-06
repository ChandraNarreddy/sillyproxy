package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"runtime/pprof"
	"syscall"
	"time"
	"unsafe"
)

//MinTLSVer is the minimum version of TLS that Silly enforces for client
// connections. Defaults to TLSv1.0
var minVersionTLS uint16 = 0x0301

/*
const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
)
*/

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
		ReadTimeout:  50 * time.Second,
		WriteTimeout: 600 * time.Second,
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
