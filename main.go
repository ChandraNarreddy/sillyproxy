package main

import (
	"flag"
	"log"

	"./utility"
)

func main() {

	// sillyProxy -keypass xyz -keystore abc -minTLSVer 1 -bind :8443 -routes file
	keyStoreFile = flag.String("keystore", "", "keystore file with the absolute path")

	hostname := flag.String("hostname", "",
		"Hostname under which the pem content needs to be written to."+
			"Leave blank if you wish this certificate to be bound as default")

	keyStorePass := flag.String("keypass", "", "Password to the keystore")

	minTLSVer := flag.Uint("minTLSver", 1,
		"global configuration for minimum TLS version - \n\t"+
			"1 for 1.1, \n\t 2 for 1.2, \n\t3 for 1.3. \n\t Default is 1.1")

	bindAddr := flag.String("bind", ":443", "address and port to bind")

	pemCertFile := flag.String("pemCert", "",
		"location of certificate file(PEM) to read")

	pemKeyFile := flag.String("pemKey", "",
		"location of privateKey file(PEM) to read")

	routeMapFilePath := flag.String("routes", "", "path to routes map file")

	// let us parse the flags
	flag.Parse()

	//Usage:: sillyProxy -options KeyStore for keystore related operations
	//				sillyProxy -options to run the proxy
	if len(flag.Args()) > 0 {
		switch flag.Args()[0] {
		case "KeyStore", "keystore":
			err := utility.GenerateKeyStore(keyStoreFile, hostname, pemCertFile, pemKeyFile,
				keyStorePass)
			if err != nil {
				log.Printf(err.Error())
			}
			return
		}
	}
	/***profiling code
	f, err := os.Create(fmt.Sprintf("SP_CPU.prof_%#v", time.Now().Unix()))
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()
	*****profiling****/
	sillyProxy, sillyProxyErr := SillyProxy(keyStoreFile, keyStorePass, minTLSVer, bindAddr, routeMapFilePath)
	if sillyProxyErr != nil {
		log.Fatalf("SillyProxy failed with error: %#v", sillyProxyErr.Error())
	}
	log.Fatal(sillyProxy.ListenAndServeTLS("", "").Error())
}
