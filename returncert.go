package main

import (
	"crypto/tls"
	"fmt"
)

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
