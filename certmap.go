package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	keystore "github.com/pavel-v-chernykh/keystore-go/v4"
)

//certMap is a map of aliases and certificates in the form ("w.a.p:ECDSA",cert)
var certMap map[string]tls.Certificate

// keyStorePass is a pointer to the key store's password byte array
var keyStorePassBytes []byte

// keyStoreFile is a pointer to the keystore file's location string
var keyStoreFile *string

//loadCertMap loads the certificate map from the keystore object
func loadCertMap(filePtr *string, password []byte,
	certMap *map[string]tls.Certificate) error {
	f, err := os.Open(*filePtr)
	if err != nil {
		err = errors.New("loadKeyStore failed with error: " + fmt.Sprintf("%v", err))
		return err
	}
	keyStore := keystore.New(keystore.WithCaseExactAliases())
	err = keyStore.Load(f, password)
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
	aliases := keyStore.Aliases()
	for _, alias := range aliases {
		entry, getPrivateKeyEntryErr := keyStore.GetPrivateKeyEntry(alias, password)
		if getPrivateKeyEntryErr != nil {
			return fmt.Errorf("Failed to fetch a private key entry for alias %v", alias)
		}
		certChain := entry.CertificateChain
		var keyPEMBlock []byte
		var keyDERBlock *pem.Block
		cert := tls.Certificate{}
		if len(certChain) == 0 {
			log.Printf("PrivateKeyEntry for alias %s does not contain a certificate chain", alias)
		} else {
			for i := 0; i < len(certChain); i++ {
				cert.Certificate = append(cert.Certificate, certChain[i].Content)
			}
			keyPEMBlock = entry.PrivateKey
			keyDERBlock, _ = pem.Decode(keyPEMBlock)
			cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
			if err != nil {
				log.Printf("Privatekey load failed for for alias %s", alias)
			} else {

				if strings.HasPrefix(alias, "default") {
					if strings.HasSuffix(alias, ":ECDSA") {
						ECDSAdefaultExists = true
						*ECDSAdefault = cert
					} else {
						RSAdefaultExists = true
						*RSAdefault = cert
					}
				} else {
					(*certMap)[alias] = cert
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
	if exists := keyStore.IsPrivateKeyEntry(alias); exists {
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
