package utility

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"time"
	"unsafe"

	keystore "github.com/pavel-v-chernykh/keystore-go"
)

// GenerateKeyStore generates the keyStore and saves it to disk. It requires
// the keypass, keystore file, hostname for the cert and the certificate and
// key details in PEM format

// GenerateKeyStore generates the keyStore and saves it to disk.
func GenerateKeyStore(keyStoreFile *string, hostname *string,
	pemCertFile *string, pemKeyFile *string, keyStorePass *string) error {

	// If parsing the following parameters off the command line
	// Usage: ./sillyProxy -keypass arg -keystore arg1 -hostname arg3 -pemCert arg4
	// -pemKey arg5 KeyStore

	//check if flags are provided or not
	if *keyStoreFile == "" {
		return fmt.Errorf("keyStore not provided. Please use -keyStore flag")
	}
	if *pemCertFile == "" {
		return fmt.Errorf("pemCert flag not set. Please use -pemCert to set it")
	}
	if *pemKeyFile == "" {
		return fmt.Errorf("pemkey flag not set. Please use -pemkey to set it")
	}
	if *keyStorePass == "" {
		fmt.Printf("keyPass is not set. Proceed with blank password?[y/anyotherkey]: ")
		reader := bufio.NewReader(os.Stdin)
		choice, _ := reader.ReadString('\n')
		if choice[0] != 89 && choice[0] != 121 {
			return fmt.Errorf("Sure! Aborting key entry")
		}
		fmt.Printf("Proceeding with blank password..")
	}
	if *hostname == "" {
		fmt.Printf("hostname not provided. Proceed with %s?[y/anyotherkey]: ", "default")
		reader := bufio.NewReader(os.Stdin)
		choice, _ := reader.ReadString('\n')
		if choice[0] != 89 && choice[0] != 121 {
			fmt.Printf("Aborting key entry. Try with hostname flag")
			return fmt.Errorf("key entry aborted")
		}
		*hostname = "default"
	}

	keyStorePassBytes := []byte(*keyStorePass)

	// zeroing out the password and its bytes
	zeroString(keyStorePass)
	defer zeroBytes(keyStorePassBytes)

	var keyStore keystore.KeyStore
	keyStore = make(keystore.KeyStore)

	//load the pem files in a *tls.Certificate Type
	cert, pemLoadError := tls.LoadX509KeyPair(*pemCertFile, *pemKeyFile)
	if pemLoadError != nil {
		return fmt.Errorf("Pem files loading failed with the error:%v", pemLoadError)
	}

	//now parse the returned certificate to figure out the kind of
	// keyentry and certificate
	x509Cert, parseError := x509.ParseCertificate(cert.Certificate[0])
	if parseError != nil {
		return fmt.Errorf(parseError.Error())
	}

	//build the appropriate alias for the certificate entry
	var alias string
	var certType string
	switch x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		alias = *hostname + ":RSA"
		certType = "RSA"
	case *ecdsa.PublicKey:
		alias = *hostname + ":ECDSA"
		certType = "ECDSA"
	default:
		log.Fatal(errors.New("unsupported public key algorithm"))
	}

	// check if the keystore location already exists
	if fileExists(*keyStoreFile) {

		//there is a bug with the below code. It will throw an error if the file
		// exists but is empty.
		loadKSErr := loadKeyStore(*keyStoreFile, keyStorePassBytes, &keyStore)
		if loadKSErr != nil {
			log.Fatal(errors.New("keyStore file loading failed with the error: " +
				fmt.Sprintf("%v", loadKSErr)))
		}

		//checking if the alias already exists. If yes, prompt the user if she wishes
		// to overwrite it
		if aliasExists(&keyStore, alias) {
			//get a confirmation from the user that she wishes to
			// overwrite the alias
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("A key-pair cert already exists under the name %s. Do "+
				"you wish to overwrite? [y/anyotherkey]?", alias)
			choice, _ := reader.ReadString('\n')
			if choice[0] != 89 && choice[0] != 121 {
				//fmt.Printf("Aborting key entry. Have a good day!\n")
				return fmt.Errorf("Aborting key entry. Have a good day!!")
			}
		}

		if !(*hostname == "default") &&
			!aliasExists(&keyStore, "default:RSA") &&
			!aliasExists(&keyStore, "default:ECDSA") {
			// Throw a warning to the user that the keystore does not yet have a "default"
			// alias cert and whether she would like to import the current cert as "default"
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("A \"default\" cert alias does not exist in the keystore. Do " +
				"you wish to import this cert with the \"default\" alias? [y/anyotherkey]?")
			choice, _ := reader.ReadString('\n')
			if choice[0] == 89 || choice[0] == 121 {
				fmt.Printf("Great, importing this cert as %#v", "default:"+certType)
				alias = "default:" + certType
			} else {
				fmt.Printf("Sure, Continuing with %#v as the alias.\n"+
					"But do remember that sillyProxy wont run without atleast"+
					"one cert type with default alias", alias)
			}
		}
	} else if !(*hostname == "default") {
		//We know that the keystore does not exist yet. But the alias provided does
		// is not "default". Warn the user that a default cert is absolutely
		//necessary for SillyProxy to fire up.
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("A \"default\" cert alias is necessary for SillyProxy to fire. " +
			"Wish to import this cert with \"default\" alias instead? [y/anyotherkey]?")
		choice, _ := reader.ReadString('\n')
		if choice[0] == 89 || choice[0] == 121 {
			fmt.Printf("Great, importing this cert as %#v", "default:"+certType)
			alias = "default:" + certType
		} else {
			fmt.Printf("Sure, Continuing with %#v as the alias.\n"+
				"But do remember that sillyProxy wont run unless "+
				"one cert type with default alias is in the keystore", alias)
		}
	}

	//populate the keystore
	populatekeyStoreErr := populateKeyStore(&keyStore, alias, *pemKeyFile, &cert)
	if populatekeyStoreErr != nil {
		return fmt.Errorf("keyStore population failed with the error:" +
			fmt.Sprintf("%v", populatekeyStoreErr))
	}
	//clearout the keystore and the cert files after usage
	defer clearOut(keyStore[alias])
	defer clearOut(&cert)

	//write the keystore to file
	keyStoreWriteErr := writeKeystore(&keyStore, *keyStoreFile, keyStorePassBytes)
	if keyStoreWriteErr != nil {
		return fmt.Errorf("KeyStore writing failed with error: " +
			fmt.Sprintf("%v", keyStoreWriteErr))
	}
	return nil
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

func loadKeyStore(fileLocation string, password []byte,
	keyStore *keystore.KeyStore) error {
	//first check for the file's existence.
	f, err := os.Open(fileLocation)
	defer f.Close()
	if err != nil {
		err = errors.New("loadKeyStore failed with error: " +
			fmt.Sprintf("%v", err))
		return err
	}
	*keyStore, err = keystore.Decode(f, password)
	if err != nil {
		err = errors.New("loadKeyStore failed with error: " +
			fmt.Sprintf("%v", err))
		return err
	}
	return nil
}

func fileExists(fileLocation string) bool {
	if _, err := os.Stat(fileLocation); os.IsNotExist(err) {
		return false
	}
	return true
}

func aliasExists(keyStore *keystore.KeyStore, alias string) bool {
	if _, exists := (*keyStore)[alias]; exists {
		return true
	}
	return false
}

func populateKeyStore(keyStore *keystore.KeyStore, alias string,
	pemKeyFile string, cert *tls.Certificate) error {

	certChain := make([]keystore.Certificate, len(cert.Certificate), len(cert.Certificate))
	for i := 0; i < len(cert.Certificate); i++ {
		certChain[i].Content = cert.Certificate[i]
		certChain[i].Type = fmt.Sprintf("%dth Certificate in %s", i, alias)
	}
	keyPEMBlock, keyReadError := ioutil.ReadFile(pemKeyFile)
	if keyReadError != nil {
		return keyReadError
	}
	(*keyStore)[alias] = &keystore.PrivateKeyEntry{
		Entry: keystore.Entry{
			CreationDate: time.Now(),
		},
		PrivKey:   keyPEMBlock,
		CertChain: certChain,
	}
	return nil
}

func writeKeystore(keyStore *keystore.KeyStore, fileLocation string,
	password []byte) error {
	o, err := os.Create(fileLocation)
	if err != nil {
		return err
	}
	defer o.Close()
	err = keystore.Encode(o, *keyStore, password)
	return err
}
