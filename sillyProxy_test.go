package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"./utility"
	"github.com/julienschmidt/httprouter"
	keystore "github.com/pavel-v-chernykh/keystore-go"
)

const (
	RouteMapJSON = `{	"Routes":[
	              {
	                "Host":"127.0.0.1",
	                "MethodPathMaps": [
	                                    {
	                                      "Method": "GET",
	                                      "Path"  : "/wild/:domain/*end",
	                                      "Route" : [ "https://www.",0,"/.com/", 1 ]
	                                    },
	                                    {
	                                      "Method": "GET",
	                                      "Path"  : "/google/*query",
	                                      "Route" : ["https://www.google.co.in/search?q=", 0]
	                                    },
	                                    {
	                                      "Method": "GET",
	                                      "Path"  : "/failureCase/*query",
	                                      "Route" : ["https://www.domain.com/search?q=", 0, 1]
	                                    },
	                                    {
	                                      "Method": "GET",
	                                      "Path"  : "/redirect/",
	                                      "Route" : ["http://outlook.live.com/mail/"]
	                                    },
																			{
	                                      "Method": "GET",
	                                      "Path"  : "/invalid/",
	                                      "Route" : []
	                                    }
	                                  ]
	                }
								]
		}`

	ECDSA_Priv = "-----BEGIN EC PRIVATE KEY-----\n" +
		"MHcCAQEEIA4ojSMnsLmQcBp4Pkvly1am8lOygWfgh4nyJUAk4+P+oAoGCCqGSM49\n" +
		"AwEHoUQDQgAEVmiv9a+veqfrG251kflfauvtAEY4e2oepF1Tvc+8Jg0meRJh9m2O\n" +
		"A482yFko+uhLx0mgetJOBF4976qA3hOEaA==\n" +
		"-----END EC PRIVATE KEY-----\n"

	ECDSA_Cert = "-----BEGIN CERTIFICATE-----\n" +
		"MIIC0zCCAnqgAwIBAgIJAOiwLGMbREzxMAkGByqGSM49BAEwfTELMAkGA1UEBhMC\n" +
		"SU4xCzAJBgNVBAgTAktBMQwwCgYDVQQHEwNCTFIxEzARBgNVBAoTCnNpbGx5cHJv\n" +
		"eHkxDDAKBgNVBAsTA2RldjEbMBkGA1UEAxMSY29tLnNpbGx5cHJveHkuZGV2MRMw\n" +
		"EQYJKoZIhvcNAQkBFgRub25lMB4XDTE4MDEyOTA0MzIwMFoXDTE5MDEyOTA0MzIw\n" +
		"MFowfTELMAkGA1UEBhMCSU4xCzAJBgNVBAgTAktBMQwwCgYDVQQHEwNCTFIxEzAR\n" +
		"BgNVBAoTCnNpbGx5cHJveHkxDDAKBgNVBAsTA2RldjEbMBkGA1UEAxMSY29tLnNp\n" +
		"bGx5cHJveHkuZGV2MRMwEQYJKoZIhvcNAQkBFgRub25lMFkwEwYHKoZIzj0CAQYI\n" +
		"KoZIzj0DAQcDQgAEVmiv9a+veqfrG251kflfauvtAEY4e2oepF1Tvc+8Jg0meRJh\n" +
		"9m2OA482yFko+uhLx0mgetJOBF4976qA3hOEaKOB4zCB4DAdBgNVHQ4EFgQUfCz0\n" +
		"g3ka+r655Z6Qz6/1d2W0mH4wgbAGA1UdIwSBqDCBpYAUfCz0g3ka+r655Z6Qz6/1\n" +
		"d2W0mH6hgYGkfzB9MQswCQYDVQQGEwJJTjELMAkGA1UECBMCS0ExDDAKBgNVBAcT\n" +
		"A0JMUjETMBEGA1UEChMKc2lsbHlwcm94eTEMMAoGA1UECxMDZGV2MRswGQYDVQQD\n" +
		"ExJjb20uc2lsbHlwcm94eS5kZXYxEzARBgkqhkiG9w0BCQEWBG5vbmWCCQDosCxj\n" +
		"G0RM8TAMBgNVHRMEBTADAQH/MAkGByqGSM49BAEDSAAwRQIhAMt6I7KuZiRjaP2w\n" +
		"IIu7xhO6Etq06wbtljDmo6BBrCPLAiAWYiZNe03MBOTJ1JuMECb3uxwlkFAS3OHH\n" +
		"lvGj1oeEUw==\n" +
		"-----END CERTIFICATE-----\n"

	//2048 bit RSA key
	RSA_Priv = "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEpAIBAAKCAQEAwF9mZEF6lXJ0dsyxwt2JmkbaQSUSeGfzFLqaH1gsHdpyW526\n" +
		"RU30oPbPcvekff18O0SnX7onAl+ny4d1ycN+53C/fcDmwBJZRhpHlz/Ww+qJhyfu\n" +
		"bdIYzKyNMbn0zE5yofJgMyfWrMJ5ZRkVanvA3mgPkNZf95vVFokpY3sIz7UHG+80\n" +
		"QLjMnkLLKvXnweR1aYiCpakDHLTrZ5KCRTFefd4w8DsihQBzHIXeUcGZCEtaYndl\n" +
		"tdsw51xAhCB3t2bXtupfbzyLIWlZyBjmp/28budatlyjY/ozhvSHzlsoCQGBVlCB\n" +
		"UpKLG0vSbWds9+oNX5Pud9raCUy3ddhMbuhhJQIDAQABAoIBAAdYHQqazVlDQ1r9\n" +
		"uZOc7ZHsPozaI3hhT5BtB1FHBnglTNRekyvuK/axNX5IIgmFUebZWiJ3cuHOUROe\n" +
		"GksXoZKoZUchxC11Bd99RVpq34IfRBza02lx6ex2cfWCCex62jmAjVemn7V8vzGy\n" +
		"4XRtQRG8m0uGQ6eqVVpE5kWb/twfFg7pjs4bXiG3dVixgAGjNfeZr5bRu9mV5wJL\n" +
		"RUEHFWPIzEzcicgBuPnU4+XS/8phtkTkfkTE1lq+fq80yVjGX49EVst1bWRkAW3g\n" +
		"z5SLMhhMeyQKNRe10Ek8E8i1KohNVFhJ9dwJWB1KrPWkrWADF379H0opHFBTJs0g\n" +
		"nvwDFgECgYEA/ESZutqRY9V/2D0sQB0Lk9q0YWsrIDNbdrMpdhhBePcyZeOz4WhW\n" +
		"YiEr1xEmBt/BU2zlV2FgVdtPv3mG6J3xz1B9e+CPVCyQAuKoZ1ApDEcuh2s6Hu19\n" +
		"PD6V4p6FOcb8RLfd8+xb3TQUtdCqFJy2SEpDLGTd7pimiblhCDp9sEECgYEAwzf2\n" +
		"JIJgRhb5emHvPIC059GTV9CPNkSkfx7/S/3WEdfkeABed0jqoYAsoHOszL9oMhNe\n" +
		"ks4gFjrS2uhGa4mgYaiIgivQh5oNVeKMyut/st3+dYRLiJBiXRWVLc23uOb4sBKm\n" +
		"T2URNyYplH8awn3xUDpKlyyGy8d4OZOZBRyr9+UCgYEAziV1BrejhdSrE1bx+TaD\n" +
		"BoD7VHySEk9Fl9tSr1mk7yf6PD71+OYdaTU4MRinXYit3/Gl/GDrq117brntn9uq\n" +
		"BcL9uCRKm/uKd4EnIr3jvU/R2wGpzio+Y+O08iqeLhfIgJNMQg9NBpePsP/ibNOf\n" +
		"NbXR7M5Eebyuou8lNuctXMECgYAZUcTG73H1JT2uNc2Fl1vfRTtLBG3OqBB9vFN4\n" +
		"U6/UGKA1QDcAWaC02Z7wIJCk7Z5iAEkf2UQoHfEDG2UmxW7bu7QYzf352G0qWnvQ\n" +
		"RcMGO+yo6UOyrqdTU11J14ignrRagdC4M2+MK5LxA5tA5nzJ3wWVndzNyU06in4q\n" +
		"P5G+UQKBgQCS64mhscM6lS79zhBrIdA59+6P3Ttm+4qKwVNW4T6ZAZVqpE4HSE3f\n" +
		"iQdybTUmuFsQO+QcAeIUuRgohUwkQ6MYjJH8vDcw+MWqFFDQfEBCu5ZoKK5Zk7Wt\n" +
		"lG9zKO3LL36LFJ/4MQz+wAbIj4QyNQmvgzZBU/FY5CnVV7ejjxkdfQ==\n" +
		"-----END RSA PRIVATE KEY-----\n"

	RSA_Cert = "-----BEGIN CERTIFICATE-----\n" +
		"MIIEXjCCA0agAwIBAgIJAKhcoTBgZm7cMA0GCSqGSIb3DQEBBQUAMHwxCzAJBgNV\n" +
		"BAYTAklOMQswCQYDVQQIEwJLQTEMMAoGA1UEBxMDQkxSMRMwEQYDVQQKEwpTaWxs\n" +
		"eVByb3h5MQwwCgYDVQQLEwNEZXYxGzAZBgNVBAMTEmNvbS5zaWxseXByb3h5LmRl\n" +
		"djESMBAGCSqGSIb3DQEJARYDbi9hMB4XDTE4MDIxMDA1NTQxM1oXDTE5MDIxMDA1\n" +
		"NTQxM1owfDELMAkGA1UEBhMCSU4xCzAJBgNVBAgTAktBMQwwCgYDVQQHEwNCTFIx\n" +
		"EzARBgNVBAoTClNpbGx5UHJveHkxDDAKBgNVBAsTA0RldjEbMBkGA1UEAxMSY29t\n" +
		"LnNpbGx5cHJveHkuZGV2MRIwEAYJKoZIhvcNAQkBFgNuL2EwggEiMA0GCSqGSIb3\n" +
		"DQEBAQUAA4IBDwAwggEKAoIBAQDAX2ZkQXqVcnR2zLHC3YmaRtpBJRJ4Z/MUupof\n" +
		"WCwd2nJbnbpFTfSg9s9y96R9/Xw7RKdfuicCX6fLh3XJw37ncL99wObAEllGGkeX\n" +
		"P9bD6omHJ+5t0hjMrI0xufTMTnKh8mAzJ9aswnllGRVqe8DeaA+Q1l/3m9UWiSlj\n" +
		"ewjPtQcb7zRAuMyeQssq9efB5HVpiIKlqQMctOtnkoJFMV593jDwOyKFAHMchd5R\n" +
		"wZkIS1pid2W12zDnXECEIHe3Zte26l9vPIshaVnIGOan/bxu51q2XKNj+jOG9IfO\n" +
		"WygJAYFWUIFSkosbS9JtZ2z36g1fk+532toJTLd12Exu6GElAgMBAAGjgeIwgd8w\n" +
		"HQYDVR0OBBYEFE20iZcUvtwAazWCF+tQHXZBNtv3MIGvBgNVHSMEgacwgaSAFE20\n" +
		"iZcUvtwAazWCF+tQHXZBNtv3oYGApH4wfDELMAkGA1UEBhMCSU4xCzAJBgNVBAgT\n" +
		"AktBMQwwCgYDVQQHEwNCTFIxEzARBgNVBAoTClNpbGx5UHJveHkxDDAKBgNVBAsT\n" +
		"A0RldjEbMBkGA1UEAxMSY29tLnNpbGx5cHJveHkuZGV2MRIwEAYJKoZIhvcNAQkB\n" +
		"FgNuL2GCCQCoXKEwYGZu3DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IB\n" +
		"AQA22zJYaLd+SziIV6V+02P5U90TotExNqd3diugrXLRrdxRUKRHl7zuQsK2c1vY\n" +
		"amGac4oDhlFY/9fx12NUh0eg9+1N5DusmIlhteSIZPcoGYqr2L0qUhmjvq+gu+OR\n" +
		"EF08/I7gxNVVAr5ux3GcMLNGu9S7ybecezBSJbsx5YB4vaOcF7S2bnKgw48pH2Rl\n" +
		"ZWmTeEP6tCO0MXftduS8/JIac/ON1BrvNqlOoy+YGmSdz34OD2Eb0uG9dJTmG3Lv\n" +
		"bXTulpfFNwI/3YrjFgODMy91rviF7yC3++4oBjakE2JwFax9R+L4uhOJT0dzonXY\n" +
		"8uAl76/XCWukTjFHWtz1zLQL\n" +
		"-----END CERTIFICATE-----\n"

		//3072 bit DSA key
	DSA_Priv = "-----BEGIN DSA PRIVATE KEY-----\n" +
		"MIIEvQIBAAKCAYEAhk6DnWysa3CWmPt5700KQSPJXYHnIUbeBu0ch3QLHuxBxUaW\n" +
		"YrmZfmwu4JE0aZUy7BiQPvoU9M6puTfuAuHrmlUqcbhYVdv67ezOa1cNP+LCaUhF\n" +
		"yGgOokkF4hEZsI+U0rzm9ipfCbFFgW+U7r7pA0jF4H9aanO+yKGpHEMuodz3El3u\n" +
		"azZaZX3csd/6YcW/0dBQwyBCwD1BLwpGv+rCBztQdmuNIUhUQoSksbhD0ZFBS6cp\n" +
		"zvyUU6RnLl+zhWt5/L+WdVMllJqxkZHIWI9pWhUAxvL7QO6BmSqMpiXqFv4BnLhJ\n" +
		"4zItiWMmJG3g0EIQ/eJFlTQJ6KpqnVMcTMY4FIWceV+8FAjIewpVWKhO+xESHc1c\n" +
		"ieY+Mn1spjQEgKy/P6QE2V7hLLNrX3pNVfc4LG7X4A4HzGqNDw+ycoYn8NeC1pXf\n" +
		"7VTAtOFIWQ78BZvV4cW3iwQa37Qk3x8Bix16pvdGkwaUxSWKAQN8RlOjctvOUmU9\n" +
		"3cPnIIy1PbBmuKfrAhUAssDGX47qsauGM5ZNVqgrKB+nVqECggGAMEMaMZlrnShp\n" +
		"4vEJ/zT8B7RyXeu5FEEmemGgEog6n9BfeRhUlYeLgDzp60I+UiM4Pu5geXBpQ8JW\n" +
		"ffSAUOJLSkKTYTyTFVEJiPcWFyMc4KRZWyF5lJOsdkrG9DqmjjseQ28VxMReVraL\n" +
		"Ez4zfb7z14FbyG6qb6mUrofozOU5JGuze3Hxh39v/VuUJm9f7CZz39wiPXi8iOfb\n" +
		"N5tnpeAcMErcpCIJlSkKtT2KjsRB7xFN0MsnG3fhPXWu90j8J1YQAZQaoSdPa8O/\n" +
		"Bdr+F63IOYtAhAZrSzZuYIz6iU6RKi8is7+IuuovQTqERTOne4GXwGfvWUOmYB52\n" +
		"Zo6R8pM/Gf2qOJwFGu9M0WrmROTY+Ceglfk7nqDuDcjVNA/ZHms9McGwd2InavAq\n" +
		"4vqg5mhS9ecHE6/izpfR+pIT7WPxkJSD407A9ai55veMm6Iu2ZOzJL5pKagUpGDp\n" +
		"toggphS+e0RZTzrd33wc2HGKwvxvYsXp6EtaUIqI52wph5VMwb7LAoIBgGGAlXTa\n" +
		"0+TwLFPaAY7Xm3WzFJadV9Tnpyo+b3shGnL/1DfOesasinJs7Ojlcx19LIOGZu0o\n" +
		"XohBOZQyELlA/v9TyatxudJDvUdCSH3ZFwguqGGY2EVJIuYv0QgI/JlYvZe8sm4G\n" +
		"HUFJThTuSGXrF8wBoB//rNaD3qA3PdV1MbwpP0oyMn/txLxgq+zNwDfsbLhbDP7p\n" +
		"DzaFYCN4Im5zR2R9BuCyo7rcKxIANhmqEmy8KMZU/+SqOiVxaX1IsMQfY3SiIQ6P\n" +
		"7/e6JvfePJ0l2x7oemchRULc5th8wA20k4w92FAvxxt55UShuqUynSFC1Tz1ND1l\n" +
		"ZEQ8LOJRWB04H5RT3hep/QCZ4waxrm78eVJZ1aEe8WR8AwCcGPAMb38K0udm2DYD\n" +
		"Pwa0QeEy/+j/2YoTYbWoah/E6GWvsKZpO6lvjxfYgPwRO6c+CjwZExGclVr9daNi\n" +
		"F5aijbA0GeZEMbIMeN0nmm8uqMoH0Q8KeW2wc6X/e+eOjQRb4o11BN9cHQIUB7Qa\n" +
		"T99QExNMThNILuqcMAQ6fBE=\n" +
		"-----END DSA PRIVATE KEY-----\n"

	DSA_Cert = "-----BEGIN CERTIFICATE-----\n" +
		"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\n" +
		"G33E46W0xg==\n" +
		"-----END CERTIFICATE-----\n"

	BenchMarkRouteMapJSON = `{	"Routes":[
									{
										"Host":"127.0.0.1",
										"MethodPathMaps": [
																				{
																					"Method": "GET",
																					"Path"  : "/path1/:echo",
																					"Route" : [ "http://127.0.0.1:9090/", 0]
																				},
																				{
																					"Method": "GET",
																					"Path"  : "/path2/path3/:echo",
																					"Route" : ["http://127.0.0.1:9090/", 0]
																				},
																				{
																					"Method": "GET",
																					"Path"  : "/path4/path5/path6/:echo",
																					"Route" : ["http://127.0.0.1:9090/", 0]
																				},
																				{
																					"Method": "GET",
																					"Path"  : "/path7/path8/path9/path10/:echo",
																					"Route" : ["http://127.0.0.1:9090/", 0]
																				},
																				{
																					"Method": "GET",
																					"Path"  : "/path11/path12/path13/path14/path15/:echo",
																					"Route" : ["http://127.0.0.1:9090/", 0]
																				}
																			]
									},
									{
										"Host":"localhost",
										"MethodPathMaps": [
																				{
																					"Method": "GET",
																					"Path"  : "/path1/:echo",
																					"Route" : [ "http://127.0.0.1:9090/", 0]
																				},
																				{
																					"Method": "GET",
																					"Path"  : "/path2/path3/:echo",
																					"Route" : ["http://127.0.0.1:9090/", 0]
																				},
																				{
																					"Method": "GET",
																					"Path"  : "/path4/path5/path6/:echo",
																					"Route" : ["http://127.0.0.1:9090/", 0]
																				},
																				{
																					"Method": "GET",
																					"Path"  : "/path7/path8/path9/path10/:echo",
																					"Route" : ["http://127.0.0.1:9090/", 0]
																				},
																				{
																					"Method": "GET",
																					"Path"  : "/path11/path12/path13/path14/path15/:echo",
																					"Route" : ["http://127.0.0.1:9090/", 0]
																				}
																			]
										}
									]
			}`
)

var (
	ECDSA_Crt             = "test_ECDSA.cert"
	ECDSA_Key             = "test_ECDSA.key"
	RSA_Crt               = "test_RSA.cert"
	RSA_Key               = "test_RSA.key"
	DSA_Crt               = "test_DSA.cert"
	DSA_Key               = "test_DSA.key"
	KeyStore              = "test.keystore"
	alias_default         = "default"
	alias                 = "localhost"
	KeyStorePass          = "test"
	Addr                  = "127.0.0.1:8444"
	RouteMapFilePath      = "test_routemap.json"
	BenchRouteMapFilePath = "bench_routemap.json"
	BenchmarkRequests     = []string{
		"https://127.0.0.1:8444/path1/hello",
		"https://127.0.0.1:8444/path2/path3/hello",
		"https://127.0.0.1:8444/path4/path5/path6/hello",
		"https://127.0.0.1:8444/path7/path8/path9/path10/hello",
		"https://127.0.0.1:8444/path11/path12/path13/path14/path15/hello",
		"https://localhost:8444/path1/hello",
		"https://localhost:8444/path2/path3/hello",
		"https://localhost:8444/path4/path5/path6/hello",
		"https://localhost:8444/path7/path8/path9/path10/hello",
		"https://localhost:8444/path11/path12/path13/path14/path15/hello",
	}
	BenchMarkKeystore = "benchmark.keystore"
)

var minTLSver = []uint{uint(0), uint(1), uint(2), uint(3)}

func TestMain(m *testing.M) {
	err := writeKeys()
	if err != nil {
		log.Fatal("Test initialization Failed!", err)
	}
	var pass = KeyStorePass
	utility.GenerateKeyStore(&KeyStore, &alias_default, &ECDSA_Crt, &ECDSA_Key,
		&pass)
	//log.Print("GenerateKeyStore() succeeded for default:ECDSA")
	pass = KeyStorePass
	utility.GenerateKeyStore(&KeyStore, &alias, &ECDSA_Crt, &ECDSA_Key,
		&pass)
	//log.Print("GenerateKeyStore() succeeded for non-default:ECDSA")
	pass = KeyStorePass
	utility.GenerateKeyStore(&KeyStore, &alias_default, &RSA_Crt, &RSA_Key,
		&pass)
	//log.Print("GenerateKeyStore() succeeded for default:RSA")
	pass = KeyStorePass
	utility.GenerateKeyStore(&KeyStore, &alias, &RSA_Crt, &RSA_Key,
		&pass)
	//log.Print("GenerateKeyStore() succeeded for non-default:RSA")

	pass = KeyStorePass
	utility.GenerateKeyStore(&BenchMarkKeystore, &alias_default, &ECDSA_Crt, &ECDSA_Key,
		&pass)
	//log.Print("BenchGenerateKeyStore() succeeded for default:ECDSA")
	pass = KeyStorePass
	utility.GenerateKeyStore(&BenchMarkKeystore, &alias, &ECDSA_Crt, &ECDSA_Key,
		&pass)
	//log.Print("BenchGenerateKeyStore() succeeded for non-default:ECDSA")
	pass = KeyStorePass
	utility.GenerateKeyStore(&BenchMarkKeystore, &alias_default, &RSA_Crt, &RSA_Key,
		&pass)
	//log.Print("BenchGenerateKeyStore() succeeded for default:RSA")
	pass = KeyStorePass
	utility.GenerateKeyStore(&BenchMarkKeystore, &alias, &RSA_Crt, &RSA_Key,
		&pass)
	//log.Print("BenchGenerateKeyStore() succeeded for non-default:RSA")
	/*
		pass = KeyStorePass
		utility.GenerateKeyStore(&KeyStore, &alias_default, &DSA_Crt, &DSA_Key,
			&pass)
		log.Print("GenerateKeyStore() succeeded for default:DSA")
		pass = KeyStorePass
		utility.GenerateKeyStore(&KeyStore, &alias, &DSA_Crt, &DSA_Key,
			&pass)
		log.Print("GenerateKeyStore() succeeded for non-default:DSA")
	*/
	certMap = make(map[string]tls.Certificate)
	runTests := m.Run()
	os.Exit(runTests)
}

func writeKeys() (err error) {
	err = ioutil.WriteFile(ECDSA_Crt, []byte(ECDSA_Cert), 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(ECDSA_Key, []byte(ECDSA_Priv), 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(RSA_Crt, []byte(RSA_Cert), 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(RSA_Key, []byte(RSA_Priv), 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(DSA_Crt, []byte(DSA_Cert), 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(DSA_Key, []byte(DSA_Priv), 0600)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(RouteMapFilePath, []byte(RouteMapJSON), 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(BenchRouteMapFilePath, []byte(BenchMarkRouteMapJSON), 0644)
	if err != nil {
		return err
	}

	os.Remove(KeyStore)
	os.Remove(BenchMarkKeystore)
	return
}

func resetParams() {
	ECDSA_Crt = "test_ECDSA.cert"
	ECDSA_Key = "test_ECDSA.key"
	RSA_Crt = "test_RSA.cert"
	RSA_Key = "test_RSA.key"
	DSA_Crt = "test_DSA.cert"
	DSA_Key = "test_DSA.key"
	KeyStore = "test.keystore"
	alias_default = "default"
	alias = "localhost"
	KeyStorePass = "test"
	Addr = "127.0.0.1:8444"
	RouteMapFilePath = "test_routemap.json"
	BenchRouteMapFilePath = "test_routemap.json"
}

func TestLoadCertMap(t *testing.T) {
	certMap = make(map[string]tls.Certificate)
	var incorrectPassword = "incorrectPassword"
	var invalidFileName = "invalidFileName"
	if loadCertMap(&invalidFileName, []byte(KeyStorePass), &certMap) == nil {
		t.Errorf("loadCertMap() fail: failed to catch fileload error")
	}
	if loadCertMap(&KeyStore, []byte(incorrectPassword), &certMap) == nil {
		t.Errorf("loadCertMap() fail: failed to catch incorrect password error")
	}

	//test for loading a non-defaulted keystore
	var incorrectKeyStore = "incorrect.keystore"
	var nonDefaultAlias = "nonDefault"
	var tempPass = KeyStorePass

	YesInput := []byte("na-da")
	tmpfile, err := ioutil.TempFile("", "tmp")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up
	if _, err := tmpfile.Write(YesInput); err != nil {
		log.Fatal(err)
	}
	if _, err := tmpfile.Seek(0, 0); err != nil {
		log.Fatal(err)
	}
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }() // Restore original Stdin
	os.Stdin = tmpfile
	os.Remove(incorrectKeyStore)
	utility.GenerateKeyStore(&incorrectKeyStore, &nonDefaultAlias, &ECDSA_Crt, &ECDSA_Key,
		&tempPass)
	tempPass = KeyStorePass
	if loadCertMap(&incorrectKeyStore, []byte(tempPass), &certMap) == nil {
		t.Errorf("loadCertMap() fail: failed to catch error for keystore without Default alias")
	}
	//test for loading a non-defaulted keystore

	certMap = make(map[string]tls.Certificate)
	loadCertMapErr := loadCertMap(&KeyStore, []byte(KeyStorePass), &certMap)
	if loadCertMapErr != nil {
		t.Errorf("loadCertMap() fail: failed with error: %s", loadCertMapErr)
	}
	log.Printf("TestLoadCertMap() debug: ECDSAdefault - %#v", ECDSAdefault.Certificate[0])
	// check if the default ECDSA has been loaded properly
	x509Cert, certParseErr := x509.ParseCertificate(ECDSAdefault.Certificate[0])
	if certParseErr != nil {
		t.Errorf("loadCertMap() fail: failed to load certificates correctly")
	}
	log.Printf("TestLoadCertMap() debug: x509Cert - %#v", x509Cert.PublicKeyAlgorithm)
	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := ECDSAdefault.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			t.Errorf("loadCertMap() fail: private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			t.Errorf("loadCertMap() fail: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		//priv, ok := certMap[Hostname+":ECDSA"].PrivateKey.(*ecdsa.PrivateKey)
		priv, ok := ECDSAdefault.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Errorf("loadCertMap() fail: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			t.Errorf("loadCertMap() fail: private key does not match public key")
		}
	default:
		t.Errorf("loadCertMap() fail: unknown public key algorithm")
	}

	//check if the non-default ECDSA has been loaded properly
	x509Cert, certParseErr = x509.ParseCertificate(certMap[alias+":ECDSA"].Certificate[0])
	if certParseErr != nil {
		t.Errorf("loadCertMap() fail: failed to load certificates correctly")
	}
	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := certMap[alias+":ECDSA"].PrivateKey.(*rsa.PrivateKey)
		if !ok {
			t.Errorf("loadCertMap() fail: private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			t.Errorf("loadCertMap() fail: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := certMap[alias+":ECDSA"].PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Errorf("loadCertMap() fail: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			t.Errorf("loadCertMap() fail: private key does not match public key")
		}
	default:
		t.Errorf("loadCertMap() fail: unknown public key algorithm")
	}
}

func TestReloadCertMap(t *testing.T) {
	quitReloadChannel := make(chan struct{})
	certMap = make(map[string]tls.Certificate)
	go reloadCertMap(&KeyStore, []byte(KeyStorePass), &certMap,
		quitReloadChannel, uint(1))
	time.Sleep(2 * time.Second)
	log.Printf("TestReLoadCertMap() debug: ECDSAdefault is %#v", ECDSAdefault.Certificate[0])
	// check if the default ECDSA has been loaded properly
	x509Cert, certParseErr := x509.ParseCertificate(ECDSAdefault.Certificate[0])
	if certParseErr != nil {
		t.Errorf("reloadCertMap() fail: failed to load certificates correctly")
	}
	log.Printf("TestReLoadCertMap() debug: x509Cert - %#v", x509Cert.PublicKeyAlgorithm)
	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := ECDSAdefault.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			t.Errorf("reloadCertMap() fail: private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			t.Errorf("reloadCertMap() fail: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := ECDSAdefault.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Errorf("reloadCertMap() fail: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			t.Errorf("reloadCertMap() fail: private key does not match public key")
		}
	default:
		t.Errorf("reloadCertMap() fail: unknown public key algorithm")
	}

	// check if the non-default ECDSA has been loaded properly
	x509Cert, certParseErr = x509.ParseCertificate(certMap[alias+":ECDSA"].Certificate[0])
	if certParseErr != nil {
		t.Errorf("reloadCertMap() fail: failed to load certificates correctly")
	}
	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := certMap[alias+":ECDSA"].PrivateKey.(*rsa.PrivateKey)
		if !ok {
			t.Errorf("reloadCertMap() fail: private key type does not match public key type")
		}
		if pub.N.Cmp(priv.N) != 0 {
			t.Errorf("reloadCertMap() fail: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		priv, ok := certMap[alias+":ECDSA"].PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Errorf("reloadCertMap() fail: private key type does not match public key type")
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			t.Errorf("reloadCertMap() fail: private key does not match public key")
		}
	default:
		t.Errorf("reloadCertMap() fail: unknown public key algorithm")
	}

	stopReloadKeyStore(quitReloadChannel)
	certMap = make(map[string]tls.Certificate)
	ECDSAdefault = &tls.Certificate{}
	ECDSAdefaultExists = false
	time.Sleep(5 * time.Second)
	if _, exists := certMap[alias+":ECDSA"]; exists {
		t.Errorf("stopReloadKeyStore() fail: failed to stop reloadKeyStore goroutine.")
	}
	if ECDSAdefaultExists {
		t.Errorf("stopReloadKeyStore() fail: failed to stop reloadKeyStore goroutine.")
	}
}

func TestAliasExists(t *testing.T) {
	f, _ := os.Open(KeyStore)
	keyStore, _ := keystore.Decode(f, []byte(KeyStorePass))
	if !aliasExists(&keyStore, "default:ECDSA") {
		t.Errorf("aliasExists() fail: failed to locate existing alias.")
	}
	if !aliasExists(&keyStore, "default:RSA") {
		t.Errorf("aliasExists() fail: failed to locate existing alias.")
	}
	if aliasExists(&keyStore, "random") {
		t.Errorf("aliasExists() fail: failed to flag a non-existant alias.")
	}
}

func TestParsePrivateKey(t *testing.T) {

}

func TestReturnCert(t *testing.T) {
	server, _ := net.Pipe()
	defer server.Close()
	var clientHelloMap [4](*tls.ClientHelloInfo)
	clientHelloMap[0] = &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS10},
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		ServerName:        "default",
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	}
	clientHelloMap[1] = &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS11},
		ServerName:        "",
		CipherSuites:      []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
		Conn:              server,
	}
	clientHelloMap[2] = &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		ServerName:        "localhost",
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
	}
	clientHelloMap[3] = &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		ServerName:        "localhost",
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
	}
	loadCertMapErr := loadCertMap(&KeyStore, []byte(KeyStorePass), &certMap)
	if loadCertMapErr != nil {
		t.Errorf("returnTLSConfig() fail: failed with error: %s", loadCertMapErr)
	}
	for _, clientHello := range clientHelloMap {
		Cert, CertErr := returnCert(clientHello)
		if CertErr != nil {
			t.Errorf("returnCert() fail: failed with error: %#v", CertErr)
		}
		////debug/////
		log.Printf("TestReturnCert() debug: Cert returned  - %#v", Cert.Certificate[0])
		////debug/////
		x509Cert, certParseErr := x509.ParseCertificate(Cert.Certificate[0])
		if certParseErr != nil {
			t.Errorf("testReturnCert() fail: Certificate returned is not valid")
		}
		switch pub := x509Cert.PublicKey.(type) {
		case *rsa.PublicKey:
			priv, ok := Cert.PrivateKey.(*rsa.PrivateKey)
			if !ok {
				t.Errorf("returnCert() fail: private key type does not match public key type")
			}
			if pub.N.Cmp(priv.N) != 0 {
				t.Errorf("returnCert() fail: private key does not match public key")
			}
		case *ecdsa.PublicKey:
			priv, ok := Cert.PrivateKey.(*ecdsa.PrivateKey)
			if !ok {
				t.Errorf("returnCert() fail: private key type does not match public key type")
			}
			if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
				t.Errorf("returnCert() fail: private key does not match public key")
			}
		default:
			t.Errorf("returnCert() fail: unknown public key algorithm")
		}
	}

	testClientHello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		ServerName:        "localhost",
		CipherSuites:      []uint16{0x0040},
		Conn:              server,
	}
	_, testCertErr := returnCert(testClientHello)
	if testCertErr == nil {
		t.Errorf("returnCert() fail: failed to catch cert match exception: %#v",
			testCertErr)
	}
}

func TestBuildRouteMap(t *testing.T) {
	testRouteMap := &RouteMap{}
	if buildRouteMap(&RouteMapFilePath, testRouteMap) != nil {
		t.Errorf("buildRouteMap() fail: failed to build a valid Route Map")
	}
	InvalidFilePath := "invalid"
	if buildRouteMap(&InvalidFilePath, testRouteMap) == nil {
		t.Errorf("buildRouteMap() fail: failed to throw error for a non-existing file")
	}
	var InvalidRouteMapJSON = `{	"Routes":[
	              {
	                "Host":"127.0.0.1",
	                "MethodPathMaps": {
                                      "Method": "GET",
                                      "Path"  : "/wild/:domain/*end",
                                      "Route" : [ "https://www.",0,"/.com/", 1 ]
	                                  },
																		{
																			"Method": "GET",
																			"Path"  : "/invalid/",
																			"Route" : [/,,"?"]
																		}
	               }
								]
		}`
	InvalidRouteMapPath := "test_InvalidRouteMap.json"
	err := ioutil.WriteFile(InvalidRouteMapPath, []byte(InvalidRouteMapJSON), 0644)
	if err != nil {
		log.Printf("\nTestBuildRouteMap(): Failed to write %#v", InvalidRouteMapPath)
	}
	if buildRouteMap(&InvalidRouteMapPath, testRouteMap) == nil {
		t.Errorf("buildRouteMap() fail: failed to throw error for invalid JSON Route Path")
	}
}

func TestAssignRoutes(t *testing.T) {

}

func TestProxyHandlerMapServeHTTP(t *testing.T) {
	testpHMap := make(proxyHanlderMap)
	testRouter := httprouter.New()
	testRouter.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprint(w, "Welcome!\n")
	})
	testpHMap["www.donkeys.com"] = testRouter
	testServer := httptest.NewUnstartedServer(testpHMap)
	testServer.Start()
	defer testServer.Close()
	testClient := &http.Client{
		//first create a transport that is tolerant to SSL errors
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: false,
		},
		// we will not follow any redirect rather pass the instructions to
		// the client
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		//we will declare a reasonable timeout value here. Alternatively we
		// can look to parameterize this to fetch its value from routeMap
		Timeout: 5 * time.Second,
	}
	testResponse, _ := testClient.Get(testServer.URL + "/")
	if testResponse.StatusCode != 403 {
		t.Errorf("\nPHMap.ServeHTTP() fail: failed to handle non-Mapped hosts")
	}
}

func TestRouteBuilder(t *testing.T) {

}

func TestIsSigAlgSupported(t *testing.T) {

}

func TestSillyProxy(t *testing.T) {

	for _, ver := range minTLSver {
		resetParams()
		TLSVersion := ver
		invalidRouteMapFilePath := "invalidfilepath"
		_, err := SillyProxy(&KeyStore, &KeyStorePass, &TLSVersion,
			&Addr, &invalidRouteMapFilePath)
		if err == nil {
			t.Errorf("\nTestSillyProxy() fail: failed to catch buildRouteMap() error")
		}
		resetParams()
		TLSVersion = ver
		invalidKeyStoreFilePath := "invalidfilepath"
		_, err = SillyProxy(&invalidKeyStoreFilePath, &KeyStorePass, &TLSVersion,
			&Addr, &RouteMapFilePath)
		if err == nil {
			t.Errorf("\nTestSillyProxy() fail: failed to catch loadCertMap() error")
		}
		resetParams()
		TLSVersion = ver
		sp, spError := SillyProxy(&KeyStore, &KeyStorePass,
			&TLSVersion, &Addr, &RouteMapFilePath)
		if spError != nil {
			t.Errorf("\nTestSillyProxy() fail: failed with error: %s", spError)
		}
		testServer := httptest.NewUnstartedServer(sp.Handler)
		testServer.Config = sp
		testServer.StartTLS()
		defer testServer.Close()
		//log.Printf("\nTest log - Test server URL:%#v", testServer.URL+"/wild/qssum/index.html")
		testClient := &http.Client{
			//first create a transport that is tolerant to SSL errors
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives: false,
			},
			// we will not follow any redirect rather pass the instructions to
			// the client
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			//we will declare a reasonable timeout value here. Alternatively we
			// can look to parameterize this to fetch its value from routeMap
			Timeout: 5 * time.Second,
		}
		testURIMaps := make(map[int][]string)
		testURIMaps[200] = append(testURIMaps[200], "/google/wonderful")
		testURIMaps[404] = append(testURIMaps[404], "/pattern/not/caught/by/proxy")
		testURIMaps[301] = append(testURIMaps[301], "/redirect/")
		testURIMaps[http.StatusBadRequest] = append(testURIMaps[http.StatusBadRequest], "/wild/notexistingdomain/validPathButNotExistingDownstream")
		testURIMaps[http.StatusBadRequest] = append(testURIMaps[http.StatusBadRequest], "/failureCase/RoutePathIncorrect")
		testURIMaps[http.StatusBadRequest] = append(testURIMaps[http.StatusBadRequest], "/invalid/")

		for testStatus, testURIMap := range testURIMaps {
			for _, testURI := range testURIMap {
				testReq, _ := http.NewRequest(http.MethodGet, testServer.URL+testURI, nil)
				testReq.Header.Add("Silly", "first value")
				testReq.Header.Add("Silly", "second value")
				testResponse, testResponseErr := testClient.Do(testReq)
				if testResponseErr != nil {
					t.Errorf("\nTest Request failed: %#v", testResponseErr)
				}
				if testResponse.StatusCode != testStatus {
					t.Errorf("\nTest Request failed for %#v: %#v", testURI, testResponse)
				}
				//log.Printf("\nTest log - Test Response: %#v", testResponse)
				//log.Printf("\nTest log - Test Response Body: %#v", testResponse.Body)
				testResponse.Body.Close()
			}
		}

	}
	//syscall.Kill(syscall.Getpid(), syscall.SIGINT)
}

func BenchmarkSillyProxy(b *testing.B) {
	/////BenchMark related setup follows//////

	pass := KeyStorePass

	benchTLSVersion := uint(1)
	benchSP, benchSPError := SillyProxy(&BenchMarkKeystore, &pass,
		&benchTLSVersion, &Addr, &BenchRouteMapFilePath)
	if benchSPError != nil {
		log.Fatalf("\nSetup fail: failed to fire benchSP with error: %s", benchSPError)
	}
	go benchSP.ListenAndServeTLS("", "")

	benchmarkClient := &http.Client{
		//first create a transport that is tolerant to SSL errors
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true,
				CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			},
			DisableKeepAlives: false,
		},
		// we will not follow any redirect rather pass the instructions to
		// the client
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		//we will declare a reasonable timeout value here. Alternatively we
		// can look to parameterize this to fetch its value from routeMap
		Timeout: 5 * time.Second,
	}
	count := len(BenchmarkRequests)
	benchmarkTargetServer := &http.Server{
		Addr: ":9090",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			io.WriteString(w, "hello")
		}),
	}
	go benchmarkTargetServer.ListenAndServe()

	/////BenchMark related setup ends//////
	//now run the test
	//log.Printf("let us run the benchmark now")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		res, _ := benchmarkClient.Get(BenchmarkRequests[n%count])
		res.Body.Close()
	}
}

func BenchmarkWithOutSilly(b *testing.B) {
	directClient := &http.Client{
		//first create a transport that is tolerant to SSL errors
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			},
			DisableKeepAlives: false,
		},
		// we will not follow any redirect rather pass the instructions to
		// the client
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		//we will declare a reasonable timeout value here. Alternatively we
		// can look to parameterize this to fetch its value from routeMap
		Timeout: 5 * time.Second,
	}
	directServer := &http.Server{
		Addr: ":9091",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			io.WriteString(w, "hello")
		}),
	}
	go directServer.ListenAndServeTLS("test_ECDSA.cert", "test_ECDSA.key")
	//log.Printf("let us run the benchmark now")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		res, _ := directClient.Get("https://localhost:9091")
		res.Body.Close()
	}
}
