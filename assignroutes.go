package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
)

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
			ResponseHeaderTimeout: 500 * time.Second,
			ExpectContinueTimeout: 10 * time.Second,
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
					//now add the query params from the original request as is
					if r.URL.RawQuery != "" {
						route = route + "?" + r.URL.RawQuery
					}

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
						resp.Body.Close()
						return
					}
					resp.Body.Close()
					return
				})
			//router.Handle ended
		}
		(*pHMap)[hostMap.Host] = router
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
