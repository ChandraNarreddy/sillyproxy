package main

import (
	"net/http"
	"strings"
)

//proxyHanlderMap maps the host names to their http.Handlers
type proxyHanlderMap map[string]http.Handler

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
