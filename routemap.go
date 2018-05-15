package main

import (
	"encoding/json"
	"fmt"
	"os"
)

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

//RouteMap is a collection of HostMap called Routes
type RouteMap struct {
	Routes []HostMap
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
