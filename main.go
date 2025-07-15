package main

import (
	"fmt"
	"log"
	"net/http"

	wurfl "github.com/WURFL/golang-wurfl"
)

func main() {
	// User-Agent from the request
	ua := "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36"

	// The entire cookie string containing lengthbin encoded UACH data
	cookieString := "wuach=YnIuMC5tLjIuPzF1YWZ2LjAuZnZsLjkwLiJOb3Q7IEEgQnJhbmQiO3Y9IjI0LjAuMCIsICJDaHJvbWl1bSI7dj0iMTM3LjAuNzE1MS41NSIsICJHb29nbGUgQ2hyb21lIjt2PSIxMzcuMC43MTUxLjU1Im1kLjEzLiJQaXhlbCA5IFBybyJwLjkuIkFuZHJvaWQicHYuNC4iMTUiYXJjaC4yLiIiYnQuMC4="

	// Pass the cookie string and receive a decoded header map
	headerMap, cerr := DecodeHeadersFromCookie("wuach", cookieString)
	if cerr != nil {
		log.Fatalf("Unparsable cookie string: %v", cerr)
	}

	// Download a fresh WURFL snapshot
	wurflerr := wurfl.Download("https://data.scientiamobile.com/xxxxxxx/wurfl.zip", ".")
	if wurflerr != nil {
		log.Fatalf("Error downloading WURFL file: %v", wurflerr)
	}

	// Create a WURFL Engine with a default configuration
	wengine, werr := wurfl.Create("./wurfl.zip", nil, nil, -1, wurfl.WurflCacheProviderLru, "100000")
	if werr != nil {
		log.Fatalf("WURFL Engine Error: %v", werr)
	}
	defer wengine.Destroy()

	// Transform the header map into a HTTP request to pass to the WURFL API
	req, rerr := http.NewRequest("GET", "http://example.com", nil)
	if rerr != nil {
		log.Fatalf("Error creating a HTTP Request: %v", rerr)
	}

	req.Header.Add("User-Agent", ua)
	for key, value := range headerMap {
		req.Header.Set(key, value)
	}

	// Perform the device lookup using the HTTP request
	device, derr := wengine.LookupRequest(req)
	if derr != nil {
		log.Fatalf("Error performing a device lookup: %v", derr)
	}
	defer device.Destroy()

	// Get WURFL ID and other device capabilities
	deviceid, deverr := device.GetDeviceID()
	if deverr != nil {
		log.Fatalf("Error getting WURFL ID: %v", deverr)
	}

	fmt.Println("WURFL ID: " + deviceid)
	fmt.Println("Device Name: " + device.GetVirtualCapability("device_name"))
	fmt.Println("Device OS: " + device.GetVirtualCapability("advertised_device_os"))
	fmt.Println("Device OS Version: " + device.GetVirtualCapability("advertised_device_os_version"))
	fmt.Println("Browser Name: " + device.GetVirtualCapability("advertised_browser"))
	fmt.Println("Browser Version: " + device.GetVirtualCapability("advertised_browser_version"))
}
