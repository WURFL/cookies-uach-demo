package main

import (
	"encoding/base64"
	"errors"
	"net/http"
)

var (
	headerKeyLookup = map[string]string{
		"arch": "Sec-CH-UA-Arch",
		"bt":   "Sec-CH-UA-Bitness",
		"br":   "Sec-CH-UA-Brands",
		"fvl":  "Sec-CH-UA-Full-Version-List",
		"m":    "Sec-CH-UA-Mobile",
		"md":   "Sec-CH-UA-Model",
		"p":    "Sec-CH-UA-Platform",
		"pv":   "Sec-CH-UA-Platform-Version",
		"uafv": "Sec-CH-UA-Full-Version",
	}
)

var ErrInvalidFormat = errors.New("WURFL UA-CH Cookie Decoder: invalid format")

// DecodeHeadersFromCookie takes a cookie name and cookie data,
// and returns a map of UA-CH HTTP headers decoded from the cookie data.
// The cookie data is expected to be in the format of a WURFL UA-CH cookie.
// If the cookie is not found or if the data is malformed, it returns an error.
func DecodeHeadersFromCookie(cookieName string, cookieData string) (map[string]string, error) {
	cookie, err := http.ParseCookie(cookieData)
	if err != nil {
		return nil, err
	}
	for _, c := range cookie {
		if c.Name == cookieName {
			return DecodeLengthBin(c.Value)
		}
	}
	return nil, errors.New("cookie not found")
}

// DecodeLengthBin takes a base64‑encoded string of the form
//
//	key.length.valuekey2.length2.value2...
//
// and returns a map[key]value.  If it hits malformed data,
// it returns the partial map plus ErrInvalidFormat.
func DecodeLengthBin(input string) (map[string]string, error) {
	m := make(map[string]string)
	// Base64‑decode
	data, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		// no partial data to return
		return m, err
	}
	// Use a single pass with minimal allocations
	i, n := 0, len(data)
	for i < n {
		// Find key
		start := i
		for i < n && data[i] != '.' {
			i++
		}
		if i >= n {
			return m, ErrInvalidFormat
		}
		key := string(data[start:i])
		i++ // skip '.'
		// Parse length field
		start = i
		for i < n && data[i] >= '0' && data[i] <= '9' {
			i++
		}
		if i >= n || data[i] != '.' {
			return m, ErrInvalidFormat
		}
		// Parse the length field, for example,
		// If the string to be read is "251":
		//   Iteration 1: length = 2
		//   Iteration 2: length = (2*10 = 20) + 5 = 25
		//   Iteration 3: length = (25*10 = 250) + 1 = 251
		length := 0
		for _, b := range data[start:i] {
			// In each iteration, we multiply the current length by 10
			// and add the integer value of the current character.
			// int(b-'0') is subtracting the ASCII value of '0' from the ASCII value of b
			// to convert the character to its integer value quickly.
			length = length*10 + int(b-'0')
		}
		i++ // skip '.'
		// Extract value
		if i+length > n {
			return m, ErrInvalidFormat
		}
		value := string(data[i : i+length])
		i += length
		// Store in map
		if headerKey, ok := headerKeyLookup[key]; ok {
			m[headerKey] = value
		} else {
			m[key] = value
		}
	}
	return m, nil
}
