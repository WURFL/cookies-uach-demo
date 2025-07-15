package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
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

	// Maximum allowed length to prevent memory exhaustion attacks
	maxAllowedLength = 1024 * 1024 // 1MB

	// Threshold for integer overflow detection when multiplying by 10
	maxIntDiv10 = math.MaxInt / 10
)

var (
	ErrInvalidFormat   = errors.New("WURFL UA-CH Cookie Decoder: invalid format")
	ErrEmptyInput      = errors.New("WURFL UA-CH Cookie Decoder: empty input parameters")
	ErrLengthTooLarge  = errors.New("WURFL UA-CH Cookie Decoder: length too large")
	ErrIntegerOverflow = errors.New("WURFL UA-CH Cookie Decoder: integer overflow in length parsing")
)

// DecodeHeadersFromCookie takes a cookie name and cookie data,
// and returns a map of UA-CH HTTP headers decoded from the cookie data.
// The cookie data is expected to be in the format of a WURFL UA-CH cookie.
// If the cookie is not found or if the data is malformed, it returns an error.
func DecodeHeadersFromCookie(cookieName string, cookieData string) (map[string]string, error) {
	// Input validation
	if cookieName == "" {
		return nil, fmt.Errorf("%w: cookie name cannot be empty", ErrEmptyInput)
	}
	if cookieData == "" {
		return nil, fmt.Errorf("%w: cookie data cannot be empty", ErrEmptyInput)
	}

	cookies, err := http.ParseCookie(cookieData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cookie: %w", err)
	}

	for _, c := range cookies {
		if c.Name == cookieName {
			return DecodeLengthBin(c.Value)
		}
	}
	return nil, fmt.Errorf("cookie '%s' not found", cookieName)
}

// DecodeLengthBin takes a base64‑encoded string of the form
//
//	key.length.valuekey2.length2.value2...
//
// and returns a map[key]value.  If it hits malformed data,
// it returns the partial map plus ErrInvalidFormat.
func DecodeLengthBin(input string) (map[string]string, error) {
	m := make(map[string]string)

	// Input validation
	if input == "" {
		return m, fmt.Errorf("%w: input string cannot be empty", ErrEmptyInput)
	}

	// Base64‑decode
	data, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		// no partial data to return
		return m, fmt.Errorf("failed to decode base64: %w", err)
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

		// Validate key is not empty
		if key == "" {
			return m, fmt.Errorf("%w: empty key found", ErrInvalidFormat)
		}

		i++ // skip '.'

		// Parse length field
		start = i
		for i < n && data[i] >= '0' && data[i] <= '9' {
			i++
		}
		if i >= n || data[i] != '.' {
			return m, ErrInvalidFormat
		}

		// Parse the length field with overflow protection, for example,
		// If the string to be read is "251":
		//   Iteration 1: length = 2
		//   Iteration 2: length = (2*10 = 20) + 5 = 25
		//   Iteration 3: length = (25*10 = 250) + 1 = 251
		length := 0
		for _, b := range data[start:i] {
			// Check for integer overflow before multiplication
			if length > maxIntDiv10 {
				return m, ErrIntegerOverflow
			}
			// Extract the current digit
			digit := int(b - '0')
			// In each iteration, we multiply the current length by 10
			// and add the integer value of the current character.
			// int(b-'0') is subtracting the ASCII value of '0' from the ASCII value of b
			// to convert the character to its integer value quickly.
			length = length*10 + digit
		}

		// Validate length
		if length <= 0 {
			return m, fmt.Errorf("%w: invalid length %d (must be positive)", ErrInvalidFormat, length)
		}
		if length > maxAllowedLength {
			return m, fmt.Errorf("%w: length %d exceeds maximum allowed %d", ErrLengthTooLarge, length, maxAllowedLength)
		}

		i++ // skip '.'

		// Extract value
		if i+length > n {
			return m, ErrInvalidFormat
		}
		value := string(data[i : i+length])
		i += length

		// Store in map (duplicate keys will overwrite, which is expected behavior)
		if headerKey, ok := headerKeyLookup[key]; ok {
			m[headerKey] = value
		} else {
			m[key] = value
		}
	}
	return m, nil
}
