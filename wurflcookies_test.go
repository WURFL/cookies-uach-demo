package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	input := `YXJjaC41LiJ4ODYiYnQuNC4iNjQiYnIuNjQuIkdvb2dsZSBDaHJvbWUiO3Y9IjEzNSIsICJOb3QtQS5CcmFuZCI7dj0iOCIsICJDaHJvbWl1bSI7dj0iMTM1ImZ2bC45MC4iR29vZ2xlIENocm9tZSI7dj0iMTM1LjAuNzA0OS40MiIsICJOb3QtQS5CcmFuZCI7dj0iOC4wLjAuMCIsICJDaHJvbWl1bSI7dj0iMTM1LjAuNzA0OS40MiJtLjIuPzBtZC4yLiIicC45LiJXaW5kb3dzInB2LjguIjE5LjAuMCJ1YWZ2LjE1LiIxMzUuMC43MDQ5LjQyIg==`
	expected := map[string]string{
		"Sec-CH-UA-Arch":              `"x86"`,
		"Sec-CH-UA-Bitness":           `"64"`,
		"Sec-CH-UA-Brands":            `"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"`,
		"Sec-CH-UA-Full-Version-List": `"Google Chrome";v="135.0.7049.42", "Not-A.Brand";v="8.0.0.0", "Chromium";v="135.0.7049.42"`,
		"Sec-CH-UA-Mobile":            `?0`,
		"Sec-CH-UA-Model":             `""`,
		"Sec-CH-UA-Platform":          `"Windows"`,
		"Sec-CH-UA-Platform-Version":  `"19.0.0"`,
		"Sec-CH-UA-Full-Version":      `"135.0.7049.42"`,
	}

	res, err := DecodeLengthBin(input)
	require.NoError(t, err)
	assert.EqualValues(t, expected, res)

	assert.NotNil(t, res)
}

func TestDecodeHeadersFromCookie(t *testing.T) {
	cookieName := "uach-lengthbin"
	cookie := `uach-uriencode=arch%3D%2522x86%2522%3Bbt%3D%252264%2522%3Bbr%3D%2522Google%2520Chrome%2522%253Bv%253D%2522135%2522%252C%2520%2522Not-A.Brand%2522%253Bv%253D%25228%2522%252C%2520%2522Chromium%2522%253Bv%253D%2522135%2522%3Bfvl%3D%2522Google%2520Chrome%2522%253Bv%253D%2522135.0.7049.42%2522%252C%2520%2522Not-A.Brand%2522%253Bv%253D%25228.0.0.0%2522%252C%2520%2522Chromium%2522%253Bv%253D%2522135.0.7049.42%2522%3Bm%3D%253F0%3Bmd%3D%2522%2522%3Bp%3D%2522Windows%2522%3Bpv%3D%252219.0.0%2522%3Buafv%3D%2522135.0.7049.42%2522; uach=%7B%22uach%22%3A%22%5C%22Google%20Chrome%5C%22%3Bv%3D%5C%22135%5C%22%2C%20%5C%22Not-A.Brand%5C%22%3Bv%3D%5C%228%5C%22%2C%20%5C%22Chromium%5C%22%3Bv%3D%5C%22135%5C%22%22%2C%22fullv%22%3A%22%22%2C%22fullvl%22%3A%22%5C%22Google%20Chrome%5C%22%3Bv%3D%5C%22135.0.7049.42%5C%22%2C%20%5C%22Not-A.Brand%5C%22%3Bv%3D%5C%228.0.0.0%5C%22%2C%20%5C%22Chromium%5C%22%3Bv%3D%5C%22135.0.7049.42%5C%22%22%2C%22model%22%3A%22%5C%22%5C%22%22%2C%22pl%22%3A%22%5C%22Windows%5C%22%22%2C%22plver%22%3A%22%5C%2219.0.0%5C%22%22%2C%22arch%22%3A%22%5C%22x86%5C%22%22%7D; uach-json=eyJhcmNoaXRlY3R1cmUiOiJcIng4NlwiIiwiYml0bmVzcyI6IlwiNjRcIiIsImJyYW5kcyI6IlwiR29vZ2xlIENocm9tZVwiO3Y9XCIxMzVcIiwgXCJOb3QtQS5CcmFuZFwiO3Y9XCI4XCIsIFwiQ2hyb21pdW1cIjt2PVwiMTM1XCIiLCJmdWxsVmVyc2lvbkxpc3QiOiJcIkdvb2dsZSBDaHJvbWVcIjt2PVwiMTM1LjAuNzA0OS40MlwiLCBcIk5vdC1BLkJyYW5kXCI7dj1cIjguMC4wLjBcIiwgXCJDaHJvbWl1bVwiO3Y9XCIxMzUuMC43MDQ5LjQyXCIiLCJtb2JpbGUiOiI/MCIsIm1vZGVsIjoiXCJcIiIsInBsYXRmb3JtIjoiXCJXaW5kb3dzXCIiLCJwbGF0Zm9ybVZlcnNpb24iOiJcIjE5LjAuMFwiIiwidWFGdWxsVmVyc2lvbiI6IlwiMTM1LjAuNzA0OS40MlwiIn0=; uach-base64=arch%3DIng4NiI%3D%3Bbt%3DIjY0Ig%3D%3D%3Bbr%3DIkdvb2dsZSBDaHJvbWUiO3Y9IjEzNSIsICJOb3QtQS5CcmFuZCI7dj0iOCIsICJDaHJvbWl1bSI7dj0iMTM1Ig%3D%3D%3Bfvl%3DIkdvb2dsZSBDaHJvbWUiO3Y9IjEzNS4wLjcwNDkuNDIiLCAiTm90LUEuQnJhbmQiO3Y9IjguMC4wLjAiLCAiQ2hyb21pdW0iO3Y9IjEzNS4wLjcwNDkuNDIi%3Bm%3DPzA%3D%3Bmd%3DIiI%3D%3Bp%3DIldpbmRvd3Mi%3Bpv%3DIjE5LjAuMCI%3D%3Buafv%3DIjEzNS4wLjcwNDkuNDIi; uach-lengthbin=YXJjaC41LiJ4ODYiYnQuNC4iNjQiYnIuNjQuIkdvb2dsZSBDaHJvbWUiO3Y9IjEzNSIsICJOb3QtQS5CcmFuZCI7dj0iOCIsICJDaHJvbWl1bSI7dj0iMTM1ImZ2bC45MC4iR29vZ2xlIENocm9tZSI7dj0iMTM1LjAuNzA0OS40MiIsICJOb3QtQS5CcmFuZCI7dj0iOC4wLjAuMCIsICJDaHJvbWl1bSI7dj0iMTM1LjAuNzA0OS40MiJtLjIuPzBtZC4yLiIicC45LiJXaW5kb3dzInB2LjguIjE5LjAuMCJ1YWZ2LjE1LiIxMzUuMC43MDQ5LjQyIg==`

	expected := map[string]string{
		"Sec-CH-UA-Arch":              `"x86"`,
		"Sec-CH-UA-Bitness":           `"64"`,
		"Sec-CH-UA-Brands":            `"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"`,
		"Sec-CH-UA-Full-Version-List": `"Google Chrome";v="135.0.7049.42", "Not-A.Brand";v="8.0.0.0", "Chromium";v="135.0.7049.42"`,
		"Sec-CH-UA-Mobile":            `?0`,
		"Sec-CH-UA-Model":             `""`,
		"Sec-CH-UA-Platform":          `"Windows"`,
		"Sec-CH-UA-Platform-Version":  `"19.0.0"`,
		"Sec-CH-UA-Full-Version":      `"135.0.7049.42"`,
	}

	res, err := DecodeHeadersFromCookie(cookieName, cookie)
	require.NoError(t, err)
	assert.EqualValues(t, expected, res)

	assert.NotNil(t, res)
}

func BenchmarkDecode(b *testing.B) {
	input := `YXJjaC41LiJ4ODYiYnQuNC4iNjQiYnIuNjQuIkdvb2dsZSBDaHJvbWUiO3Y9IjEzNSIsICJOb3QtQS5CcmFuZCI7dj0iOCIsICJDaHJvbWl1bSI7dj0iMTM1ImZ2bC45MC4iR29vZ2xlIENocm9tZSI7dj0iMTM1LjAuNzA0OS40MiIsICJOb3QtQS5CcmFuZCI7dj0iOC4wLjAuMCIsICJDaHJvbWl1bSI7dj0iMTM1LjAuNzA0OS40MiJtLjIuPzBtZC4yLiIicC45LiJXaW5kb3dzInB2LjguIjE5LjAuMCJ1YWZ2LjE1LiIxMzUuMC43MDQ5LjQyIg==`
	for i := 0; i < b.N; i++ {
		_, err := DecodeLengthBin(input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeHeadersFromCookie(b *testing.B) {
	cookieName := "uach-lengthbin"
	cookie := `uach-uriencode=arch%3D%2522x86%2522%3Bbt%3D%252264%2522%3Bbr%3D%2522Google%2520Chrome%2522%253Bv%253D%2522135%2522%252C%2520%2522Not-A.Brand%2522%253Bv%253D%25228%2522%252C%2520%2522Chromium%2522%253Bv%253D%2522135%2522%3Bfvl%3D%2522Google%2520Chrome%2522%253Bv%253D%2522135.0.7049.42%2522%252C%2520%2522Not-A.Brand%2522%253Bv%253D%25228.0.0.0%2522%252C%2520%2522Chromium%2522%253Bv%253D%2522135.0.7049.42%2522%3Bm%3D%253F0%3Bmd%3D%2522%2522%3Bp%3D%2522Windows%2522%3Bpv%3D%252219.0.0%2522%3Buafv%3D%2522135.0.7049.42%2522; uach=%7B%22uach%22%3A%22%5C%22Google%20Chrome%5C%22%3Bv%3D%5C%22135%5C%22%2C%20%5C%22Not-A.Brand%5C%22%3Bv%3D%5C%228%5C%22%2C%20%5C%22Chromium%5C%22%3Bv%3D%5C%22135%5C%22%22%2C%22fullv%22%3A%22%22%2C%22fullvl%22%3A%22%5C%22Google%20Chrome%5C%22%3Bv%3D%5C%22135.0.7049.42%5C%22%2C%20%5C%22Not-A.Brand%5C%22%3Bv%3D%5C%228.0.0.0%5C%22%2C%20%5C%22Chromium%5C%22%3Bv%3D%5C%22135.0.7049.42%5C%22%22%2C%22model%22%3A%22%5C%22%5C%22%22%2C%22pl%22%3A%22%5C%22Windows%5C%22%22%2C%22plver%22%3A%22%5C%2219.0.0%5C%22%22%2C%22arch%22%3A%22%5C%22x86%5C%22%22%7D; uach-json=eyJhcmNoaXRlY3R1cmUiOiJcIng4NlwiIiwiYml0bmVzcyI6IlwiNjRcIiIsImJyYW5kcyI6IlwiR29vZ2xlIENocm9tZVwiO3Y9XCIxMzVcIiwgXCJOb3QtQS5CcmFuZFwiO3Y9XCI4XCIsIFwiQ2hyb21pdW1cIjt2PVwiMTM1XCIiLCJmdWxsVmVyc2lvbkxpc3QiOiJcIkdvb2dsZSBDaHJvbWVcIjt2PVwiMTM1LjAuNzA0OS40MlwiLCBcIk5vdC1BLkJyYW5kXCI7dj1cIjguMC4wLjBcIiwgXCJDaHJvbWl1bVwiO3Y9XCIxMzUuMC43MDQ5LjQyXCIiLCJtb2JpbGUiOiI/MCIsIm1vZGVsIjoiXCJcIiIsInBsYXRmb3JtIjoiXCJXaW5kb3dzXCIiLCJwbGF0Zm9ybVZlcnNpb24iOiJcIjE5LjAuMFwiIiwidWFGdWxsVmVyc2lvbiI6IlwiMTM1LjAuNzA0OS40MlwiIn0=; uach-base64=arch%3DIng4NiI%3D%3Bbt%3DIjY0Ig%3D%3D%3Bbr%3DIkdvb2dsZSBDaHJvbWUiO3Y9IjEzNSIsICJOb3QtQS5CcmFuZCI7dj0iOCIsICJDaHJvbWl1bSI7dj0iMTM1Ig%3D%3D%3Bfvl%3DIkdvb2dsZSBDaHJvbWUiO3Y9IjEzNS4wLjcwNDkuNDIiLCAiTm90LUEuQnJhbmQiO3Y9IjguMC4wLjAiLCAiQ2hyb21pdW0iO3Y9IjEzNS4wLjcwNDkuNDIi%3Bm%3DPzA%3D%3Bmd%3DIiI%3D%3Bp%3DIldpbmRvd3Mi%3Bpv%3DIjE5LjAuMCI%3D%3Buafv%3DIjEzNS4wLjcwNDkuNDIi; uach-lengthbin=YXJjaC41LiJ4ODYiYnQuNC4iNjQiYnIuNjQuIkdvb2dsZSBDaHJvbWUiO3Y9IjEzNSIsICJOb3QtQS5CcmFuZCI7dj0iOCIsICJDaHJvbWl1bSI7dj0iMTM1ImZ2bC45MC4iR29vZ2xlIENocm9tZSI7dj0iMTM1LjAuNzA0OS40MiIsICJOb3QtQS5CcmFuZCI7dj0iOC4wLjAuMCIsICJDaHJvbWl1bSI7dj0iMTM1LjAuNzA0OS40MiJtLjIuPzBtZC4yLiIicC45LiJXaW5kb3dzInB2LjguIjE5LjAuMCJ1YWZ2LjE1LiIxMzUuMC43MDQ5LjQyIg==`
	for i := 0; i < b.N; i++ {
		_, err := DecodeHeadersFromCookie(cookieName, cookie)
		if err != nil {
			b.Fatal(err)
		}
	}
}
