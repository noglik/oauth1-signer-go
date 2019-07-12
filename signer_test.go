package signer

import (
	"reflect"
	"regexp"
	"strconv"
	"testing"
)

func TestGetAuthorizationHeader(t *testing.T) {
	uri := "HTTPS://SANDBOX.api.mastercard.com/merchantid/v1/merchantid?MerchantId=GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29&Type=ExactMatch&Format=JSON"
	method := "GET"
	consumerKey := "aaa!aaa"
	signingKey := "dummy"

	testCases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "Empty body",
			body: "",
			want: `OAuth oauth_body_hash="47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",oauth_consumer_key="aaa!aaa",oauth_nonce="uTeLPs6K",oauth_signature_method="RSA-SHA256",oauth_timestamp="1524771555",oauth_version="1.0",oauth_signature="RSA_SIGNATURE"`,
		},
		{
			name: "Empty json object",
			body: "{}",
			want: `OAuth oauth_body_hash="RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=",oauth_consumer_key="aaa!aaa",oauth_nonce="uTeLPs6K",oauth_signature_method="RSA-SHA256",oauth_timestamp="1524771555",oauth_version="1.0",oauth_signature="RSA_SIGNATURE"`,
		},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetAuthorizationHeader(uri, method, tC.body, consumerKey, signingKey)

			if err != nil {
				t.Error(err)
			}

			if got != tC.want {
				t.Errorf("got '%v' want '%v'", got, tC.want)
			}
		})
	}
}

func TestExtractQueryParams(t *testing.T) {
	testCases := []struct {
		name string
		uri  string
		want map[string][]string
	}{
		{
			name: "Simple uri",
			uri:  "https://example.com/?test=true",
			want: map[string][]string{"test": []string{"true"}},
		},
		{
			name: "Complex uri",
			uri:  "https://sandbox.api.mastercard.com/merchantid/v1/merchantid?MerchantId=GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29&Format=XML&Type=ExactMatch&Format=JSON&EmptyVal=",
			want: map[string][]string{
				"EmptyVal":   []string{""},
				"Format":     []string{"JSON", "XML"},
				"MerchantId": []string{"GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29"},
				"Type":       []string{"ExactMatch"},
			},
		},
		{
			name: "Support RFC",
			uri:  "https://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b",
			want: map[string][]string{
				"b5":   []string{"%3D%253D"},
				"a3":   []string{"a"},
				"c%40": []string{""},
				"a2":   []string{"r%20b"},
			},
		},
		{
			name: "Non-encoded params",
			uri:  "https://example.com/request?colon=:&plus=+&comma=,",
			want: map[string][]string{
				"colon": []string{":"},
				"plus":  []string{"+"},
				"comma": []string{","},
			},
		},
		{
			name: "Encoded params",
			uri:  "https://example.com/request?colon=%3A&plus=%2B&comma=%2C",
			want: map[string][]string{
				"colon": []string{"%3A"},
				"plus":  []string{"%2B"},
				"comma": []string{"%2C"},
			},
		},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()
			got, err := extractQueryParams(tC.uri)

			if err != nil {
				t.Error(err)
			}

			if !reflect.DeepEqual(got, tC.want) {
				t.Errorf("\ngot '%v'\nwant '%v'", got, tC.want)
			}
		})
	}
}

func TestGetOAuthParams(t *testing.T) {
	commonConsumerKey := "aaa!aaa"
	timestamp := getTimestamp()

	testCases := []struct {
		name        string
		consumerKey string
		payload     string
		want        map[string]string
	}{
		{
			name:        "Without payload",
			consumerKey: commonConsumerKey,
			payload:     "",
			want: map[string]string{
				"oauth_body_hash":        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
				"oauth_consumer_key":     commonConsumerKey,
				"oauth_nonce":            "uTeLPs6K",
				"oauth_signature_method": "RSA-SHA256",
				"oauth_timestamp":        timestamp,
				"oauth_version":          "1.0",
			},
		},
		{
			name:        "Without payload",
			consumerKey: commonConsumerKey,
			payload:     `{ my: "payload" }`,
			want: map[string]string{
				"oauth_body_hash":        "Qm/nLCqwlog0uoCDvypgninzNQ25YHgTmUDl/zOgT1s=",
				"oauth_consumer_key":     commonConsumerKey,
				"oauth_nonce":            "uTeLPs6K",
				"oauth_signature_method": "RSA-SHA256",
				"oauth_timestamp":        timestamp,
				"oauth_version":          "1.0",
			},
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got, err := getOAuthParams(tC.consumerKey, tC.payload)

			if err != nil {
				t.Error(err)
			}

			if !reflect.DeepEqual(got, tC.want) {
				t.Errorf("\ngot '%v'\nwant '%v'", got, tC.want)
			}
		})
	}
}

func TestGetTimestamp(t *testing.T) {
	got := getTimestamp()

	gotNumber, err := strconv.Atoi(got)

	if err != nil {
		t.Error(err)
	}

	if gotNumber <= 0 {
		t.Errorf("got '%v', want >0", gotNumber)
	}
}

func TestGetNonce(t *testing.T) {
	regexpString := "^[a-zA-Z0-9]+$"
	r, err := regexp.Compile(regexpString)

	if err != nil {
		t.Error(err)
	}

	got, err := getNonce()

	if err != nil {
		t.Error(err)
	}

	length := len(got)

	if length != nonceLength {
		t.Errorf("got '%v' with length %v, but want length =%v", got, length, nonceLength)
	}

	if !r.MatchString(got) {
		t.Errorf("got '%v', which didn't match regexp '%v'", got, regexpString)
	}
}

func TestGetBodyHash(t *testing.T) {
	testCases := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "Empty string",
			payload: "",
			want:    "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
		},
		{
			name:    "String",
			payload: `{ my: "payload" }`,
			want:    "Qm/nLCqwlog0uoCDvypgninzNQ25YHgTmUDl/zOgT1s=",
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got := getBodyHash(tC.payload)

			if got != tC.want {
				t.Errorf("\ngot '%v'\nwant '%v'", got, tC.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	array := []string{"Brad", "John", "Anna"}

	testCases := []struct {
		name    string
		array   []string
		element string
		want    bool
	}{
		{
			name:    "Exist",
			array:   array,
			element: "John",
			want:    true,
		},
		{
			name:    "Doesn't exist",
			array:   array,
			element: "Joshua",
			want:    false,
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got := contains(tC.array, tC.element)

			if got != tC.want {
				t.Errorf("\ngot '%v'\nwant'%v'", got, tC.want)
			}
		})
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	testCases := []struct {
		name   string
		length int
	}{
		{
			name:   "Length 6",
			length: 6,
		},
		{
			name:   "Length 8",
			length: 8,
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got, err := generateRandomBytes(tC.length)

			if err != nil {
				t.Error(err)
			}

			if len(got) != tC.length {
				t.Errorf("got length %v, want %v", len(got), tC.length)
			}
		})
	}
}
