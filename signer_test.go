package signer

import (
	"reflect"
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
		t.Run(tC.name, func(t *testing.T) {
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
			uri:  "https://google.com/?test=true",
			want: map[string][]string{"test": []string{"true"}},
		},
		{
			name: "Complex uri",
			uri:  "https://google.com/?https://sandbox.api.mastercard.com/merchantid/v1/merchantid?MerchantId=GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29&Format=XML&Type=ExactMatch&Format=JSON&EmptyVal=",
			want: map[string][]string{
				"EmptyVal":   []string{""},
				"Format":     []string{"JSON", "XML"},
				"MerchantId": []string{"GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29"},
				"Type":       []string{"ExactMatch"},
			},
		},
	}

	for _, tC := range testCases {
		t.Run(tC.name, func(t *testing.T) {
			got, err := extractQueryParams(tC.uri)

			if err != nil {
				t.Error(err)
			}

			if !reflect.DeepEqual(got, tC.want) {
				t.Errorf("got '%v' want '%v'", got, tC.want)
			}
		})
	}
}
