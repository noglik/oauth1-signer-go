# Oauth1-signer-go NO LONGER SUPPORTED

Mastercard created own [package](https://github.com/Mastercard/oauth1-signer-go) for sign creation, so there is no point to support this any longer.

Basically just a go version of [oauth1-signer-nodejs](https://github.com/Mastercard/oauth1-signer-nodejs).

This package is partially tested with sanbox service.

## Overview

Zero dependency library for generating a Mastercard API compliant OAuth signature.

## Compatibility

Go 1.12.9

## Usage

### Prerequisites

Before using this library, you will need to set up a project in [Mastercard Developer Portal](https://developer.mastercard.com/).
As part of this setup, you'll receive credentials for your app.
- A consumer key (displayed on Mastercard Developer Portal)
- A private request signging key (matching the public certificate displayed on the Mastercard Developer Portal)

### Adding the library to your project

```bash
go get -u github.com/noglik/oauth1-signer-go
```

### Loading the Signing Key

```go
import (
  "encoding/pem"
  "io/ioutil"

  "golang.org/x/crypto/pkcs12"
)

func main() {
  data, err := ioutil.ReadFile("./your-p12-file-path.p12")

  if err != nil {
    panic(err)
  }

  blocks, err := pkcs12.ToPEM(data, "your-password")

  if err != nil {
    panic(err)
  }

  var pemData []byte

  for _, b := range blocks {
    pemData = append(pemData, pem.EncodeToMemory(b)...)
  }

  private, _ := pem.Decode(pemData)

  signingKey := pem.EncodeToMemory(private)
}
```

### Creating the OAuth authorization header

Add `signer "github.com/noglik/oauth1-signer-go"` to `import`.

```go
consumerKey := "<your consumer key>"
uri := "https://sandbox.api.mastercard.com/service"
method := http.MethodPost
payload := "Hello world!"

authHeader := signer.GetAuthorizationHeader(uri, method, payload, consumerKey, signingKey)
```
