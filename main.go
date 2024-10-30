package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/SermoDigital/jose/jws"
	"github.com/urfave/cli"
)

type JWKeys struct {
	Keys []JWKey `json:"keys"`
}

type JWKey struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`

	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	K   string `json:"k,omitempty"`
}

type JWTHeader struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

var (
	appName, appVer string
)

func main() {
	app := cli.NewApp()
	app.Name = appName
	app.HelpName = appName
	app.Usage = "Used for quick retrieval of public key from JWK"
	app.Version = appVer
	app.Copyright = ""
	app.Authors = []cli.Author{
		{
			Name: "Rafpe ( https://rafpe.ninja )",
		},
	}

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "out",
			Value: "RSA",
			Usage: "Output type ( RSA | PUBLIC )",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "from-server",
			Usage: "Get public key from JWKs from an http server",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "url",
					Usage: "URL from which details should be retrieved",
				},
				cli.StringFlag{
					Name:  "kid",
					Value: "*",
					Usage: "Select specific kid - otherwise query all",
				},
				cli.BoolFlag{
					Name:  "show-kid",
					Usage: "When more keys exists shows kid for every key",
				},
				cli.StringFlag{
					Name:  "resolver",
					Usage: "ip addr of the dns resolver",
				},
			},
			Action: cmdRetrievePublicKey,
		},
		{
			Name:  "from-token",
			Usage: "Get public key from JWKs extracted from JWT",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "token",
					Usage: "Token to be parsed",
				},
			},
			Action: cmdRetrievePublicKeyFromToken,
		},
		{
			Name:  "from-file",
			Usage: "Get public key from JWKs from file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "file",
					Usage: "File to be parsed",
				},
				cli.StringFlag{
					Name:  "kid",
					Value: "*",
					Usage: "Select specific kid - otherwise query all",
				},
				cli.BoolFlag{
					Name:  "show-kid",
					Usage: "When more keys exists shows kid for every key",
				},
			},

			Action: cmdRetrievePublicKeyFromFile,
		},
		{
			Name:  "from-stdin",
			Usage: "Get public key from JWKs from standard input",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "kid",
					Value: "*",
					Usage: "Select specific kid - otherwise query all",
				},
				cli.BoolFlag{
					Name:  "show-kid",
					Usage: "When more keys exists shows kid for every key",
				},
			},

			Action: cmdRetrievePublicKeyFromStdin,
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	app.Action = func(c *cli.Context) error {

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

func cmdRetrievePublicKeyFromToken(c *cli.Context) error {
	verifyArgumentByName(c, "token")
	token := c.String("token")

	// Parse token to get issuer information
	parsedJWT, err := jws.ParseJWT([]byte(token))
	if err != nil {
		return err
	}

	// Customize URL to match Okta
	issuer, _ := parsedJWT.Claims().Issuer()
	url := issuer + "/v1/keys"

	// Get kid from our JWT
	decoded, _ := base64.StdEncoding.DecodeString(strings.Split(token, ".")[0])
	jwtHeader := JWTHeader{}
	json.Unmarshal([]byte(string(decoded)+"}"), &jwtHeader)

	// retrrieve JWKs from the server
	byteArr, err := getJWK(url)
	jwsKeys := JWKeys{}
	if err = json.Unmarshal([]byte(byteArr), &jwsKeys); err != nil {
		return fmt.Errorf("failed to unmarshal jwsKeys: %w", err)
	}

	// Extract public key
	extractPublicKeyFromJWK(jwsKeys, c.GlobalString("out"), jwtHeader.Kid, c.Bool("show-kid"))

	return nil
}

func cmdRetrievePublicKey(c *cli.Context) error {
	verifyArgumentByName(c, "url")
	url := c.String("url")
	resolver := c.String("resolver")
	if resolver != "" {
		changeResolver(resolver)
	}
	// Call to retrieve JWKs - this assumes full URL has been given
	// to path where JWKs are to be retrieved from
	byteArr, err := getJWK(url)
	if err != nil {
		return fmt.Errorf("failed to get jwk: %w", err)
	}

	// retrrieve JWKs from the server
	jwsKeys := JWKeys{}
	if err = json.Unmarshal([]byte(byteArr), &jwsKeys); err != nil {
		fmt.Println(err)
	}

	// Extract public key
	extractPublicKeyFromJWK(jwsKeys, c.GlobalString("out"), c.String("kid"), c.Bool("show-kid"))

	return nil
}

func cmdRetrievePublicKeyFromFile(c *cli.Context) error {
	verifyArgumentByName(c, "file")
	fileName := c.String("file")

	// Call to retrieve JWKs - this assumes full URL has been given
	// to path where JWKs are to be retrieved from
	data, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}
	// retrieve JWKs from the server
	jwsKeys := JWKeys{}
	if err = json.Unmarshal(data, &jwsKeys); err != nil {
		return fmt.Errorf("failed to unmarshal json content: %w ", err)
	}
	// Extract public key
	extractPublicKeyFromJWK(jwsKeys, c.GlobalString("out"), c.String("kid"), c.Bool("show-kid"))

	return nil
}

func cmdRetrievePublicKeyFromStdin(c *cli.Context) error {

	data := make([]byte, 0)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		data = append(data, scanner.Bytes()...)
	}

	if scanner.Err() != nil {
		return fmt.Errorf("failed to read stdin: %v", scanner.Err())
	}

	// retrieve JWKs from the server
	jwsKeys := JWKeys{}
	if err := json.Unmarshal(data, &jwsKeys); err != nil {
		return fmt.Errorf("failed to unmarshal json content: %w ", err)
	}
	// Extract public key
	extractPublicKeyFromJWK(jwsKeys, c.GlobalString("out"), c.String("kid"), c.Bool("show-kid"))

	return nil
}

// getJWK  retrieves JWKs from the provided URL
func getJWK(url string) ([]byte, error) {

	client := http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	byt, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return byt, nil

}

func extractPublicKeyFromJWK(jwks JWKeys, outType, kid string, showKid bool) {
	for _, singleJWK := range jwks.Keys {
		if kid != "*" && kid != singleJWK.Kid {
			continue
		}

		//  c.Bool("show-kid")
		if showKid {
			fmt.Println(fmt.Sprintf("KID: %s", singleJWK.Kid))
		}

		if singleJWK.Kty != "RSA" {
			log.Fatal("invalid key type:", singleJWK.Kty)
		}

		// decode the base64 bytes for n
		nb, err := base64.RawURLEncoding.DecodeString(singleJWK.N)
		if err != nil {
			log.Fatal(err)
		}

		e := 0
		// The default exponent is usually 65537, so just compare the
		// base64 for [1,0,1] or [0,1,0,1]
		if singleJWK.E == "AQAB" || singleJWK.E == "AAEAAQ" {
			e = 65537
		} else {
			// need to decode "e" as a big-endian int
			log.Fatal("need to deocde e:", singleJWK.E)
		}

		pk := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: e,
		}

		der, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			log.Fatal(err)
		}

		// Define the output type of our key
		outputType := ""
		switch outType {
		case "RSA":
			outputType = "RSA PUBLIC KEY"
		case "PUBLIC":
			outputType = "PUBLIC KEY"
		}

		block := &pem.Block{
			Type:  outputType,
			Bytes: der,
		}

		var out bytes.Buffer
		pem.Encode(&out, block)
		fmt.Println(out.String())

	}
}

// verifyArgumentByName helper function to display information about
//
//	missing arguments
func verifyArgumentByName(c *cli.Context, argName string) {
	if c.String(argName) == "" {
		log.Fatal(fmt.Sprintf("Please provide required argument(s)! [ %s ]", argName))
	}
}

func changeResolver(dnsResolverIP string) {
	fmt.Println("resolver ip:", dnsResolverIP)
	var (
		dnsResolverProto     = "udp" // Protocol to use for the DNS resolver
		dnsResolverTimeoutMs = 5000  // Timeout (ms) for the DNS resolver (optional)
	)

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(dnsResolverTimeoutMs) * time.Millisecond,
				}
				return d.DialContext(ctx, dnsResolverProto, dnsResolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	http.DefaultTransport.(*http.Transport).DialContext = dialContext

}
