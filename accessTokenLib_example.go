package accessTokenLib // killme and uncomment example
/*
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
package main
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
import (
	"fmt"
	"os"
	"github.com/progman/accessTokenLib.go"
)
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
func main() {
	var err error
	var atl accessTokenLib.AccessTokenLib
	atl.Init()


// set private key
	err = atl.LoadPrivateKey("resource/oauth-private.key")
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}


// set public key
	err = atl.LoadPublicKey("resource/oauth-public.key")
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}


// prepare access token body
	var accessTokenBody accessTokenLib.AccessTokenBody
	accessTokenBody.Iss    = ""
	accessTokenBody.Aud    = "2"
	accessTokenBody.Jti    = "6c2fc5e3c7f5fd944203b94418263cac4575ffd4d5ab69230938d434f3d7297701a3e700026d4e92" // use MakeTokenId()
	accessTokenBody.Iat    = 1607336111
	accessTokenBody.Nbf    = 1607336111
	accessTokenBody.Exp    = 1607336711
	accessTokenBody.Sub    = "16"
	accessTokenBody.Scopes = append(accessTokenBody.Scopes, "api")
	accessTokenBody.Scopes = append(accessTokenBody.Scopes, "paymentapi")


// show access token body
	accessTokenBody.Show()


// encode access token
	fmt.Printf("\n --- Encode...\n")
	access_token, err := atl.Encode(&accessTokenBody)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}


// show access token
	fmt.Printf("access token: %s\n", string(access_token))


// decode access token
	fmt.Printf("\n --- Decode...\n")
	err = atl.Decode(&accessTokenBody, access_token)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		os.Exit(1)
	}


// show access token body
	accessTokenBody.Show()


	os.Exit(0)
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
*/
