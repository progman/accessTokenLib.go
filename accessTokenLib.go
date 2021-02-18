//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
// Laravel              - https://laravel.com
// Laravel Passport     - https://laravel.com/docs/passport
// League OAuth2 server - https://github.com/thephpleague/oauth2-server
// access_token         - https://github.com/lcobucci/jwt, https://tools.ietf.org/html/rfc7519
// refresh_token        - https://github.com/defuse/php-encryption
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
package accessTokenLib
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
import (
	"encoding/json"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"io/ioutil"
	"encoding/hex"
	"github.com/progman/libcore.go"
)
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * header of access token
 */
type accessTokenHead struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * body of access token
 */
type AccessTokenBody struct {
	Iss    string   `json:"iss"`    // issuer (a person or company that supplies or distributes something) - maker, https://tools.ietf.org/html/rfc7519#section-4.1.1
	Aud    string   `json:"aud"`    // client_id,                                                                   https://tools.ietf.org/html/rfc7519#section-4.1.3
	Jti    string   `json:"jti"`    // access_token_id,                                                             https://tools.ietf.org/html/rfc7519#section-4.1.7
	Iat    int      `json:"iat"`    // time of make (delete if too far of this time),                               https://tools.ietf.org/html/rfc7519#section-4.1.6
	Nbf    int      `json:"nbf"`    // time of start to work                                                        https://tools.ietf.org/html/rfc7519#section-4.1.5
	Exp    int      `json:"exp"`    // time to stop to work (delete if too far of this time),                       https://tools.ietf.org/html/rfc7519#section-4.1.4
	Sub    string   `json:"sub"`    // user_id,                                                                     https://tools.ietf.org/html/rfc7519#section-4.1.2
	Scopes []string `json:"scopes"` // ["api","paymentapi"]
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * simple show of body of access token
 */
func (p *AccessTokenBody) Show() {
	fmt.Printf("Iss:    \"%s\"\n", p.Iss)
	fmt.Printf("Aud:    \"%s\"\n", p.Aud)
	fmt.Printf("Jti:    \"%s\"\n", p.Jti)
	fmt.Printf("Iat:    %d\n", p.Iat)
	fmt.Printf("Nbf:    %d\n", p.Nbf)
	fmt.Printf("Exp:    %d\n", p.Exp)
	fmt.Printf("Sub:    \"%s\"\n", p.Sub)
	fmt.Printf("Scopes: [ ")

	for i := 0; i < len(p.Scopes); i++ {
		if i != 0 {
			fmt.Printf(", ")
		}
		fmt.Printf("\"%s\"", p.Scopes[i])
	}
	fmt.Printf(" ]\n")
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * access token lib class
 */
type AccessTokenLib struct {
	privateKey     interface{}
	publicKey      interface{}
	flagPrivateKey bool
	flagPublicKey  bool
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * init access token lib object
 */
func (p *AccessTokenLib) Init() {
	p.flagPrivateKey = false
	p.flagPublicKey  = false
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * make new token id
 * \return id new token id
 * \return err error
 */
func (p *AccessTokenLib) MakeTokenId() (id string, err error) {
	src := make([]byte, 40)
	_, err = rand.Read(src)
	if err != nil {
		return
	}


	dst := make([]byte, len(src) * 2)
	hex.Encode(dst, src)
	id = string(dst)


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * load private key from PEM file
 * \param[in] path path of private key PEM file
 * \return err error
 */
func (p *AccessTokenLib) LoadPrivateKey(path string) (err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}


	return p.ParsePrivateKey(data)
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * parse private key PEM file body
 * \param[in] pemBytes body of private key PEM file
 * \return err error
 */
func (p *AccessTokenLib) ParsePrivateKey(pemBytes []byte) (err error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		err = errors.New("ssh: no key found")
		return
	}


	if block.Type != "RSA PRIVATE KEY" {
		err = fmt.Errorf("ssh: unsupported key type %q", block.Type)
		return
	}


	rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	p.privateKey = rsa
	p.flagPrivateKey = true


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * load public key from PEM file
 * \param[in] path path of public key PEM file
 * \return err error
 */
func (p *AccessTokenLib) LoadPublicKey(path string) (err error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return
	}


	return p.ParsePublicKey(data)
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * parse public key PEM file body
 * \param[in] pemBytes body of public key PEM file
 * \return err error
 */
func (p *AccessTokenLib) ParsePublicKey(pemBytes []byte) (err error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		err = errors.New("ssh: no key found")
		return
	}


	if block.Type != "PUBLIC KEY" {
		err = fmt.Errorf("ssh: unsupported key type %q", block.Type)
		return
	}


	rsa, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}
	p.publicKey = rsa
	p.flagPublicKey = true


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * make rsa-sha256 signature for the message
 * \param[in] message source message
 * \return out rsa-sha256 signature for the message
 * \return err error
 */
func (p *AccessTokenLib) sign(message []byte) (out []byte, err error) {
	if p.flagPrivateKey == false {
		err = fmt.Errorf("private key must be loaded")
		return
	}

/*
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)
*/
	d := sha256.Sum256(message)

	return rsa.SignPKCS1v15(rand.Reader, p.privateKey.(*rsa.PrivateKey), crypto.SHA256, d)
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * verify rsa-sha256 signature for the message
 * \param[in] message source message
 * \param[in] signature rsa-sha256 signature for the message
 * \return err error
 */
func (p *AccessTokenLib) verify(message []byte, signature []byte) (err error) {
	h := sha256.New()
	h.Write(message)
	d := h.Sum(nil)


	if p.flagPublicKey == false {
		err = fmt.Errorf("public key must be loaded")
		return
	}


	return rsa.VerifyPKCS1v15(p.publicKey.(*rsa.PublicKey), crypto.SHA256, d, signature)
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * decode access token to AccessTokenBody object
 * \param[in] token access token
 * \return AccessTokenBody object
 * \return err error
 */
func (p *AccessTokenLib) Decode(pAccessTokenBody *AccessTokenBody, token []byte) (err error) {
	index1 := strings.Index(string(token), ".")
	index2 := strings.LastIndex(string(token), ".")


	if index1 == -1 {
		err = fmt.Errorf("parse error, first symbol '.' is not found")
		return
	}
	if index2 == -1 {
		err = fmt.Errorf("parse error, second symbol '.' is not found")
		return
	}
	if index1 == index2 {
		err = fmt.Errorf("parse error, second symbol '.' is not found")
		return
	}


	partA_base64url  := libcore.SubByte(token, 0, index1)
	partB_base64url  := libcore.SubByte(token, index1 + 1, index2 - index1 - 1)
	partC_base64url  := libcore.SubByte(token, index2 + 1, -1)
	partAB_base64url := libcore.SubByte(token, 0, index2)


	partA, err := base64.RawURLEncoding.DecodeString(string(partA_base64url))
	if err != nil {
		return
	}
	partB, err := base64.RawURLEncoding.DecodeString(string(partB_base64url))
	if err != nil {
		return
	}
	partC, err := base64.RawURLEncoding.DecodeString(string(partC_base64url))
	if err != nil {
		return
	}


	err = p.verify(partAB_base64url, partC)
	if err != nil {
		return
	}


	var head accessTokenHead
	err = json.Unmarshal(partA, &head)
	if err != nil {
		return
	}


	if head.Typ != "JWT" {
		err = fmt.Errorf("parse error, 'typ' is not 'JWT'")
		return
	}
	if head.Alg != "RS256" {
		err = fmt.Errorf("parse error, 'alg' is not 'RS256'")
		return
	}


	err = json.Unmarshal(partB, pAccessTokenBody)
	if err != nil {
		return
	}


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
/**
 * encode AccessTokenBody object to access token
 * \param[in] AccessTokenBody object
 * \return token access token
 * \return err error
 */
func (p *AccessTokenLib) Encode(AccessTokenBody *AccessTokenBody) (token []byte, err error) {
	var head accessTokenHead
	head.Typ = "JWT"
	head.Alg = "RS256"


	partA, err := json.Marshal(head)
	if err != nil {
		return
	}
	partB, err := json.Marshal(AccessTokenBody)
	if err != nil {
		return
	}


	partA_base64url := base64.RawURLEncoding.EncodeToString(partA)
	partB_base64url := base64.RawURLEncoding.EncodeToString(partB)


	token = append(token, partA_base64url...)
	token = append(token, []byte{'.'}...)
	token = append(token, partB_base64url...)


	partC, err := p.sign(token)
	if err != nil {
		return
	}
	partC_base64url := base64.RawURLEncoding.EncodeToString(partC)


	token = append(token, []byte{'.'}...)
	token = append(token, partC_base64url...)


	return
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------//
