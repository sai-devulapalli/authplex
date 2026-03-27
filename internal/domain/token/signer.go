package token

// Signer creates signed JWT strings from claims.
type Signer interface {
	Sign(claims Claims, kid string, privateKeyPEM []byte, algorithm string) (string, error)
}
