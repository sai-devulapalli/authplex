package jwk

// Converter transforms PEM-encoded public keys into PublicJWK format.
type Converter interface {
	PEMToPublicJWK(publicKeyPEM []byte, kid string, alg string) (PublicJWK, error)
}
