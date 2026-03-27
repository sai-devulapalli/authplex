package jwk

// Generator is the port interface for cryptographic key pair generation.
type Generator interface {
	GenerateRSA() (privateKeyPEM []byte, publicKeyPEM []byte, err error)
	GenerateEC() (privateKeyPEM []byte, publicKeyPEM []byte, err error)
}
