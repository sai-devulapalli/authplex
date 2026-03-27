package client

// SecretHasher is the port interface for client secret hashing.
type SecretHasher interface {
	Hash(secret string) ([]byte, error)
	Verify(secret string, hash []byte) error
}
