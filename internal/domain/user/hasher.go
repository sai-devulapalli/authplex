package user

// PasswordHasher is the port interface for password hashing.
// The adapter (BcryptHasher) implements both this and client.SecretHasher.
type PasswordHasher interface {
	Hash(password string) ([]byte, error)
	Verify(password string, hash []byte) error
}
