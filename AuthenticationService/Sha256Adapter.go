package AuthenticationService

import "crypto/sha256"

type Sha256Adapter struct {
}

func (s Sha256Adapter) computeHash(password string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		return "", err
	}
	hashedPassword := string(hash.Sum(nil))
	return hashedPassword, nil
}
