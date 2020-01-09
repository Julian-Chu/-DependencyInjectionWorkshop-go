package AuthenticationService

import "crypto/sha256"

type IHash interface {
	compute(password string) (string, error)
}

type Sha256Adapter struct {
}

func (s Sha256Adapter) compute(password string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		return "", err
	}
	hashedPassword := string(hash.Sum(nil))
	return hashedPassword, nil
}
