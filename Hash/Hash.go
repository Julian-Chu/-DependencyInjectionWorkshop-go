package Hash

import "crypto/sha256"

type IHash interface {
	Compute(password string) (string, error)
}

type Sha256Adapter struct {
}

func (s Sha256Adapter) Compute(password string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		return "", err
	}
	hashedPassword := string(hash.Sum(nil))
	return hashedPassword, nil
}
