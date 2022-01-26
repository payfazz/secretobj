package secretobj

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/payfazz/go-errors/v2"
	"gopkg.in/square/go-jose.v2"
)

type Encryption struct {
	key []byte
	enc jose.Encrypter
}

func New(key string) (*Encryption, error) {
	sum := sha256.Sum256([]byte(key))
	keyBytes := sum[:16]
	enc, err := jose.NewEncrypter(
		jose.A128GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       keyBytes,
		},
		nil,
	)
	if err != nil {
		return nil, errors.Trace(err)
	}
	return &Encryption{
		key: keyBytes,
		enc: enc,
	}, nil
}

func (c *Encryption) Encrypt(msg interface{}) (string, error) {
	bytes, err := json.Marshal(msg)
	if err != nil {
		return "", errors.Trace(err)
	}

	jwe, err := c.enc.Encrypt(bytes)
	if err != nil {
		return "", errors.Trace(err)
	}

	compactJwe, err := jwe.CompactSerialize()
	if err != nil {
		return "", errors.Trace(err)
	}

	return compactJwe, nil
}

func (c *Encryption) Decrypt(msg string, target interface{}) error {
	jwe, err := jose.ParseEncrypted(msg)
	if err != nil {
		return errors.Trace(err)
	}

	if jwe.Header.Algorithm != string(jose.DIRECT) || jwe.Header.ExtraHeaders["enc"] != string(jose.A128GCM) {
		return errors.Errorf("invalid alg or enc header")
	}

	data, err := jwe.Decrypt(c.key)
	if err != nil {
		return errors.Trace(err)
	}

	if err := json.Unmarshal(data, target); err != nil {
		return errors.Trace(err)
	}

	return nil
}
