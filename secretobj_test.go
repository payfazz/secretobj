package secretobj

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestEncryptDecrypt(t *testing.T) {
	type mytpe struct {
		Int    int
		Float  float64
		Map    map[string]string
		IntPtr *int
	}

	data := mytpe{
		Int:   10,
		Float: 11,
		Map: map[string]string{
			"12": "12",
			"13": "13",
		},
	}
	data.IntPtr = &data.Int

	encdec, err := New("somekey")
	if err != nil {
		t.Fatalf("cannot create encryption engine: %v", err)
	}

	encryptedData, err := encdec.Encrypt(data)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	var decryptedData mytpe
	if err := encdec.Decrypt(encryptedData, &decryptedData); err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	qt.Assert(t, decryptedData, qt.DeepEquals, data)
}
