package envelope

import (
	"crypto/rand"
	"testing"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, keyMaterialLen)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	kr := NewKeyring()
	if err := kr.AddKey("k1", newKey(t), true); err != nil {
		t.Fatalf("add key: %v", err)
	}
	c := NewEnvelopeCipher(kr)
	pt := []byte("hello envelope keyring")
	aad := []byte("tenant-42")
	ct, err := c.Encrypt(pt, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	t.Logf("input=%q aad=%q => ciphertext(len=%d, version=%d) 判断依据: 密文头魔数/版本/keyID 自描述",
		string(pt), string(aad), len(ct), ct[4])
	got, err := c.Decrypt(ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, pt)
	}
	t.Logf("decrypt 成功: 按密文携带 keyID=%q 选择 KEK，两层 GCM 均通过认证", "k1")
}
