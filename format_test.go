package envelope

import (
	"encoding/binary"
	"errors"
	"testing"
)

// TestFormatV1V2Mixed 新写为 V2；历史 V1 密文仍能读取，两者在同一密钥环混用。
func TestFormatV1V2Mixed(t *testing.T) {
	kr := NewKeyring()
	_ = kr.AddKey("k", newKey(t), true)
	c := NewEnvelopeCipher(kr)

	v1CT, err := c.encryptWithVersion(formatV1, []byte("legacy-payload"), []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	v2CT, err := c.Encrypt([]byte("current-payload"), []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	if v1CT[4] != byte(formatV1) || v2CT[4] != byte(formatV2) {
		t.Fatalf("version bytes: got v1=%d v2=%d", v1CT[4], v2CT[4])
	}
	t.Logf("V1 密文 len=%d versionByte=%d；V2 密文 len=%d versionByte=%d（keyID 长度前缀不同）",
		len(v1CT), v1CT[4], len(v2CT), v2CT[4])

	// V1/V2 解码后的 keyID 长度前缀布局不同但都应正确解析。
	p1, err := decode(v1CT)
	if err != nil {
		t.Fatalf("decode v1: %v", err)
	}
	p2, err := decode(v2CT)
	if err != nil {
		t.Fatalf("decode v2: %v", err)
	}
	if p1.keyID != "k" || p2.keyID != "k" {
		t.Fatalf("key ids: %q %q", p1.keyID, p2.keyID)
	}

	// 同一密钥环下两种格式都能解出原文。
	pt1, err := c.Decrypt(v1CT, []byte("a"))
	if err != nil {
		t.Fatalf("decrypt v1: %v", err)
	}
	pt2, err := c.Decrypt(v2CT, []byte("a"))
	if err != nil {
		t.Fatalf("decrypt v2: %v", err)
	}
	if string(pt1) != "legacy-payload" || string(pt2) != "current-payload" {
		t.Fatalf("plaintexts: %q %q", pt1, pt2)
	}
	t.Logf("判定依据: 按版本字节分流解析，V1 用 uint8 keyID 长度，V2 用 uint16；两层认证均通过")
}

// TestV2LongerKeyID V2 的格式演进入口价值：支持超过 255 字节的 keyID，V1 拒绝。
func TestV2LongerKeyID(t *testing.T) {
	longID := make([]byte, 256)
	for i := range longID {
		longID[i] = 'z'
	}
	kr := NewKeyring()
	if err := kr.AddKey(string(longID), newKey(t), true); err != nil {
		t.Fatal(err)
	}
	c := NewEnvelopeCipher(kr)
	ct, err := c.Encrypt([]byte("x"), nil)
	if err != nil {
		t.Fatalf("v2 with 256-byte key id: %v", err)
	}
	if ct[4] != byte(formatV2) {
		t.Fatalf("want v2, got %d", ct[4])
	}
	if _, err := c.encryptWithVersion(formatV1, []byte("x"), nil); err == nil {
		t.Fatal("v1 must reject key id longer than 255")
	}
	t.Logf("判定依据: 256 字节 keyID 超出 V1 uint8 上限，V2 uint16 可容纳")
}

// TestUnsupportedVersionRejected 无法识别的版本字节必须明确拒绝。
func TestUnsupportedVersionRejected(t *testing.T) {
	kr := NewKeyring()
	_ = kr.AddKey("k", newKey(t), true)
	c := NewEnvelopeCipher(kr)
	ct, _ := c.Encrypt([]byte("x"), nil)

	bogus := make([]byte, len(ct))
	copy(bogus, ct)
	bogus[4] = 99
	_, err := c.Decrypt(bogus, nil)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
	t.Logf("输入版本字节=99 => 判定 %v：版本不在 {{1,2}，拒绝按当前格式误解析", err)
}

// TestTamperClassifications 各部位篡改必须归类为可区分原因。
func TestTamperClassifications(t *testing.T) {
	kr := NewKeyring()
	_ = kr.AddKey("k", newKey(t), true)
	c := NewEnvelopeCipher(kr)
	ct, _ := c.Encrypt([]byte("payload-1234"), []byte("aad"))

	// 1) 翻转末尾密文/标签字节 => ErrCiphertextTampered
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF
	_, err := c.Decrypt(tampered, []byte("aad"))
	if !errors.Is(err, ErrCiphertextTampered) {
		t.Fatalf("payload tamper: want ErrCiphertextTampered, got %v", err)
	}
	t.Logf("翻转密文末字节 => %v（数据层 GCM 认证失败，拒绝返回明文）", err)

	// 2) 篡改封装 DEK 段 => ErrCiphertextTampered
	p, _ := decode(ct)
	wrapStart := 5 + 1 + len(p.keyID) + len(p.nonce) // V2: magic4+ver1+idLen2
	// 用 encode 的真实头长度重新定位：直接重解码计算偏移
	off := headerLen(ct)
	t2 := make([]byte, len(ct))
	copy(t2, ct)
	t2[off+2] ^= 0x01 // wrapped DEK 第 3 字节
	_ = wrapStart
	_, err = c.Decrypt(t2, []byte("aad"))
	if !errors.Is(err, ErrCiphertextTampered) {
		t.Fatalf("wrapped DEK tamper: want ErrCiphertextTampered, got %v", err)
	}
	t.Logf("翻转 wrappedDEK 字节 => %v（封装层 GCM 认证失败，DEK 解不出）", err)

	// 3) AAD 不一致 => ErrCiphertextTampered
	_, err = c.Decrypt(ct, []byte("different-aad"))
	if !errors.Is(err, ErrCiphertextTampered) {
		t.Fatalf("aad mismatch: want ErrCiphertextTampered, got %v", err)
	}
	t.Logf("AAD 从 'aad' 变为 'different-aad' => %v（封装层绑定 AAD）", err)
}

// TestInvalidFormatInputs 结构非法的输入一律 ErrInvalidFormat，且不得 panic。
func TestInvalidFormatInputs(t *testing.T) {
	kr := NewKeyring()
	_ = kr.AddKey("k", newKey(t), true)
	c := NewEnvelopeCipher(kr)

	cases := map[string][]byte{
		"nil":                nil,
		"empty":              {},
		"short":              []byte("EN"),
		"bad magic":          []byte("XXXX\x02"),
		"truncated header":   append([]byte("ENVK"), 0x02, 0x00, 0x05, 'k'),
		"valid-magic-then-1": []byte("ENVK"),
	}
	for name, in := range cases {
		_, err := c.Decrypt(in, nil)
		if !errors.Is(err, ErrInvalidFormat) {
			t.Fatalf("%s: want ErrInvalidFormat, got %v", name, err)
		}
		t.Logf("输入 %-18q len=%d => %v", name, len(in), err)
	}

	// V1 声称 20 字节 keyID 但输入不足。
	badV1 := []byte("ENVK")
	badV1 = append(badV1, 0x01, 20, 'k')
	_, err := c.Decrypt(badV1, nil)
	if !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("truncated v1: want ErrInvalidFormat, got %v", err)
	}
	t.Logf("V1 keyID 长度声明越界 => %v", err)
}

// TestEmptyPlaintext 空明文也是合法输入。
func TestEmptyPlaintext(t *testing.T) {
	kr := NewKeyring()
	_ = kr.AddKey("k", newKey(t), true)
	c := NewEnvelopeCipher(kr)
	ct, err := c.Encrypt(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := c.Decrypt(ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pt) != 0 {
		t.Fatalf("empty plaintext: got %d bytes", len(pt))
	}
}

// headerLen 返回 V2 密文中 wrapped DEK 长度字段之前的头部字节数。
func headerLen(ct []byte) int {
	// ENVK(4) ver(1) idLen(2) id nonceLen(1) nonce(24)
	idLen := int(binary.BigEndian.Uint16(ct[5:7]))
	return 4 + 1 + 2 + idLen + 1 + 24
}
