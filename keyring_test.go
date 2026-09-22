package envelope

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// TestRotationKeepsHistoryReadable 轮换后旧密文仍用旧密钥解出，新密文用新密钥。
func TestRotationKeepsHistoryReadable(t *testing.T) {
	kr := NewKeyring()
	if err := kr.AddKey("v1", newKey(t), true); err != nil {
		t.Fatal(err)
	}
	c := NewEnvelopeCipher(kr)

	oldCT, err := c.Encrypt([]byte("before-rotation"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("轮换前: keyID=v1 加密成功, 密文版本=%d", oldCT[4])

	if err := kr.Rotate("v2", newKey(t)); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	active, err := kr.ActiveKey()
	if err != nil {
		t.Fatal(err)
	}
	if active.ID() != "v2" {
		t.Fatalf("active key = %q, want v2", active.ID())
	}
	t.Logf("轮换后: active=%q, 旧密钥保留用于解密（active=false 但未 disabled）", active.ID())

	// 历史密文解密结果必须与轮换前一致。
	got, err := c.Decrypt(oldCT, nil)
	if err != nil {
		t.Fatalf("history decrypt after rotation: %v", err)
	}
	if string(got) != "before-rotation" {
		t.Fatalf("history plaintext changed: %q", got)
	}
	t.Logf("历史密文解密稳定: 密文携带 keyID=v1，按标识选择旧 KEK，未回退到 v2")

	newCT, err := c.Encrypt([]byte("after-rotation"), nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := decode(newCT)
	if err != nil {
		t.Fatal(err)
	}
	if p.keyID != "v2" {
		t.Fatalf("new ciphertext key id = %q, want v2", p.keyID)
	}
	t.Logf("新密文由当前激活密钥封装: keyID=%q version=%d", p.keyID, p.version)
}

// TestConcurrentRotationAndCrypto 并发轮换与加解密必须安全共存。
func TestConcurrentRotationAndCrypto(t *testing.T) {
	kr := NewKeyring()
	if err := kr.AddKey("key-0", newKey(t), true); err != nil {
		t.Fatal(err)
	}
	c := NewEnvelopeCipher(kr)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 轮换者：不断追加新版本密钥。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= 30; i++ {
			if err := kr.Rotate(fmt.Sprintf("key-%d", i), newKey(t)); err != nil {
				t.Errorf("rotate key-%d: %v", i, err)
				return
			}
		}
		close(stop)
	}()

	// 加解密者：先在本 goroutine 内生成密文再解密，保证密钥始终在环中。
	wg.Add(1)
	go func() {
		defer wg.Done()
		n := 0
		for {
			select {
			case <-stop:
				t.Logf("并发加解密 goroutine 完成 %d 次往返，全部成功", n)
				return
			default:
			}
			msg := []byte(fmt.Sprintf("concurrent-%d", n))
			ct, err := c.Encrypt(msg, nil)
			if err != nil {
				t.Errorf("concurrent encrypt: %v", err)
				return
			}
			pt, err := c.Decrypt(ct, nil)
			if err != nil {
				t.Errorf("concurrent decrypt: %v", err)
				return
			}
			if string(pt) != string(msg) {
				t.Errorf("concurrent plaintext mismatch: %q != %q", pt, msg)
				return
			}
			n++
		}
	}()

	wg.Wait()
}

// TestUnknownKeyIsRejected 密文 keyID 不在环中 => ErrUnknownKey，不得回退。
func TestUnknownKeyIsRejected(t *testing.T) {
	kr := NewKeyring()
	_ = kr.AddKey("known", newKey(t), true)
	c := NewEnvelopeCipher(kr)
	ct, err := c.Encrypt([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	// 用一个全新的环（不含 known）解密。
	other := NewKeyring()
	_ = other.AddKey("different", newKey(t), true)
	_, err = NewEnvelopeCipher(other).Decrypt(ct, nil)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
	t.Logf("输入密文 keyID=known，解密环仅含 different => 判定 %v：按标识查找失败即拒绝，绝不尝试其他密钥", err)
}

// TestDisabledKeyIsRejected 历史密钥被显式停用后解密 => ErrKeyDisabled。
func TestDisabledKeyIsRejected(t *testing.T) {
	kr := NewKeyring()
	_ = kr.AddKey("old", newKey(t), true)
	c := NewEnvelopeCipher(kr)
	oldCT, _ := c.Encrypt([]byte("legacy"), nil)

	if err := kr.Rotate("new", newKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := kr.DisableKey("old"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	_, err := c.Decrypt(oldCT, nil)
	if !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("want ErrKeyDisabled, got %v", err)
	}
	t.Logf("旧密钥 old 已显式 disabled => 判定 %v：可识别标识但拒绝使用", err)

	// 激活密钥不允许直接停用。
	if err := kr.DisableKey("new"); !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("disabling active key should fail, got %v", err)
	}
	t.Logf("拒绝停用当前激活密钥 new，避免出现无密钥可用窗口")
}

// TestDuplicateAndInvalidKey 登记非法参数必须被拒绝。
func TestDuplicateAndInvalidKey(t *testing.T) {
	kr := NewKeyring()
	mat := newKey(t)
	if err := kr.AddKey("dup", mat, true); err != nil {
		t.Fatal(err)
	}
	if err := kr.AddKey("dup", newKey(t), false); err == nil {
		t.Fatal("duplicate key id must be rejected")
	}
	if err := kr.AddKey("short", make([]byte, 16), false); err == nil {
		t.Fatal("16-byte key material must be rejected")
	}
	if err := kr.AddKey("", mat, false); err == nil {
		t.Fatal("empty key id must be rejected")
	}
	if err := kr.Rotate("dup", newKey(t)); err == nil {
		t.Fatal("rotating to an existing id must be rejected")
	}
	t.Logf("重复标识/空标识/非 32 字节材料均被拒绝，判定依据为输入参数校验")
}
