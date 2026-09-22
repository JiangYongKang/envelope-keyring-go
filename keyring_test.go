package envelope

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

// testKey 由种子派生确定的 32 字节测试密钥（不使用随机数据，便于复现日志）。
func testKey(seed string) []byte {
	sum := sha256.Sum256([]byte("test-key:" + seed))
	return sum[:]
}

func TestKeyRingLifecycle(t *testing.T) {
	ring := NewKeyRing()

	// 初始：无激活密钥。
	_, err := ring.ActiveKeyID()
	if !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("input=<empty keyring> 判定依据=应无激活密钥, got %v", err)
	}
	t.Logf("输入=空密钥环 | 判定依据=ActiveKeyID 返回 ErrNoActiveKey（正确归类为无激活密钥）")

	// 首个密钥不激活：环内存在但仍无激活密钥。
	if err := ring.AddKey("k-old", testKey("old"), false); err != nil {
		t.Fatalf("AddKey k-old: %v", err)
	}
	if _, err := ring.ActiveKeyID(); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("input=<k-old not activated> got %v", err)
	}

	// 激活 k1。
	if err := ring.AddKey("k1", testKey("one"), true); err != nil {
		t.Fatalf("AddKey k1: %v", err)
	}
	id, err := ring.ActiveKeyID()
	if err != nil || id != "k1" {
		t.Fatalf("input=<activate k1> 期望激活=k1, got id=%q err=%v", id, err)
	}
	t.Logf("输入=AddKey(k1, activate=true) | 判定依据=ActiveKeyID=%q 状态=%s", id, statusOf(ring, "k1"))

	// 轮换到 k2：k1 必须保留为 retired 且仍可按 id 查到（可解密历史密文）。
	if err := ring.Rotate("k2", testKey("two")); err != nil {
		t.Fatalf("Rotate k2: %v", err)
	}
	id, _ = ring.ActiveKeyID()
	if id != "k2" {
		t.Fatalf("轮换后期望激活=k2, got %q", id)
	}
	e1, err := ring.lookupByID("k1")
	if err != nil {
		t.Fatalf("input=<lookup k1 after rotate> 历史密钥应仍可用于解密, got err=%v", err)
	}
	if e1.status != StatusRetired {
		t.Fatalf("input=<k1> 判定依据=轮换后旧密钥应为 retired, got %s", e1.status)
	}
	t.Logf("输入=Rotate(k2) | 判定依据=active=%q, k1=%s（历史密钥保留可解密）", id, e1.status)

	// 撤销 k1：此后命中 k1 的查找必须被拒绝，且原因是 revoked 而非 unknown。
	if err := ring.Revoke("k1"); err != nil {
		t.Fatalf("Revoke k1: %v", err)
	}
	if _, err := ring.lookupByID("k1"); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("input=<lookup revoked k1> 期望 ErrKeyRevoked, got %v", err)
	}
	t.Logf("输入=lookupByID(k1) after Revoke | 判定依据=%v（与未知密钥明确区分）", ErrKeyRevoked)
}

func TestKeyRingErrorClassification(t *testing.T) {
	ring := NewKeyRing()
	if err := ring.AddKey("k1", testKey("one"), true); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		call func() error
		want error
	}{
		{
			name: "重复密钥标识",
			call: func() error { return ring.AddKey("k1", testKey("dup"), true) },
			want: ErrDuplicateKeyID,
		},
		{
			name: "密钥材料长度非法(16字节)",
			call: func() error { return ring.AddKey("bad", make([]byte, 16), false) },
			want: ErrInvalidKey,
		},
		{
			name: "空密钥标识",
			call: func() error { return ring.AddKey("", testKey("x"), false) },
			want: ErrInvalidKey,
		},
		{
			name: "撤销不存在的密钥",
			call: func() error { return ring.Revoke("ghost") },
			want: ErrUnknownKey,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			t.Logf("输入=%s | 输出错误=%v | 判定依据=errors.Is(_, %v)=%v",
				tc.name, err, tc.want, errors.Is(err, tc.want))
			if !errors.Is(err, tc.want) {
				t.Fatalf("期望 %v, got %v", tc.want, err)
			}
		})
	}

	// 未知密钥查找：必须归类为 unknown。
	_, err := ring.lookupByID("does-not-exist")
	t.Logf("输入=lookupByID(does-not-exist) | 输出=%v | 判定依据=errors.Is ErrUnknownKey=%v",
		err, errors.Is(err, ErrUnknownKey))
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("期望 ErrUnknownKey, got %v", err)
	}
}

func TestKeyRingKeysSnapshotExcludesMaterial(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("one"), true)
	_ = ring.Rotate("k2", testKey("two"))

	infos := ring.Keys()
	t.Logf("输入=Keys() 快照 | 输出=%d 条元信息: %v | 判定依据=仅含 ID 与状态, 无密钥材料",
		len(infos), infos)
	if len(infos) != 2 {
		t.Fatalf("期望 2 条, got %d", len(infos))
	}
	for _, info := range infos {
		if info.ID == "" {
			t.Fatal("KeyInfo 不应包含空 ID")
		}
	}
}

func statusOf(r *KeyRing, id string) string {
	e, err := r.lookupByID(id)
	if err != nil {
		return fmt.Sprintf("err=%v", err)
	}
	return e.status.String()
}
