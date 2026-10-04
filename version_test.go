package envelope

import (
	"encoding/binary"
	"errors"
	"testing"
)

// 本文件验证“同一份密文只能按它自己声明的版本理解”：
//   - 把一种版本的密文按另一种版本布局重新拼装，不得被当作合法密文打开；
//   - 不认识的版本号明确拒绝。
//
// 三个版本的 AAD 使用相互独立的域，且 v3 正文 AAD 是完整头部原文，
// 因此即使字节恰好能按另一版本解析，GCM 标签也无法通过。

// repackV1AsV2 将一份合法 v1 密文的字段按 v2 布局重新拼装：
// 插入 FLAGS=0、把 1 字节 KEYIDLEN 扩为 2 字节、NONCELEN(1)=12、TIMESTAMP=0。
func repackV1AsV2(t *testing.T, v1raw []byte) []byte {
	t.Helper()
	env, err := parseEnvelope(v1raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.version != FormatV1 {
		t.Fatal("输入必须是 v1")
	}
	out := make([]byte, 0)
	out = append(out, formatMagic[:]...)
	out = append(out, FormatV2)
	out = append(out, 0) // FLAGS
	out = binary.BigEndian.AppendUint16(out, uint16(len(env.keyID)))
	out = append(out, env.keyID...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(env.encDEK)))
	out = append(out, env.encDEK...)
	out = append(out, byte(len(env.nonce))) // v2 NONCELEN 为 1 字节
	out = append(out, env.nonce...)
	out = append(out, make([]byte, 8)...) // TIMESTAMP=0
	out = append(out, env.ciphertext...)
	return out
}

// repackV2AsV1 将一份合法 v2 密文按 v1 布局重新拼装（去掉 FLAGS/TIMESTAMP/长度扩展）。
func repackV2AsV1(t *testing.T, v2raw []byte) []byte {
	t.Helper()
	env, err := parseEnvelope(v2raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.version != FormatV2 {
		t.Fatal("输入必须是 v2")
	}
	if len(env.keyID) > 255 || len(env.nonce) != v1NonceSize {
		t.Skip("该重排仅覆盖 v1 可表达字段范围")
	}
	out := make([]byte, 0)
	out = append(out, formatMagic[:]...)
	out = append(out, FormatV1)
	out = append(out, byte(len(env.keyID)))
	out = append(out, env.keyID...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(env.encDEK)))
	out = append(out, env.encDEK...)
	out = append(out, env.nonce...) // v1 nonce 定长 12
	out = append(out, env.ciphertext...)
	return out
}

// repackV3AsV2 将合法 v3 密文的字段按 v2 布局重拼：
// NONCELEN 2 字节缩为 1 字节、丢弃 CTX/CTXLEN 与 TIMESTAMP 重定位。
func repackV3AsV2(t *testing.T, v3raw []byte) []byte {
	t.Helper()
	env, err := parseEnvelope(v3raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.version != FormatV3 {
		t.Fatal("输入必须是 v3")
	}
	if len(env.nonce) > 255 {
		t.Skip("nonce 超出 v2 单字节长度")
	}
	out := make([]byte, 0)
	out = append(out, formatMagic[:]...)
	out = append(out, FormatV2)
	out = append(out, env.flags)
	out = binary.BigEndian.AppendUint16(out, uint16(len(env.keyID)))
	out = append(out, env.keyID...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(env.encDEK)))
	out = append(out, env.encDEK...)
	out = append(out, byte(len(env.nonce)))
	out = append(out, env.nonce...)
	out = binary.BigEndian.AppendUint64(out, uint64(env.timestamp))
	// 注意：v3 的 CTX 字段被直接丢弃。
	out = append(out, env.ciphertext...)
	return out
}

// repackV2AsV3 将合法 v2 密文按 v3 布局重拼：NONCELEN 扩 2 字节、插入空 CTX。
func repackV2AsV3(t *testing.T, v2raw []byte) []byte {
	t.Helper()
	env, err := parseEnvelope(v2raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.version != FormatV2 {
		t.Fatal("输入必须是 v2")
	}
	out := make([]byte, 0)
	out = append(out, formatMagic[:]...)
	out = append(out, FormatV3)
	out = append(out, env.flags)
	out = binary.BigEndian.AppendUint16(out, uint16(len(env.keyID)))
	out = append(out, env.keyID...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(env.encDEK)))
	out = append(out, env.encDEK...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(env.nonce)))
	out = append(out, env.nonce...)
	out = binary.BigEndian.AppendUint16(out, 0) // CTXLEN=0
	out = binary.BigEndian.AppendUint64(out, uint64(env.timestamp))
	out = append(out, env.ciphertext...)
	return out
}

// TestCrossVersionRepackRejected：四种跨版本重排全部不得打开。
func TestCrossVersionRepackRejected(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("repack"), true)
	k1, _ := ring.lookupByID("k1")
	svc := NewEnvelopeService(ring)

	v1ct := sealVersion(t, k1, []byte("born-v1"), FormatV1, 10)
	v2ct := sealVersion(t, k1, []byte("born-v2"), FormatV2, 11)
	v3ct := sealV3(t, k1, []byte("born-v3"), []byte("repack-ctx"), 12)

	cases := []struct {
		name string
		raw  []byte
	}{
		{"v1 字段按 v2 布局重拼", repackV1AsV2(t, v1ct)},
		{"v2 字段按 v1 布局重拼", repackV2AsV1(t, v2ct)},
		{"v3 字段按 v2 布局重拼(丢弃CTX)", repackV3AsV2(t, v3ct)},
		{"v2 字段按 v3 布局重拼(插入空CTX)", repackV2AsV3(t, v2ct)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			declared := tc.raw[magicSize]
			_, err := svc.OpenWithContext(tc.raw, []byte("repack-ctx"))
			// 重排后 v3 上下文非空会先命中 ErrContextMismatch；再以空上下文试一次，
			// 真正验证“跨版本重排无法通过密码学校验”。
			if errors.Is(err, ErrContextMismatch) {
				_, err = svc.Open(tc.raw)
			}
			t.Logf("输入=%s，重排后声明版本=0x%02x | 输出=%v | 判定依据=必须拒绝(版本专属 AAD 域不匹配)",
				tc.name, declared, err)
			if err == nil {
				t.Fatalf("%s 竟然被当作合法 v%d 密文打开", tc.name, declared)
			}
			// 结构层面可能先报格式非法；能解析则必然在 GCM 处失败。
			if !errors.Is(err, ErrCiphertextModified) && !errors.Is(err, ErrMalformedCiphertext) {
				t.Fatalf("%s: 期望认证失败/格式非法, got %v", tc.name, err)
			}
		})
	}

	// 控制组：三份原始密文各自按自己声明的版本正常打开。
	if pt, err := svc.Open(v1ct); err != nil || string(pt) != "born-v1" {
		t.Fatalf("v1 控制组: pt=%q err=%v", pt, err)
	}
	if pt, err := svc.Open(v2ct); err != nil || string(pt) != "born-v2" {
		t.Fatalf("v2 控制组: pt=%q err=%v", pt, err)
	}
	if pt, err := svc.OpenWithContext(v3ct, []byte("repack-ctx")); err != nil || string(pt) != "born-v3" {
		t.Fatalf("v3 控制组: pt=%q err=%v", pt, err)
	}
	t.Log("判定依据=控制组: v1/v2/v3 原始密文按自身版本均正常，明文无漂移")
}

// TestUnknownVersionRejected：魔数正确、版本号不属于 v1/v2/v3 时明确拒绝。
func TestUnknownVersionRejected(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("unkver"), true)
	svc := NewEnvelopeService(ring)
	ct, err := svc.SealWithContext([]byte("ver"), []byte("c"))
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range []byte{0x00, 0x04, 0x10, 0x7F, 0xFE, 0xFF} {
		bad := append([]byte{}, ct...)
		bad[magicSize] = v
		_, err := svc.Open(bad)
		t.Logf("输入=版本字节=0x%02x | 输出=%v | 判定依据=ErrUnsupportedVersion", v, err)
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("版本 0x%02x: 期望 ErrUnsupportedVersion, got %v", v, err)
		}
	}
}

// TestV3TamperedKeyIDCannotFallback：v3 头部 keyID 是自声明字段，
// 改它无法借用别的密钥解开，且头部受正文 AAD 逐字节保护。
func TestV3TamperedKeyIDCannotFallback(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("v3fb1"), true)
	_ = ring.Rotate("k2", testKey("v3fb2"))
	k1, _ := ring.lookupByID("k1")
	svc := NewEnvelopeService(ring)

	ctx := []byte("fallback-ctx")
	ct := sealV3(t, k1, []byte("v3-bound-k1"), ctx, 7)

	// KEYID 起点：MAGIC(4)+VER(1)+FLAGS(1)+KEYIDLEN(2)
	off := magicSize + 1 + 1 + 2

	t.Run("改写成另一个环内密钥 k2", func(t *testing.T) {
		bad := append([]byte{}, ct...)
		copy(bad[off:], "k2")
		_, err := svc.OpenWithContext(bad, ctx)
		t.Logf("输入=v3 keyID k1->k2 | 输出=%v | 判定依据=版本专属 AAD/头部认证阻止借用 k2", err)
		if err == nil {
			t.Fatal("改写 keyID 后不应解密成功")
		}
		if !errors.Is(err, ErrCiphertextModified) {
			t.Fatalf("期望 ErrCiphertextModified, got %v", err)
		}
	})

	t.Run("改写成不存在的标识", func(t *testing.T) {
		bad := append([]byte{}, ct...)
		copy(bad[off:], "zz")
		_, err := svc.OpenWithContext(bad, ctx)
		t.Logf("输入=v3 keyID k1->zz | 输出=%v | 判定依据=查表未命中 ErrUnknownKey", err)
		if !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("期望 ErrUnknownKey, got %v", err)
		}
	})

	// 控制组。
	if pt, err := svc.OpenWithContext(ct, ctx); err != nil || string(pt) != "v3-bound-k1" {
		t.Fatalf("控制组原始 v3 密文: pt=%q err=%v", pt, err)
	}
}
