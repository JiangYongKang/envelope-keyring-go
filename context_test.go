package envelope

import (
	"bytes"
	"errors"
	"testing"
)

// newCtxService 构造带单个激活密钥的服务，供上下文用例复用。
func newCtxService(t *testing.T) *EnvelopeService {
	t.Helper()
	ring := NewKeyRing()
	if err := ring.AddKey("k1", testKey("ctx"), true); err != nil {
		t.Fatal(err)
	}
	return NewEnvelopeService(ring)
}

// TestContextRoundtrip：同一段上下文加密、解密可往返。
func TestContextRoundtrip(t *testing.T) {
	svc := newCtxService(t)
	ctx := []byte("tenant=acme|purpose=billing")
	pt := []byte("tenant-scoped-secret")

	ct, err := svc.SealWithContext(pt, ctx)
	if err != nil {
		t.Fatalf("SealWithContext: %v", err)
	}
	t.Logf("输入=明文%q + 上下文%q | 密文版本=0x%02x 长度=%d | 判定依据=上下文以 CTXCHECK 形式绑定",
		pt, ctx, ct[magicSize], len(ct))

	got, err := svc.OpenWithContext(ct, ctx)
	if err != nil {
		t.Fatalf("OpenWithContext(相同上下文) 应成功, got %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("明文不一致: got %q want %q", got, pt)
	}
	t.Logf("输入=同一密文 + 相同上下文 | 输出=%q | 判定依据=CTXCHECK 逐字节一致, GCM 验签通过", got)

	// 上下文是机密性的边界而非明文附件：密文字节中不得出现上下文原文。
	if bytes.Contains(ct, ctx) {
		t.Fatal("密文中不应出现上下文原文")
	}
	t.Logf("判定依据=密文不含上下文原文（上下文仅以 HMAC 校验值形式存在）")
}

// TestContextMismatch：上下文对不上时给出可区分的结论。
func TestContextMismatch(t *testing.T) {
	svc := newCtxService(t)
	ctx := []byte("tenant=acme|purpose=billing")
	ct, err := svc.SealWithContext([]byte("secret"), ctx)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		ctx  []byte
	}{
		{"完全不同的上下文", []byte("tenant=other|purpose=billing")},
		{"仅差一个字节", []byte("tenant=acme|purpose=billinG")},
		{"上下文为空(加密时非空)", nil},
		{"原上下文追加一字节", append(append([]byte{}, ctx...), 0x00)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.OpenWithContext(ct, tc.ctx)
			t.Logf("输入=密文(绑定 %q) + 上下文 %q | 输出=%v | 判定依据=CTXCHECK 不匹配 => ErrContextMismatch, 且与篡改归类不同",
				ctx, tc.ctx, err)
			if !errors.Is(err, ErrContextMismatch) {
				t.Fatalf("期望 ErrContextMismatch, got %v", err)
			}
			if errors.Is(err, ErrCiphertextModified) {
				t.Fatalf("上下文不匹配不得归类为 ErrCiphertextModified, got %v", err)
			}
		})
	}

	// 对照组：密文被篡改（而非上下文错误）仍归类为 ErrCiphertextModified。
	bad := append([]byte{}, ct...)
	bad[len(bad)-1] ^= 0xFF
	_, err = svc.OpenWithContext(bad, ctx)
	t.Logf("输入=末字节翻转 + 正确上下文 | 输出=%v | 判定依据=GCM 验签失败 => ErrContextModified 类, 而非 ErrContextMismatch", err)
	if !errors.Is(err, ErrCiphertextModified) || errors.Is(err, ErrContextMismatch) {
		t.Fatalf("期望 ErrCiphertextModified 且非 ErrContextMismatch, got %v", err)
	}
}

// TestContextProtectsEveryByte：上下文改一个字节都解不开（逐字节翻转）。
func TestContextProtectsEveryByte(t *testing.T) {
	svc := newCtxService(t)
	ctx := []byte("tenant=acme")
	ct, err := svc.SealWithContext([]byte("secret"), ctx)
	if err != nil {
		t.Fatal(err)
	}

	for i := range ctx {
		mut := append([]byte{}, ctx...)
		mut[i] ^= 0x01
		if _, err := svc.OpenWithContext(ct, mut); !errors.Is(err, ErrContextMismatch) {
			t.Fatalf("上下文第 %d 字节被改仍应拒绝(ErrContextMismatch), got %v", i, err)
		}
	}
	t.Logf("输入=逐字节翻转上下文(共 %d 处) | 判定依据=每处翻转都 => ErrContextMismatch, 无一放行", len(ctx))
}

// TestContextOnLegacyFormats：v1/v2 历史密文的隐式上下文为空。
func TestContextOnLegacyFormats(t *testing.T) {
	ring := NewKeyRing()
	if err := ring.AddKey("k1", testKey("ctx"), true); err != nil {
		t.Fatal(err)
	}
	k1, _ := ring.lookupByID("k1")
	svc := NewEnvelopeService(ring)

	for _, ver := range []byte{FormatV1, FormatV2} {
		ct := sealVersion(t, k1, []byte("legacy"), ver, 0)

		// 空上下文：历史密文照常可读。
		if _, err := svc.OpenWithContext(ct, nil); err != nil {
			t.Fatalf("v%d 历史密文 + 空上下文应可读取, got %v", ver, err)
		}
		t.Logf("输入=v%d 历史密文 + 空上下文 | 判定依据=历史格式隐式上下文为空, 照常解密", ver)

		// 非空上下文：明确归类为上下文不匹配，而非其他失败。
		_, err := svc.OpenWithContext(ct, []byte("tenant=acme"))
		t.Logf("输入=v%d 历史密文 + 非空上下文 | 输出=%v | 判定依据=历史格式无上下文绑定 => ErrContextMismatch", ver, err)
		if !errors.Is(err, ErrContextMismatch) {
			t.Fatalf("v%d + 非空上下文期望 ErrContextMismatch, got %v", ver, err)
		}
	}
}

// TestContextBoundToCiphertext：同一份明文在不同上下文下产生不可互换的密文。
func TestContextBoundToCiphertext(t *testing.T) {
	svc := newCtxService(t)
	pt := []byte("same-plaintext")

	ctA, err := svc.SealWithContext(pt, []byte("tenant=a"))
	if err != nil {
		t.Fatal(err)
	}
	ctB, err := svc.SealWithContext(pt, []byte("tenant=b"))
	if err != nil {
		t.Fatal(err)
	}

	// 交叉打开：A 的密文不能用 B 的上下文解开，反之亦然。
	if _, err := svc.OpenWithContext(ctA, []byte("tenant=b")); !errors.Is(err, ErrContextMismatch) {
		t.Fatalf("ctA + tenant=b 期望 ErrContextMismatch, got %v", err)
	}
	if _, err := svc.OpenWithContext(ctB, []byte("tenant=a")); !errors.Is(err, ErrContextMismatch) {
		t.Fatalf("ctB + tenant=a 期望 ErrContextMismatch, got %v", err)
	}
	t.Log("输入=同一明文分别绑定 tenant=a / tenant=b | 判定依据=交叉打开均 => ErrContextMismatch（上下文不可互换）")

	// 各自用正确上下文可解开。
	if got, err := svc.OpenWithContext(ctA, []byte("tenant=a")); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("ctA + tenant=a 应成功, got=%q err=%v", got, err)
	}
	if got, err := svc.OpenWithContext(ctB, []byte("tenant=b")); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("ctB + tenant=b 应成功, got=%q err=%v", got, err)
	}
	t.Log("判定依据=各自正确上下文下均还原为同一明文")
}
