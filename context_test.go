package envelope

import (
	"bytes"
	"errors"
	"testing"
)

// newContextSvc 准备一个含 k1 激活密钥的服务用于上下文绑定测试。
func newContextSvc(t *testing.T) (*EnvelopeService, *KeyRing) {
	t.Helper()
	ring := NewKeyRing()
	if err := ring.AddKey("k1", testKey("ctx-one"), true); err != nil {
		t.Fatal(err)
	}
	return NewEnvelopeService(ring), ring
}

// TestContextBindingRoundtrip：同一段上下文封装/打开成功。
func TestContextBindingRoundtrip(t *testing.T) {
	svc, _ := newContextSvc(t)

	cases := []struct {
		name string
		ctx  []byte
	}{
		{"租户+用途", []byte("tenant-42/payment-export")},
		{"空上下文(nil)", nil},
		{"空上下文(空切片)", []byte{}},
		{"含中文与二进制边界字符", []byte("租户=甲;用途=报表\x00;v=1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pt := []byte("context-bound-payload")
			ct, err := svc.SealWithContext(pt, tc.ctx)
			if err != nil {
				t.Fatalf("SealWithContext: %v", err)
			}
			t.Logf("输入=Seal ctx=%q | 版本=0x%02x 密文长度=%d", tc.ctx, ct[magicSize], len(ct))

			got, err := svc.OpenWithContext(ct, tc.ctx)
			if err != nil {
				t.Fatalf("同上下文打开失败: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("明文不符: %q", got)
			}
			t.Logf("输入=Open 同一段 ctx=%q | 输出=%q | 判定依据=上下文逐字节一致且两层 GCM 验签通过",
				tc.ctx, got)
		})
	}
}

// TestContextMismatch：上下文对不上必须得到 ErrContextMismatch，
// 且该结论先于密钥查找、与篡改错误可区分。
func TestContextMismatch(t *testing.T) {
	svc, _ := newContextSvc(t)

	pt := []byte("tenant-secret")
	ctx := []byte("tenant-acme/billing")
	ct, err := svc.SealWithContext(pt, ctx)
	if err != nil {
		t.Fatal(err)
	}

	wrong := [][]byte{
		[]byte("tenant-acme/BILLING"), // 改一个字符（大小写）
		[]byte("tenant-acme/billing "),
		[]byte("tenant-other/billing"),
		[]byte(""),
		nil,
	}
	for _, supplied := range wrong {
		_, err := svc.OpenWithContext(ct, supplied)
		t.Logf("输入=封于 ctx=%q 却以 ctx=%q 打开 | 输出=%v | 判定依据=期望 ErrContextMismatch",
			ctx, supplied, err)
		if !errors.Is(err, ErrContextMismatch) {
			t.Fatalf("ctx=%q: 期望 ErrContextMismatch, got %v", supplied, err)
		}
		if errors.Is(err, ErrCiphertextModified) {
			t.Fatalf("ctx=%q: 上下文不匹配不得归类为篡改", supplied)
		}
	}
}

// TestContextEmptyIsDefault：Seal/Open（无上下文 API）等价于空上下文绑定的 v3。
func TestContextEmptyIsDefault(t *testing.T) {
	svc, _ := newContextSvc(t)

	ct, err := svc.Seal([]byte("default-ctx"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := parseEnvelope(ct)
	if err != nil {
		t.Fatal(err)
	}
	if env.version != FormatV3 || len(env.context) != 0 {
		t.Fatalf("Seal 应产出空上下文 v3, version=v%d ctxLen=%d", env.version, len(env.context))
	}
	t.Logf("输入=Seal(无上下文 API) | 判定依据=产出 v3 且 CTXLEN=0")

	// 显式传 nil / 空切片 / 走 Open 都必须能打开；传非空必须拒绝。
	if _, err := svc.OpenWithContext(ct, nil); err != nil {
		t.Fatalf("nil 上下文打开失败: %v", err)
	}
	if _, err := svc.OpenWithContext(ct, []byte{}); err != nil {
		t.Fatalf("空切片上下文打开失败: %v", err)
	}
	if _, err := svc.Open(ct); err != nil {
		t.Fatalf("Open 打开失败: %v", err)
	}
	if _, err := svc.OpenWithContext(ct, []byte("x")); !errors.Is(err, ErrContextMismatch) {
		t.Fatalf("非空上下文应被拒绝, got %v", err)
	}
	t.Logf("判定依据=nil 与空切片等价; 非空上下文 => ErrContextMismatch")
}

// TestContextTamperedOnWire：直接改写密文头部里的上下文字节，密文必须被拒绝。
// 两条路径都安全：
//   - 仍提供原始上下文 -> 头部声明的上下文与提供值不符 => ErrContextMismatch；
//   - 提供“与被改后头部一致”的上下文 -> 比对通过，但 GCM 标签覆盖原上下文，
//     认证失败 => ErrCiphertextModified（证明上下文每个字都受完整性保护）。
func TestContextTamperedOnWire(t *testing.T) {
	svc, _ := newContextSvc(t)

	ctx := []byte("tenant-acme/billing")
	ct, err := svc.SealWithContext([]byte("integrity"), ctx)
	if err != nil {
		t.Fatal(err)
	}

	env, err := parseEnvelope(ct)
	if err != nil {
		t.Fatal(err)
	}
	// CTX 在头部中的起点：总头部长度减去 8(时间戳) 再减去上下文长度。
	ctxStart := len(env.header) - 8 - len(ctx)

	t.Run("仍提供原始上下文", func(t *testing.T) {
		bad := append([]byte{}, ct...)
		bad[ctxStart] ^= 0x01 // 翻转上下文首字节
		_, err := svc.OpenWithContext(bad, ctx)
		t.Logf("输入=翻转线上 CTX 首字节(偏移=%d)+提供原始 ctx | 输出=%v | 判定依据=安全拒绝",
			ctxStart, err)
		if !errors.Is(err, ErrContextMismatch) {
			t.Fatalf("期望 ErrContextMismatch（密文被改后上下文对不上）, got %v", err)
		}
	})

	t.Run("提供被改后头部声明的上下文", func(t *testing.T) {
		bad := append([]byte{}, ct...)
		bad[ctxStart] ^= 0x01
		tamperedCtx := append([]byte{}, ctx...)
		tamperedCtx[0] ^= 0x01
		_, err := svc.OpenWithContext(bad, tamperedCtx)
		t.Logf("输入=翻转 CTX 首字节并提供同值 ctx 试图通过比对 | 输出=%v | 判定依据=GCM 标签仍认证原上下文", err)
		if !errors.Is(err, ErrCiphertextModified) {
			t.Fatalf("期望 ErrCiphertextModified（上下文逐字节受完整性保护）, got %v", err)
		}
	})
}

// TestContextTooLarge：超过 64KiB 的上下文在封装阶段被明确拒绝。
func TestContextTooLarge(t *testing.T) {
	svc, _ := newContextSvc(t)
	big := make([]byte, maxContextLen+1)
	_, err := svc.SealWithContext([]byte("x"), big)
	t.Logf("输入=上下文 %d 字节(上限 %d) | 输出=%v", len(big), maxContextLen, err)
	if !errors.Is(err, ErrContextTooLarge) {
		t.Fatalf("期望 ErrContextTooLarge, got %v", err)
	}
}
