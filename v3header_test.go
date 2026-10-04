package envelope

import (
	"errors"
	"fmt"
	"testing"
)

// v3HeaderOffsets 依据 v3 线格式计算各字段在线上字节中的偏移区间。
// 布局：MAGIC(4) VER(1) FLAGS(1) KEYIDLEN(2) KEYID DEKLEN(2) ENC_DEK
//
//	NONCELEN(2) NONCE CTXLEN(2) CTX TIMESTAMP(8) CIPHERTEXT…
type v3HeaderOffsets struct {
	magic     [2]int
	version   [2]int
	flags     [2]int
	keyIDLen  [2]int
	keyID     [2]int
	dekLen    [2]int
	encDEK    [2]int
	nonceLen  [2]int
	nonce     [2]int
	ctxLen    [2]int
	ctx       [2]int
	timestamp [2]int
}

func v3Offsets(t *testing.T, raw []byte) v3HeaderOffsets {
	t.Helper()
	env, err := parseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if env.version != FormatV3 {
		t.Fatalf("期望 v3 密文, got v%d", env.version)
	}
	var o v3HeaderOffsets
	pos := 0
	o.magic = [2]int{pos, pos + magicSize}
	pos += magicSize
	o.version = [2]int{pos, pos + 1}
	pos++
	o.flags = [2]int{pos, pos + 1}
	pos++
	o.keyIDLen = [2]int{pos, pos + 2}
	pos += 2
	o.keyID = [2]int{pos, pos + len(env.keyID)}
	pos += len(env.keyID)
	o.dekLen = [2]int{pos, pos + 2}
	pos += 2
	o.encDEK = [2]int{pos, pos + len(env.encDEK)}
	pos += len(env.encDEK)
	o.nonceLen = [2]int{pos, pos + 2}
	pos += 2
	o.nonce = [2]int{pos, pos + len(env.nonce)}
	pos += len(env.nonce)
	o.ctxLen = [2]int{pos, pos + 2}
	pos += 2
	o.ctx = [2]int{pos, pos + len(env.context)}
	pos += len(env.context)
	o.timestamp = [2]int{pos, pos + 8}
	// timestamp 结束位置必须等于解析器认定的头部长度。
	if pos+8 != len(env.header) {
		t.Fatalf("偏移计算与解析器头部长度不一致: %d vs %d", pos+8, len(env.header))
	}
	return o
}

// TestV3EveryHeaderFieldIsAuthenticated：逐个字段翻转一个字节，
// 任何一种篡改都不得成功解密。版本字节的特殊情况单独处理（未知版本）。
func TestV3EveryHeaderFieldIsAuthenticated(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("v3hdr"), true)
	svc := NewEnvelopeService(ring)

	ctx := []byte("tenant-7/usage=archive")
	ct, err := svc.SealWithContext([]byte("all-header-fields-protected"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	o := v3Offsets(t, ct)

	// 对区间内“代表性字节”做翻转：首字节、末字节、以及中间一字节（若存在）。
	probeOffsets := func(r [2]int) []int {
		start, end := r[0], r[1]
		switch {
		case end-start <= 0:
			return nil
		case end-start == 1:
			return []int{start}
		case end-start == 2:
			return []int{start, end - 1}
		default:
			return []int{start, start + (end-start)/2, end - 1}
		}
	}

	// 这些字段被翻转后，解析仍可能成功，但认证必须失败。
	authFields := []struct {
		name string
		ran  [2]int
	}{
		{"MAGIC", o.magic},
		{"FLAGS", o.flags},
		{"KEYIDLEN", o.keyIDLen},
		{"KEYID", o.keyID},
		{"DEKLEN", o.dekLen},
		{"ENC_DEK", o.encDEK},
		{"NONCELEN", o.nonceLen},
		{"NONCE", o.nonce},
		{"CTXLEN", o.ctxLen},
		{"CTX", o.ctx},
		{"TIMESTAMP", o.timestamp},
	}
	for _, f := range authFields {
		for _, idx := range probeOffsets(f.ran) {
			idx := idx
			t.Run(fmt.Sprintf("%s@%d", f.name, idx), func(t *testing.T) {
				bad := append([]byte{}, ct...)
				bad[idx] ^= 0x01
				_, err := svc.OpenWithContext(bad, ctx)
				if err == nil {
					t.Fatalf("翻转 %s 偏移 %d 后竟然解密成功——头部该字段未受保护", f.name, idx)
				}
				// 合法结论仅限：格式非法 / 未知版本 / 篡改；绝不允许成功。
				classified := errors.Is(err, ErrMalformedCiphertext) ||
					errors.Is(err, ErrUnsupportedVersion) ||
					errors.Is(err, ErrCiphertextModified) ||
					errors.Is(err, ErrContextMismatch) ||
					errors.Is(err, ErrUnknownKey)
				t.Logf("输入=翻转 v3 %s 偏移=%d | 输出=%v | 判定依据=打开被拒绝(%v)",
					f.name, idx, err, classified)
				if !classified {
					t.Fatalf("翻转 %s@%d 得到未归类错误: %v", f.name, idx, err)
				}
			})
		}
	}

	// 控制组：原始密文必须正常。
	got, err := svc.OpenWithContext(ct, ctx)
	if err != nil || string(got) != "all-header-fields-protected" {
		t.Fatalf("控制组原始密文应可解, got=%q err=%v", got, err)
	}
}

// TestV3HeaderByteSweep：更强保证——对头部每一个字节逐个翻转，无一可开。
// 版本字节翻转属于“未知版本”或“落到 v1/v2 布局后验签失败”，二者都必须拒绝。
func TestV3HeaderByteSweep(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("sweep"), true)
	svc := NewEnvelopeService(ring)

	ctx := []byte("sweep-ctx")
	ct, err := svc.SealWithContext([]byte("sweep-payload"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := parseEnvelope(ct)
	if err != nil {
		t.Fatal(err)
	}
	headerLen := len(env.header)

	var success, malformed, auth, unknownVer, unknownKey, other int
	for i := 0; i < headerLen; i++ {
		bad := append([]byte{}, ct...)
		bad[i] ^= 0x01
		_, err := svc.OpenWithContext(bad, ctx)
		switch {
		case err == nil:
			success++
			t.Errorf("头部偏移 %d 翻转后解密成功——完整性缺口", i)
		case errors.Is(err, ErrMalformedCiphertext):
			malformed++
		case errors.Is(err, ErrUnsupportedVersion):
			unknownVer++
		case errors.Is(err, ErrUnknownKey):
			unknownKey++
		case errors.Is(err, ErrCiphertextModified) || errors.Is(err, ErrContextMismatch):
			auth++
		default:
			other++
			t.Errorf("头部偏移 %d 翻转得到未预期错误: %v", i, err)
		}
	}
	t.Logf("输入=逐字节翻转 v3 头部全部 %d 字节 | 结论分布: 成功=%d 格式非法=%d 未知版本=%d 未知密钥=%d 认证/上下文失败=%d 其他=%d",
		headerLen, success, malformed, unknownVer, unknownKey, auth, other)
	if success != 0 || other != 0 {
		t.Fatalf("存在可被接受的头部篡改: success=%d other=%d", success, other)
	}
}
