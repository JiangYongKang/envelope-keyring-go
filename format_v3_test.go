package envelope

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// v3HeaderFields 返回 v3 头部各字段的名称与字节区间，供逐字段篡改用例使用。
func v3HeaderFields(env *envelope) []struct {
	name string
	off  int
} {
	keyIDOff := magicSize + 1 + 1 + 2
	nonceLenOff := keyIDOff + len(env.keyID)
	nonceOff := nonceLenOff + 1
	tsOff := nonceOff + len(env.nonce)
	ctxCheckOff := tsOff + 8
	dekLenOff := ctxCheckOff + ctxCheckSize
	return []struct {
		name string
		off  int
	}{
		{"MAGIC", 0},
		{"VER", magicSize},
		{"FLAGS", magicSize + 1},
		{"KEYIDLEN", magicSize + 1 + 1},
		{"KEYID", keyIDOff},
		{"NONCELEN", nonceLenOff},
		{"NONCE", nonceOff},
		{"TIMESTAMP", tsOff},
		{"CTXCHECK", ctxCheckOff},
		{"DEKLEN", dekLenOff},
		{"ENC_DEK", env.dekOff},
	}
}

// TestV3HeaderTamperEveryField：v3 头部逐字段篡改，解密必须一律拒绝。
func TestV3HeaderTamperEveryField(t *testing.T) {
	svc := newCtxService(t)
	ctx := []byte("tenant=acme")
	ct, err := svc.SealWithContext([]byte("header-integrity"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := parseEnvelope(ct)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range v3HeaderFields(env) {
		t.Run("字段"+f.name, func(t *testing.T) {
			bad := append([]byte{}, ct...)
			bad[f.off] ^= 0x01
			_, err := svc.OpenWithContext(bad, ctx)
			t.Logf("输入=翻转 %s 首字节(偏移=%d) | 输出=%v | 判定依据=头部字段受 AAD/解析保护, 必须拒绝", f.name, f.off, err)
			if err == nil {
				t.Fatalf("头部字段 %s 被改动后解密竟然成功", f.name)
			}
		})
	}
}

// TestV3HeaderTamperEveryByte：加强版——头部每一个字节逐位翻转，无一放行。
func TestV3HeaderTamperEveryByte(t *testing.T) {
	svc := newCtxService(t)
	ctx := []byte("tenant=acme")
	ct, err := svc.SealWithContext([]byte("byte-level-integrity"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := parseEnvelope(ct)
	if err != nil {
		t.Fatal(err)
	}

	rejected := 0
	for off := 0; off < env.headerLen; off++ {
		bad := append([]byte{}, ct...)
		bad[off] ^= 0x01
		if _, err := svc.OpenWithContext(bad, ctx); err == nil {
			t.Fatalf("头部偏移 %d 被翻转后解密竟然成功", off)
		}
		rejected++
	}
	t.Logf("输入=逐字节翻转头部 0..%d 共 %d 处 | 判定依据=每一处都被拒绝(解析失败或验签失败), 无一放行",
		env.headerLen-1, rejected)
}

// repackAs 把 src 密文解析出的字段按 target 版本的布局重新拼装，
// 模拟“拿一种版本的密文按另一种版本的布局重排”的攻击。
func repackAs(t *testing.T, srcRaw []byte, target byte) []byte {
	t.Helper()
	env, err := parseEnvelope(srcRaw)
	if err != nil {
		t.Fatalf("repack 源密文解析失败: %v", err)
	}
	out := &envelope{
		version:    target,
		keyID:      env.keyID,
		encDEK:     env.encDEK,
		nonce:      env.nonce,
		ciphertext: env.ciphertext,
		timestamp:  env.timestamp,
		flags:      env.flags,
	}
	if target == FormatV3 && env.ctxCheck == nil {
		// 源版本没有 CTXCHECK：攻击者只能填占位字节。
		out.ctxCheck = make([]byte, ctxCheckSize)
	}
	return encode(out)
}

// TestCrossVersionRepackRejected：跨版本重排的密文不得被当成另一版本合法密文打开。
func TestCrossVersionRepackRejected(t *testing.T) {
	ring := NewKeyRing()
	if err := ring.AddKey("k1", testKey("repack"), true); err != nil {
		t.Fatal(err)
	}
	k1, _ := ring.lookupByID("k1")
	svc := NewEnvelopeService(ring)

	ctx := []byte("tenant=acme")
	sources := map[byte][]byte{
		FormatV1: sealVersion(t, k1, []byte("repack-v1"), FormatV1, 0),
		FormatV2: sealVersion(t, k1, []byte("repack-v2"), FormatV2, 9),
	}
	v3ct, err := svc.SealWithContext([]byte("repack-v3"), ctx)
	if err != nil {
		t.Fatal(err)
	}
	sources[FormatV3] = v3ct

	// 控制组：三条原始密文按各自声明的版本都能正常打开。
	for ver, raw := range sources {
		openCtx := []byte(nil)
		if ver == FormatV3 {
			openCtx = ctx
		}
		if _, err := svc.OpenWithContext(raw, openCtx); err != nil {
			t.Fatalf("控制组: v%d 原始密文应可打开, got %v", ver, err)
		}
	}
	t.Log("控制组=v1/v2/v3 原始密文按各自版本均可正常解密")

	for srcVer, srcRaw := range sources {
		for _, target := range []byte{FormatV1, FormatV2, FormatV3} {
			if target == srcVer {
				continue
			}
			name := fmt.Sprintf("v%d重排为v%d", srcVer, target)
			t.Run(name, func(t *testing.T) {
				repacked := repackAs(t, srcRaw, target)
				// 打开上下文按目标版本的合法用法提供（v1/v2 隐式为空），
				// 确保拒绝只能来自版本/头部绑定的验签失败，而非上下文检查。
				openCtx := []byte(nil)
				if target == FormatV3 {
					openCtx = ctx
				}
				_, err := svc.OpenWithContext(repacked, openCtx)
				t.Logf("输入=v%d 密文字段按 v%d 布局重排 | 输出=%v | 判定依据=AAD 绑定版本/头部, 重排后验签必失败",
					srcVer, target, err)
				if err == nil {
					t.Fatalf("v%d 密文被重排为 v%d 后竟然能打开", srcVer, target)
				}
				if !errors.Is(err, ErrCiphertextModified) {
					t.Fatalf("重排密文应归类为验签失败 ErrCiphertextModified, got %v", err)
				}
			})
		}
	}
}

// TestUnknownVersionRejected：魔数正确但版本号不认识的密文明确拒绝。
func TestUnknownVersionRejected(t *testing.T) {
	svc := newCtxService(t)
	ct, err := svc.Seal([]byte("version-probe"))
	if err != nil {
		t.Fatal(err)
	}

	for _, badVer := range []byte{0x00, 0x04, 0x7F, 0xFF} {
		bad := append([]byte{}, ct...)
		bad[magicSize] = badVer
		_, err := svc.Open(bad)
		t.Logf("输入=版本字节改为 0x%02x | 输出=%v | 判定依据=未知版本 => ErrUnsupportedVersion, 不按当前格式猜测解析",
			badVer, err)
		if !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("版本 0x%02x 期望 ErrUnsupportedVersion, got %v", badVer, err)
		}
	}
}

// TestConcurrentRotationMixedFormats：并发轮换下 v1/v2/v3 密文混用解密结果不漂移。
func TestConcurrentRotationMixedFormats(t *testing.T) {
	ring := NewKeyRing()
	if err := ring.AddKey("k-init", testKey("mixed-init"), true); err != nil {
		t.Fatal(err)
	}
	kInit, _ := ring.lookupByID("k-init")
	svc := NewEnvelopeService(ring)

	// 预置三类历史密文：v1、v2（无上下文）与 v3（绑定上下文）。
	type histItem struct {
		raw  []byte
		ctx  []byte
		want []byte
	}
	var hist []histItem
	for i := 0; i < 10; i++ {
		pt := []byte(fmt.Sprintf("mixed-v1-%02d", i))
		hist = append(hist, histItem{raw: sealVersion(t, kInit, pt, FormatV1, 0), want: pt})
		pt = []byte(fmt.Sprintf("mixed-v2-%02d", i))
		hist = append(hist, histItem{raw: sealVersion(t, kInit, pt, FormatV2, int64(i)), want: pt})
		pt = []byte(fmt.Sprintf("mixed-v3-%02d", i))
		ctx := []byte(fmt.Sprintf("tenant=t%02d", i))
		ct, err := svc.SealWithContext(pt, ctx)
		if err != nil {
			t.Fatal(err)
		}
		hist = append(hist, histItem{raw: ct, ctx: ctx, want: pt})
	}
	t.Logf("输入=预置 %d 条历史密文(v1/v2/v3 各 10 条, v3 绑定各自上下文)", len(hist))

	const rotators = 4
	const rotationsEach = 20
	var rotCount, openOK int64
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for r := 0; r < rotators; r++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < rotationsEach; i++ {
				id := fmt.Sprintf("km-g%d-%d", g, i)
				if err := ring.Rotate(id, testKey(id)); err != nil {
					t.Errorf("并发 Rotate(%s) 失败: %v", id, err)
					return
				}
				atomic.AddInt64(&rotCount, 1)
			}
		}(r)
	}

	// 巡查者：并发轮换期间反复解全部历史密文，明文不得漂移。
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for i, item := range hist {
					got, err := svc.OpenWithContext(item.raw, item.ctx)
					if err != nil {
						t.Errorf("并发轮换期间历史密文 #%d 解密失败: %v", i, err)
						return
					}
					if !bytes.Equal(got, item.want) {
						t.Errorf("并发轮换期间历史密文 #%d 明文漂移: got %q", i, got)
						return
					}
					atomic.AddInt64(&openOK, 1)
				}
			}
		}()
	}

	for atomic.LoadInt64(&rotCount) < int64(rotators*rotationsEach) {
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()

	// 最终校验：全部轮换结束后逐条复验。
	for i, item := range hist {
		got, err := svc.OpenWithContext(item.raw, item.ctx)
		if err != nil || !bytes.Equal(got, item.want) {
			t.Fatalf("最终校验历史密文 #%d: err=%v match=%v", i, err, bytes.Equal(got, item.want))
		}
	}
	t.Logf("判定依据=%d 次并发轮换期间及之后, %d 条 v1/v2/v3 混合历史密文共 %d 次解密明文全部一致",
		atomic.LoadInt64(&rotCount), len(hist), atomic.LoadInt64(&openOK))
}
