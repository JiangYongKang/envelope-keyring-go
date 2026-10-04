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

// sealVersion 复刻 Seal 的两步封装，但允许测试指定线格式版本（v1/v2），
// 用于模拟“历史版本密文仍可被读取”与“同一密钥环下新旧格式混用”。
// AAD 严格按版本选择独立域，与生产 Open 路径的版本分派保持一致。
func sealVersion(t *testing.T, entry *keyEntry, plaintext []byte, version byte, ts int64) []byte {
	t.Helper()

	var wrapAAD, payloadAAD []byte
	switch version {
	case FormatV1:
		wrapAAD = buildKeyIDAAD(aadDEKWrapV1, entry.id)
		payloadAAD = buildKeyIDAAD(aadPayloadV1, entry.id)
	case FormatV2:
		wrapAAD = buildKeyIDAAD(aadDEKWrapV2, entry.id)
		payloadAAD = buildKeyIDAAD(aadPayloadV2, entry.id)
	default:
		t.Fatalf("sealVersion 仅支持 v1/v2 历史构造, got v%d", version)
	}

	dek := testKey("dek:" + entry.id + ":" + fmt.Sprint(ts))

	wrapNonce := bytes.Repeat([]byte{0x11}, wrapNonceSize)
	sealedDEK, err := gcmSeal(entry.key, wrapNonce, dek, wrapAAD)
	if err != nil {
		t.Fatalf("gcmSeal DEK: %v", err)
	}
	encDEK := append(append([]byte{}, wrapNonce...), sealedDEK...)

	payloadNonce := bytes.Repeat([]byte{0x22}, gcmStandardNonceSize)
	ct, err := gcmSeal(dek, payloadNonce, plaintext, payloadAAD)
	if err != nil {
		t.Fatalf("gcmSeal payload: %v", err)
	}

	env := &envelope{
		version:    version,
		keyID:      entry.id,
		encDEK:     encDEK,
		nonce:      payloadNonce,
		ciphertext: ct,
		timestamp:  ts,
	}
	return encode(env)
}

// sealV3 使用与生产完全相同的封装流程构造 v3 密文，并可指定上下文标识。
func sealV3(t *testing.T, entry *keyEntry, plaintext, context []byte, ts int64) []byte {
	t.Helper()
	raw, err := sealEnvelope(entry.key, entry.id, plaintext, append([]byte{}, context...), ts)
	if err != nil {
		t.Fatalf("sealEnvelope v3: %v", err)
	}
	return raw
}

func TestSealOpenRoundtrip(t *testing.T) {
	ring := NewKeyRing()
	if err := ring.AddKey("k1", testKey("one"), true); err != nil {
		t.Fatal(err)
	}
	svc := NewEnvelopeService(ring)

	plaintext := []byte("hello-信封加密-2026")
	ct, err := svc.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	t.Logf("输入=%q | 密文长度=%d 字节, 版本字节=0x%02x | 判定依据=新密文使用当前格式 v3",
		plaintext, len(ct), ct[magicSize])
	if ct[magicSize] != FormatV3 {
		t.Fatalf("新密文默认应为 v3(0x%02x), got 0x%02x", FormatV3, ct[magicSize])
	}

	got, err := svc.Open(ct)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("明文不一致: got %q want %q", got, plaintext)
	}
	t.Logf("输入=同一密文 Open | 输出=%q | 判定依据=严格按密文携带 keyID=%q 选密钥并通过 GCM 验签",
		got, "k1")
}

func TestSealRejectsBadInputs(t *testing.T) {
	// 空密钥环：Seal 必须明确拒绝。
	svc := NewEnvelopeService(NewKeyRing())
	if _, err := svc.Seal([]byte("x")); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("input=<no active key> 期望 ErrNoActiveKey, got %v", err)
	}
	t.Logf("输入=Seal 于空密钥环 | 判定依据=%v（不允许静默生成临时密钥）", ErrNoActiveKey)

	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("one"), true)
	svc = NewEnvelopeService(ring)
	if _, err := svc.Seal(nil); !errors.Is(err, ErrEmptyPlaintext) {
		t.Fatalf("input=<empty plaintext> 期望 ErrEmptyPlaintext, got %v", err)
	}
	t.Logf("输入=Seal(nil) | 判定依据=%v", ErrEmptyPlaintext)
}

// TestFormatEvolutionV1V2V3Mix：v1/v2 历史密文与 v3 新密文在同一密钥环混用。
func TestFormatEvolutionV1V2V3Mix(t *testing.T) {
	ring := NewKeyRing()
	if err := ring.AddKey("k1", testKey("one"), true); err != nil {
		t.Fatal(err)
	}
	k1, _ := ring.lookupByID("k1")
	svc := NewEnvelopeService(ring)

	// 历史遗留：一条 v1、一条 v2 密文。
	oldV1PT := []byte("legacy-v1-payload")
	v1ct := sealVersion(t, k1, oldV1PT, FormatV1, 0)
	oldV2PT := []byte("legacy-v2-payload")
	v2ct := sealVersion(t, k1, oldV2PT, FormatV2, 1)
	// 新写入：由当前代码 SealWithContext 产生，必须为 v3 并绑定上下文。
	newPT := []byte("modern-v3-payload")
	v3ctx := []byte("tenant-a/billing")
	v3ct, err := svc.SealWithContext(newPT, v3ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("输入=历史密文 v1=0x%02x(%dB) v2=0x%02x(%dB) | 新密文 v3=0x%02x(%dB, ctx=%q)",
		v1ct[magicSize], len(v1ct), v2ct[magicSize], len(v2ct),
		v3ct[magicSize], len(v3ct), v3ctx)
	if v3ct[magicSize] != FormatV3 {
		t.Fatalf("新写入密文必须为 v3, got 0x%02x", v3ct[magicSize])
	}

	got1, err := svc.Open(v1ct)
	if err != nil {
		t.Fatalf("v1 历史密文应可读取, got %v", err)
	}
	got2, err := svc.Open(v2ct)
	if err != nil {
		t.Fatalf("v2 历史密文应可读取, got %v", err)
	}
	got3, err := svc.OpenWithContext(v3ct, v3ctx)
	if err != nil {
		t.Fatalf("v3 新密文在正确上下文下应可读取, got %v", err)
	}
	if !bytes.Equal(got1, oldV1PT) || !bytes.Equal(got2, oldV2PT) || !bytes.Equal(got3, newPT) {
		t.Fatalf("三代格式混用解密结果不符: %q / %q / %q", got1, got2, got3)
	}
	t.Logf("判定依据=按版本字节分派解析器与 AAD 域: v1->%q, v2->%q, v3->%q", got1, got2, got3)

	// v1/v2 不含上下文：带着非空上下文去开历史密文必须被拒绝。
	if _, err := svc.OpenWithContext(v2ct, []byte("tenant-a/billing")); !errors.Is(err, ErrContextMismatch) {
		t.Fatalf("v2 历史密文不接受上下文绑定, 期望 ErrContextMismatch, got %v", err)
	}
	t.Logf("输入=携带上下文打开 v2 密文 | 判定依据=%v（历史密文上下文为空）", ErrContextMismatch)

	// 无法识别的版本：必须明确拒绝，不得按当前格式误解析。
	bogus := append([]byte{}, v3ct...)
	bogus[magicSize] = 0x7F
	if _, err := svc.Open(bogus); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("input=<version 0x7F> 期望 ErrUnsupportedVersion, got %v", err)
	}
	t.Logf("输入=篡改 v3 版本字节为 0x7F | 判定依据=%v（拒绝按当前格式猜测解析）", ErrUnsupportedVersion)
}

// TestOpenUnknownKey 永不回退：密文指向密钥环中不存在的密钥。
func TestOpenUnknownKey(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("one"), true)
	svc := NewEnvelopeService(ring)

	ghost := &keyEntry{id: "ghost", key: testKey("ghost"), status: StatusActive}
	ct := sealVersion(t, ghost, []byte("secret"), FormatV2, 1)

	_, err := svc.Open(ct)
	t.Logf("输入=密文 keyID=%q（密钥环不存在）| 输出=%v | 判定依据=按标识查表失败, 禁止尝试其他密钥",
		"ghost", err)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("期望 ErrUnknownKey, got %v", err)
	}
}

// TestOpenRevokedKey：撤销后命中该密钥的历史密文一律拒绝，原因可区分。
func TestOpenRevokedKey(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("one"), true)
	svc := NewEnvelopeService(ring)
	ct, err := svc.Seal([]byte("sealed-under-k1"))
	if err != nil {
		t.Fatal(err)
	}

	if err := ring.Revoke("k1"); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Open(ct)
	t.Logf("输入=k1 密文（k1 已 Revoke）| 输出=%v | 判定依据=撤销 ≠ 未知, 归类为 ErrKeyRevoked", err)
	if !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("期望 ErrKeyRevoked, got %v", err)
	}
}

// TestRotationKeepsHistoryStable：轮换后历史密文解密结果保持稳定。
func TestRotationKeepsHistoryStable(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("k1"), true)
	svc := NewEnvelopeService(ring)

	hist := make(map[int][]byte)
	for i := 0; i < 20; i++ {
		pt := []byte(fmt.Sprintf("history-payload-%02d", i))
		ct, err := svc.Seal(pt)
		if err != nil {
			t.Fatal(err)
		}
		hist[i] = ct
	}

	// 连续轮换两次。
	for _, id := range []string{"k2", "k3"} {
		if err := ring.Rotate(id, testKey(id)); err != nil {
			t.Fatal(err)
		}
	}
	active, _ := ring.ActiveKeyID()
	t.Logf("输入=轮换至 k3 后解 20 条 k1 历史密文 | 当前激活=%q", active)

	for i := 0; i < 20; i++ {
		want := []byte(fmt.Sprintf("history-payload-%02d", i))
		got, err := svc.Open(hist[i])
		if err != nil {
			t.Fatalf("历史密文 #%d 轮换后解密失败: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("历史密文 #%d 结果漂移: got %q want %q", i, got, want)
		}
	}
	t.Log("判定依据=旧密钥仅转为 retired 仍参与解密；20 条历史密文明文逐条一致")

	// 新密文必须由新激活密钥封装。
	ct, _ := svc.Seal([]byte("after-rotation"))
	env, err := parseEnvelope(ct)
	if err != nil || env.keyID != "k3" {
		t.Fatalf("新密文应由 k3 封装, got env=%v err=%v", env, err)
	}
	t.Logf("输入=轮换后 Seal | 判定依据=密文携带 keyID=%q（新数据始终由当前激活密钥封装）", env.keyID)
}

// TestTamperedCiphertext：各类字节级破坏都归类为认证失败/格式非法。
func TestTamperedCiphertext(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("one"), true)
	svc := NewEnvelopeService(ring)
	ct, _ := svc.Seal([]byte("integrity-protected"))

	t.Run("翻转正文末尾字节(认证标签区)", func(t *testing.T) {
		bad := append([]byte{}, ct...)
		bad[len(bad)-1] ^= 0xFF
		_, err := svc.Open(bad)
		t.Logf("输入=末字节翻转 | 输出=%v | 判定依据=GCM 验签失败 => ErrCiphertextModified", err)
		if !errors.Is(err, ErrCiphertextModified) {
			t.Fatalf("期望 ErrCiphertextModified, got %v", err)
		}
	})

	t.Run("翻转封装DEK中的密文字节", func(t *testing.T) {
		env, err := parseEnvelope(ct)
		if err != nil {
			t.Fatal(err)
		}
		// encDEK 位于头部字段之后；翻转其最后一个字节（DEK 的 GCM 标签区）。
		bad := append([]byte{}, ct...)
		// 定位 encDEK 起点：魔数4+版本1+标志1+keyID长度2+keyID+dekLen2
		off := magicSize + 1 + 1 + 2 + len(env.keyID) + 2
		bad[off+len(env.encDEK)-1] ^= 0x01
		_, err = svc.Open(bad)
		t.Logf("输入=encDEK 标签位翻转 偏移=%d | 输出=%v | 判定依据=DEK 解封装验签失败", off, err)
		if !errors.Is(err, ErrCiphertextModified) {
			t.Fatalf("期望 ErrCiphertextModified, got %v", err)
		}
	})

	t.Run("截断密文", func(t *testing.T) {
		bad := ct[:len(ct)/2]
		_, err := svc.Open(bad)
		t.Logf("输入=截断至 %d/%d 字节 | 输出=%v | 判定依据=长度字段越界 => ErrMalformedCiphertext",
			len(bad), len(ct), err)
		if !errors.Is(err, ErrMalformedCiphertext) {
			t.Fatalf("期望 ErrMalformedCiphertext, got %v", err)
		}
	})

	t.Run("损坏魔数", func(t *testing.T) {
		bad := append([]byte{}, ct...)
		bad[0] = 'X'
		_, err := svc.Open(bad)
		t.Logf("输入=首字节改为 'X' | 输出=%v | 判定依据=魔数不匹配 => ErrMalformedCiphertext", err)
		if !errors.Is(err, ErrMalformedCiphertext) {
			t.Fatalf("期望 ErrMalformedCiphertext, got %v", err)
		}
	})

	t.Run("空输入", func(t *testing.T) {
		_, err := svc.Open(nil)
		t.Logf("输入=nil | 输出=%v | 判定依据=短于最小头部 => ErrMalformedCiphertext", err)
		if !errors.Is(err, ErrMalformedCiphertext) {
			t.Fatalf("期望 ErrMalformedCiphertext, got %v", err)
		}
	})
}

// TestTamperedKeyIDCannotFallback：密文中的密钥标识是自声明字段，
// 改它无法让密文在其他密钥下被解开——要么查无此密钥，要么因 AAD 绑定验签失败。
func TestTamperedKeyIDCannotFallback(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k1", testKey("one"), true)
	_ = ring.Rotate("k2", testKey("two"))
	svc := NewEnvelopeService(ring)

	ct, _ := svc.Seal([]byte("bound-to-k1"))
	// 强制构造一条由 k1 封装的 v2 密文。
	k1, _ := ring.lookupByID("k1")
	ct = sealVersion(t, k1, []byte("bound-to-k1"), FormatV2, 42)

	// v2 中 keyID 位于 MAGIC(4)+VER(1)+FLAGS(1)+KEYIDLEN(2) 之后。
	off := magicSize + 1 + 1 + 2

	t.Run("改写成另一个已存在密钥 k2", func(t *testing.T) {
		bad := append([]byte{}, ct...)
		copy(bad[off:], "k2") // 与 "k1" 等长，偏移不变
		_, err := svc.Open(bad)
		t.Logf("输入=把 keyID 字段 k1 改写为 k2 | 输出=%v | 判定依据=AAD 与封装密钥绑定, 验签失败而非回退成功", err)
		if !errors.Is(err, ErrCiphertextModified) {
			t.Fatalf("期望 ErrCiphertextModified, got %v", err)
		}
	})

	t.Run("改写成密钥环不存在的标识", func(t *testing.T) {
		bad := append([]byte{}, ct...)
		copy(bad[off:], "zz")
		_, err := svc.Open(bad)
		t.Logf("输入=把 keyID 字段改写为不存在的 zz | 输出=%v | 判定依据=先按标识查表, 未命中即拒绝", err)
		if !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("期望 ErrUnknownKey, got %v", err)
		}
	})

	// 控制组：原始密文仍可由 k1(retired) 正常解密。
	got, err := svc.Open(ct)
	if err != nil || string(got) != "bound-to-k1" {
		t.Fatalf("原始 k1 历史密文应可由 retired 密钥解密, got=%q err=%v", got, err)
	}
	t.Logf("判定依据=控制组: 未被改写的 k1 密文经 retired 密钥解密成功=%q", got)
}

// TestConcurrentRotationAndCrypto：高并发轮换与加解密共存。
// 核心不变量：任何在轮换前产生的历史密文，在任意轮换之后都能稳定解密，
// 且过程中不得 panic、不得错误归类、不得泄漏（失败只可能发生在新 Seal 时
// 恰好无激活密钥的瞬间窗口之外——本测试保证轮换连续，始终存在激活密钥）。
func TestConcurrentRotationAndCrypto(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k-init", testKey("init"), true)
	svc := NewEnvelopeService(ring)

	// 预置一批历史密文。
	const histN = 50
	hist := make([][]byte, histN)
	for i := range hist {
		pt := []byte(fmt.Sprintf("stable-%02d", i))
		ct, err := svc.Seal(pt)
		if err != nil {
			t.Fatal(err)
		}
		hist[i] = ct
	}

	const rotators = 4
	const rotationsEach = 25
	var rotCount int64
	var sealOK, openOK, openErr int64

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 轮换者：追加新版本密钥。
	for r := 0; r < rotators; r++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < rotationsEach; i++ {
				id := fmt.Sprintf("k-g%d-%d", g, i)
				if err := ring.Rotate(id, testKey(id)); err != nil {
					// 并发下标识互不冲突；任何其他错误都不允许出现。
					t.Errorf("并发 Rotate(%s) 意外失败: %v", id, err)
					return
				}
				atomic.AddInt64(&rotCount, 1)
			}
		}(r)
	}

	// 新加密/解密者：持续产生并用当前激活密钥解回新密文。
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				pt := []byte(fmt.Sprintf("live-%d-%d", id, time.Now().UnixNano()))
				ct, err := svc.Seal(pt)
				if err != nil {
					// 唯一合法失败：恰好在“撤销激活密钥”类操作后无激活密钥；
					// 本测试只做 Rotate，故不允许出现任何错误。
					t.Errorf("并发 Seal 意外失败: %v", err)
					return
				}
				atomic.AddInt64(&sealOK, 1)
				back, err := svc.Open(ct)
				if err != nil {
					atomic.AddInt64(&openErr, 1)
					t.Errorf("并发 Open 自加密文失败（错误归类=%v）", err)
					return
				}
				if !bytes.Equal(back, pt) {
					t.Errorf("并发解密明文不一致")
					return
				}
				atomic.AddInt64(&openOK, 1)
			}
		}(w)
	}

	// 历史密文巡查者：轮换越频繁，越要保证老密文结论稳定。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for i, ct := range hist {
				want := []byte(fmt.Sprintf("stable-%02d", i))
				got, err := svc.Open(ct)
				if err != nil {
					t.Errorf("并发轮换期间历史密文 #%d 解密失败: %v", i, err)
					return
				}
				if !bytes.Equal(got, want) {
					t.Errorf("并发轮换期间历史密文 #%d 明文漂移", i)
					return
				}
			}
		}
	}()

	// 等待轮换全部完成，再停止工作协程。
	rotDone := make(chan struct{})
	go func() {
		// 等待轮换者（wg 中也包含 worker，故单独计数轮次）。
		for atomic.LoadInt64(&rotCount) < int64(rotators*rotationsEach) {
			time.Sleep(time.Millisecond)
		}
		close(stop)
		close(rotDone)
	}()
	wg.Wait()
	<-rotDone

	// 轮换全部结束后做最终一致性校验：所有历史密文仍逐条可解且明文不变。
	for i, ct := range hist {
		want := []byte(fmt.Sprintf("stable-%02d", i))
		got, err := svc.Open(ct)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("最终校验历史密文 #%d: err=%v match=%v", i, err, bytes.Equal(got, want))
		}
	}

	infos := ring.Keys()
	t.Logf("输入=%d 次并发轮换 + 8 个持续加解密协程 | Seal 成功=%d Open 成功=%d Open 失败=%d | 环内密钥版本=%d",
		atomic.LoadInt64(&rotCount), atomic.LoadInt64(&sealOK),
		atomic.LoadInt64(&openOK), atomic.LoadInt64(&openErr), len(infos))
	t.Logf("判定依据=50 条初始历史密文在全部轮换前后及中途巡查中明文完全一致，错误归类无误")
}
