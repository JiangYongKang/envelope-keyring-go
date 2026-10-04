package envelope

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentRotationMixedFormats：并发轮换期间，v1/v2/v3 三代密文
// （含不同上下文绑定的 v3）持续混合解密，明文不得漂移、错误不得错分。
func TestConcurrentRotationMixedFormats(t *testing.T) {
	ring := NewKeyRing()
	_ = ring.AddKey("k0", testKey("mix-init"), true)
	k0, _ := ring.lookupByID("k0")
	svc := NewEnvelopeService(ring)

	// 预置三代历史密文：每代 20 条，并交叉绑定两种上下文。
	type sample struct {
		raw     []byte
		version byte
		ctx     []byte
		want    []byte
	}
	var hist []sample
	for i := 0; i < 20; i++ {
		hist = append(hist, sample{
			raw:     sealVersion(t, k0, []byte(fmt.Sprintf("v1-%02d", i)), FormatV1, int64(i)),
			version: FormatV1,
			want:    []byte(fmt.Sprintf("v1-%02d", i)),
		})
		hist = append(hist, sample{
			raw:     sealVersion(t, k0, []byte(fmt.Sprintf("v2-%02d", i)), FormatV2, int64(i)),
			version: FormatV2,
			want:    []byte(fmt.Sprintf("v2-%02d", i)),
		})
		ctx := []byte(fmt.Sprintf("tenant-%d/billing", i%2))
		hist = append(hist, sample{
			raw:     sealV3(t, k0, []byte(fmt.Sprintf("v3-%02d", i)), ctx, int64(i)),
			version: FormatV3,
			ctx:     ctx,
			want:    []byte(fmt.Sprintf("v3-%02d", i)),
		})
	}

	const rotators = 4
	const rotationsEach = 20
	var rotCount int64
	var v3Sealed, v3Opened, histChecked int64

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 轮换者：持续追加并激活新密钥，旧密钥全部保留为 retired。
	for r := 0; r < rotators; r++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < rotationsEach; i++ {
				id := fmt.Sprintf("mix-g%d-%d", g, i)
				if err := ring.Rotate(id, testKey(id)); err != nil {
					t.Errorf("并发 Rotate(%s): %v", id, err)
					return
				}
				atomic.AddInt64(&rotCount, 1)
			}
		}(r)
	}

	// v3 实时加解密者：新数据始终 v3，并在两个上下文间交替。
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				ctx := []byte(fmt.Sprintf("live-tenant-%d", id%2))
				pt := []byte(fmt.Sprintf("live-%d-%d", id, time.Now().UnixNano()))
				ct, err := svc.SealWithContext(pt, ctx)
				if err != nil {
					t.Errorf("并发 SealWithContext: %v", err)
					return
				}
				if ct[magicSize] != FormatV3 {
					t.Errorf("新写入必须为 v3, got 0x%02x", ct[magicSize])
					return
				}
				atomic.AddInt64(&v3Sealed, 1)

				back, err := svc.OpenWithContext(ct, ctx)
				if err != nil {
					t.Errorf("并发 OpenWithContext: %v", err)
					return
				}
				if !bytes.Equal(back, pt) {
					t.Error("并发 v3 明文不一致")
					return
				}
				atomic.AddInt64(&v3Opened, 1)
			}
		}(w)
	}

	// 历史密文巡查者：三代密文混合、逐条用各自版本/上下文反复解密。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for i := range hist {
				s := hist[i]
				got, err := svc.OpenWithContext(s.raw, s.ctx)
				if err != nil {
					t.Errorf("轮换期间 v%d 历史密文 #%d 解密失败: %v", s.version, i, err)
					return
				}
				if !bytes.Equal(got, s.want) {
					t.Errorf("轮换期间 v%d 历史密文 #%d 明文漂移: got %q want %q",
						s.version, i, got, s.want)
					return
				}
				atomic.AddInt64(&histChecked, 1)
			}
		}
	}()

	rotDone := make(chan struct{})
	go func() {
		for atomic.LoadInt64(&rotCount) < int64(rotators*rotationsEach) {
			time.Sleep(time.Millisecond)
		}
		close(stop)
		close(rotDone)
	}()
	wg.Wait()
	<-rotDone

	// 轮换全部结束后做最终逐条校验。
	for i, s := range hist {
		got, err := svc.OpenWithContext(s.raw, s.ctx)
		if err != nil {
			t.Fatalf("最终校验 v%d #%d: %v", s.version, i, err)
		}
		if !bytes.Equal(got, s.want) {
			t.Fatalf("最终校验 v%d #%d 漂移: %q vs %q", s.version, i, got, s.want)
		}
	}
	t.Logf("输入=%d 次并发轮换 + 6 个 v3 实时加解密协程 + 三代历史巡查(%d 条) | "+
		"v3 加密=%d v3 解密=%d 历史巡查=%d | 环内密钥版本=%d",
		rotators*rotationsEach, len(hist),
		atomic.LoadInt64(&v3Sealed), atomic.LoadInt64(&v3Opened),
		atomic.LoadInt64(&histChecked), len(ring.Keys()))
	t.Log("判定依据=v1/v2/v3 混用在轮换全程明文稳定; v3 必须携带正确上下文; 无错误错分")
}
