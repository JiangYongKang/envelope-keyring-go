package envelope

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	// dekSize 是每次信封加密随机生成的数据密钥长度（AES-256）。
	dekSize = 32
	// gcmStandardNonceSize 是 AES-GCM 标准随机数长度。
	gcmStandardNonceSize = 12

	// wrapNonceSize 是封装 DEK 时前置在 encDEK 中的 nonce 长度。
	wrapNonceSize = gcmStandardNonceSize
)

// 附加认证数据（AAD）：将密文用途、密钥标识、格式版本与上下文绑定到认证标签。
// 每个格式版本使用各自独立的 AAD 域，从而：
//   - 把 v1 密文按 v2/v3 布局重拼（或反向重拼）后，标签无法通过另一版本的校验；
//   - “换一个密钥尝试解密”或跨上下文搬运密文同样无法通过校验。
var (
	// v1（历史格式）：AAD 域固定不变，保证历史密文的解密结论永不漂移。
	aadDEKWrapV1 = []byte("envelope-keyring/dek-wrap/v1")
	aadPayloadV1 = []byte("envelope-keyring/payload/v1")

	// v2：独立 AAD 域（绑定格式版本），与 v1/v3 互不兼容。
	aadDEKWrapV2 = []byte("envelope-keyring/dek-wrap/v2")
	aadPayloadV2 = []byte("envelope-keyring/payload/v2")

	// v3 封装层 AAD 域：除 keyID 外还绑定调用方上下文。
	aadDEKWrapV3 = []byte("envelope-keyring/dek-wrap/v3")
	// v3 正文层不使用固定 AAD 常量：其 AAD 即完整头部原文（逐字节认证）。
)

// EnvelopeService 在一个本地密钥环上提供信封加解密。
type EnvelopeService struct {
	ring *KeyRing
}

// NewEnvelopeService 创建绑定指定密钥环的信封加解密服务。
func NewEnvelopeService(ring *KeyRing) *EnvelopeService {
	return &EnvelopeService{ring: ring}
}

// Seal 使用当前激活密钥封装随机数据密钥，再用该数据密钥加密明文。
// 新密文始终以当前格式（v3）写出，且不绑定调用方上下文（等价于空上下文）。
func (s *EnvelopeService) Seal(plaintext []byte) ([]byte, error) {
	return s.SealWithContext(plaintext, nil)
}

// SealWithContext 使用当前激活密钥封装明文，并将调用方上下文标识
// （例如“租户 ID / 用途”）以密码学方式绑定到密文：
//   - 上下文原文写入 v3 头部，同时参与 DEK 封装层与正文层的认证；
//   - 篡改上下文字节会使 GCM 验签失败（ErrCiphertextModified）；
//   - 解密时必须提供同一段上下文，否则得到 ErrContextMismatch。
//
// 上下文允许为空（nil 与空切片等价）；超过 64KiB 返回 ErrContextTooLarge。
func (s *EnvelopeService) SealWithContext(plaintext, context []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}
	if len(context) > maxContextLen {
		return nil, fmt.Errorf("%w: context length %d exceeds %d",
			ErrContextTooLarge, len(context), maxContextLen)
	}

	// 在读锁下取得激活密钥条目；并发轮换不会使其失效：
	// 轮换只会把旧密钥置为 retired，密钥材料仍然有效。
	entry, err := s.ring.lookupActive()
	if err != nil {
		return nil, err
	}

	// v3 的 keyID 长度字段为 2 字节，入环阶段未限制长度，此处防御性检查。
	if len(entry.id) > maxKeyIDLenV2 {
		return nil, fmt.Errorf("%w: active key id length %d exceeds %d",
			ErrMalformedCiphertext, len(entry.id), maxKeyIDLenV2)
	}

	raw, err := sealEnvelope(entry.key, entry.id, plaintext, context, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// sealEnvelope 是封装流程的单一实现（同时服务生产代码与测试构造历史密文）：
// 每次生成随机 DEK 与两组随机 nonce，按 v3 线格式输出。
//
// v3 的两层 GCM 认证范围：
//  1. DEK 封装层：AAD = 域 ‖ KEYIDLEN ‖ KEYID ‖ CTXLEN ‖ CTX；
//  2. 正文层：AAD = 完整头部（MAGIC..TIMESTAMP，含 ENC_DEK/NONCE/长度字段）。
//
// 因此头部中任意一个字段的任意字节被修改，正文验签都必然失败。
func sealEnvelope(kek []byte, keyID string, plaintext, context []byte, timestamp int64) ([]byte, error) {
	// 每次加密生成全新的随机数据密钥（DEK）。
	dek, err := randomBytes(dekSize)
	if err != nil {
		return nil, fmt.Errorf("envelope: generate DEK: %w", err)
	}
	defer zeroize(dek)

	// 1) 用 KEK 封装 DEK：encDEK = wrapNonce || AES-GCM-SEAL(KEK, DEK)。
	wrapNonce, err := randomBytes(wrapNonceSize)
	if err != nil {
		return nil, fmt.Errorf("envelope: generate wrap nonce: %w", err)
	}
	sealedDEK, err := gcmSeal(kek, wrapNonce, dek, buildV3WrapAAD(keyID, context))
	if err != nil {
		return nil, err
	}
	encDEK := make([]byte, 0, wrapNonceSize+len(sealedDEK))
	encDEK = append(encDEK, wrapNonce...)
	encDEK = append(encDEK, sealedDEK...)

	// 2) 用 DEK 加密真实明文。
	payloadNonce, err := randomBytes(gcmStandardNonceSize)
	if err != nil {
		return nil, fmt.Errorf("envelope: generate payload nonce: %w", err)
	}

	// 3) 先序列化头部（MAGIC..TIMESTAMP），再把头部原文作为正文 GCM 的 AAD。
	env := &envelope{
		version:   FormatV3,
		keyID:     keyID,
		encDEK:    encDEK,
		nonce:     payloadNonce,
		context:   context,
		timestamp: timestamp,
	}
	header := encodeV3Header(env)
	ciphertext, err := gcmSeal(dek, payloadNonce, plaintext, header)
	if err != nil {
		return nil, err
	}

	// 最终密文 = 头部 ‖ CIPHERTEXT+TAG。
	out := make([]byte, 0, len(header)+len(ciphertext))
	out = append(out, header...)
	out = append(out, ciphertext...)
	return out, nil
}

// Open 按密文携带的密钥标识选择密钥解封装并验签解密（不提供上下文）。
// 仅适用于无上下文绑定的密文（v1/v2 历史密文，或以空上下文封装的 v3 密文）。
func (s *EnvelopeService) Open(raw []byte) ([]byte, error) {
	return s.OpenWithContext(raw, nil)
}

// OpenWithContext 按密文自声明的版本与密钥标识解密密文，并验证上下文绑定：
//   - v1/v2 密文不含上下文字段：context 必须为空，否则 ErrContextMismatch；
//   - v3 密文：context 必须与封装时逐字节相同，否则 ErrContextMismatch。
//
// 未知密钥、已撤销密钥、头部/正文被篡改、非法格式均被明确拒绝，
// 绝不回退到其他密钥或静默返回明文。
func (s *EnvelopeService) OpenWithContext(raw, context []byte) ([]byte, error) {
	// 1) 先严格解析格式；格式非法/版本未知在此阶段被拒绝，不进入任何密钥操作。
	env, err := parseEnvelope(raw)
	if err != nil {
		return nil, err
	}

	// 2) 先校验上下文归属：密文声明的上下文必须与调用方提供的完全一致。
	//    该判定先于密钥查找，使“上下文不对”成为独立、稳定、可区分的结论。
	if !bytes.Equal(env.context, context) {
		return nil, fmt.Errorf("%w: ciphertext version v%d binds context of %d bytes, supplied %d bytes",
			ErrContextMismatch, env.version, len(env.context), len(context))
	}

	// 3) 严格按密文携带的密钥标识查找；未知/已撤销立即失败，不尝试其他密钥。
	entry, err := s.ring.lookupByID(env.keyID)
	if err != nil {
		return nil, err
	}

	// 4) 按密文版本选择该版本专属的 AAD 域。跨版本重拼的密文会在此处验签失败。
	wrapAAD, payloadAAD := aadForVersion(env)

	// 5) 解封装 DEK。encDEK 内部前置了封装 nonce。
	if len(env.encDEK) < wrapNonceSize+gcmTagSize {
		return nil, fmt.Errorf("%w: wrapped DEK too short", ErrMalformedCiphertext)
	}
	wrapNonce := env.encDEK[:wrapNonceSize]
	sealedDEK := env.encDEK[wrapNonceSize:]
	dek, err := gcmOpen(entry.key, wrapNonce, sealedDEK, wrapAAD)
	if err != nil {
		// KEK 不匹配或封装块被改动，都表现为认证失败。
		return nil, fmt.Errorf("%w: DEK unwrap failed for key %q (format v%d): %v",
			ErrCiphertextModified, env.keyID, env.version, err)
	}
	defer zeroize(dek)

	// 6) 用 DEK 验签并解密正文。
	//    v3 的 payloadAAD 是完整头部原文：头部任意字节被改动都会在此失败。
	plaintext, err := gcmOpen(dek, env.nonce, env.ciphertext, payloadAAD)
	if err != nil {
		return nil, fmt.Errorf("%w: payload open failed for key %q (format v%d): %v",
			ErrCiphertextModified, env.keyID, env.version, err)
	}
	return plaintext, nil
}

// aadForVersion 按密文自声明的版本返回对应的两层 AAD。
// v3 正文层 AAD 为解析得到的完整头部原文；封装层 AAD 绑定 keyID 与上下文。
func aadForVersion(env *envelope) (wrapAAD, payloadAAD []byte) {
	switch env.version {
	case FormatV1:
		return buildKeyIDAAD(aadDEKWrapV1, env.keyID), buildKeyIDAAD(aadPayloadV1, env.keyID)
	case FormatV2:
		return buildKeyIDAAD(aadDEKWrapV2, env.keyID), buildKeyIDAAD(aadPayloadV2, env.keyID)
	case FormatV3:
		return buildV3WrapAAD(env.keyID, env.context), env.header
	default:
		// 解析阶段已分派，未知版本不可能到达这里。
		return nil, nil
	}
}

// encode 按 envelope 携带的版本号选择对应线格式输出（供测试构造历史密文）。
func encode(e *envelope) []byte {
	switch e.version {
	case FormatV1:
		return encodeV1(e)
	case FormatV2:
		return encodeV2(e)
	case FormatV3:
		return encodeV3(e)
	default:
		// 内部不变量：写路径只可能产生受支持版本。
		panic(fmt.Sprintf("envelope: unsupported internal format version 0x%02x", e.version))
	}
}

// buildKeyIDAAD 以“域常量 ‖ 0x00 分隔 ‖ keyID”的形式构造 AAD。
// v1/v2 的封装层与正文层共用该结构，仅域常量不同。
func buildKeyIDAAD(domain []byte, keyID string) []byte {
	aad := make([]byte, 0, len(domain)+1+len(keyID))
	aad = append(aad, domain...)
	aad = append(aad, 0)
	aad = append(aad, keyID...)
	return aad
}

// buildWrapAAD 构造 v1 DEK 封装的 AAD（历史行为固定不变）。
func buildWrapAAD(keyID string) []byte {
	return buildKeyIDAAD(aadDEKWrapV1, keyID)
}

// buildPayloadAAD 构造 v1 正文加密的 AAD（历史行为固定不变）。
func buildPayloadAAD(keyID string) []byte {
	return buildKeyIDAAD(aadPayloadV1, keyID)
}

// buildV3WrapAAD 构造 v3 DEK 封装的 AAD。
// 结构：域常量 ‖ KEYIDLEN(2 BE) ‖ KEYID ‖ CTXLEN(2 BE) ‖ CTX。
// keyID 与上下文都带 2 字节长度前缀，避免拼接歧义。
func buildV3WrapAAD(keyID string, ctx []byte) []byte {
	aad := make([]byte, 0, len(aadDEKWrapV3)+2+len(keyID)+2+len(ctx))
	aad = append(aad, aadDEKWrapV3...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(keyID)))
	aad = append(aad, lenBuf[:]...)
	aad = append(aad, keyID...)
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(ctx)))
	aad = append(aad, lenBuf[:]...)
	aad = append(aad, ctx...)
	return aad
}

// gcmSeal 使用 AES-256-GCM 加密并附加认证标签。
func gcmSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: init GCM: %w", err)
	}
	return g.Seal(nil, nonce, plaintext, aad), nil
}

// gcmOpen 使用 AES-256-GCM 验签并解密；认证失败返回错误（由调用方归类）。
func gcmOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: init GCM: %w", err)
	}
	// 随机数长度不被该 GCM 实例接受时，NewGCM/Open 会返回错误而非 panic。
	if len(nonce) != g.NonceSize() {
		return nil, fmt.Errorf("envelope: nonce size %d, want %d", len(nonce), g.NonceSize())
	}
	return g.Open(nil, nonce, ciphertext, aad)
}

// randomBytes 生成密码学随机字节。
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// zeroize 尽力清除内存中的敏感字节（DEK 等），缩小明文材料暴露窗口。
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
