package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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

// 附加认证数据（AAD）：将密文用途与密钥标识绑定到认证标签上，
// 使“换一个密钥尝试解密”或跨上下文搬运密文无法通过校验。
var (
	aadDEKWrap = []byte("envelope-keyring/dek-wrap/v1")
	aadPayload = []byte("envelope-keyring/payload/v1")
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
// 新密文始终以当前格式（最高版本）写出。
func (s *EnvelopeService) Seal(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, ErrEmptyPlaintext
	}

	// 在读锁下取得激活密钥条目；并发轮换不会使其失效：
	// 轮换只会把旧密钥置为 retired，密钥材料仍然有效。
	entry, err := s.ring.lookupActive()
	if err != nil {
		return nil, err
	}

	// 每次加密生成全新的随机数据密钥（DEK）。
	dek, err := randomBytes(dekSize)
	if err != nil {
		return nil, fmt.Errorf("envelope: generate DEK: %w", err)
	}
	defer zeroize(dek)

	// 1) 用激活 KEK 封装 DEK：encDEK = wrapNonce || AES-GCM-SEAL(KEK, DEK)。
	wrapNonce, err := randomBytes(wrapNonceSize)
	if err != nil {
		return nil, fmt.Errorf("envelope: generate wrap nonce: %w", err)
	}
	sealedDEK, err := gcmSeal(entry.key, wrapNonce, dek, buildWrapAAD(entry.id))
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
	ciphertext, err := gcmSeal(dek, payloadNonce, plaintext, buildPayloadAAD(entry.id))
	if err != nil {
		return nil, err
	}

	env := &envelope{
		version:    currentFormat,
		keyID:      entry.id,
		encDEK:     encDEK,
		nonce:      payloadNonce,
		ciphertext: ciphertext,
	}
	if currentFormat == FormatV2 {
		env.timestamp = time.Now().Unix()
	}
	return encode(env), nil
}

// Open 按密文携带的密钥标识选择密钥解封装并验签解密。
// 未知密钥、已撤销密钥、篡改密文、非法格式均被明确拒绝，
// 绝不回退到其他密钥或静默返回明文。
func (s *EnvelopeService) Open(raw []byte) ([]byte, error) {
	// 1) 先严格解析格式；格式非法/版本未知在此阶段被拒绝，不进入任何密钥操作。
	env, err := parseEnvelope(raw)
	if err != nil {
		return nil, err
	}

	// 2) 严格按密文携带的密钥标识查找；未知/已撤销立即失败，不尝试其他密钥。
	entry, err := s.ring.lookupByID(env.keyID)
	if err != nil {
		return nil, err
	}

	// 3) 解封装 DEK。encDEK 内部前置了封装 nonce。
	if len(env.encDEK) < wrapNonceSize+gcmTagSize {
		return nil, fmt.Errorf("%w: wrapped DEK too short", ErrMalformedCiphertext)
	}
	wrapNonce := env.encDEK[:wrapNonceSize]
	sealedDEK := env.encDEK[wrapNonceSize:]
	dek, err := gcmOpen(entry.key, wrapNonce, sealedDEK, buildWrapAAD(env.keyID))
	if err != nil {
		// KEK 不匹配或封装块被改动，都表现为认证失败。
		return nil, fmt.Errorf("%w: DEK unwrap failed for key %q: %v",
			ErrCiphertextModified, env.keyID, err)
	}
	defer zeroize(dek)

	// 4) 用 DEK 验签并解密正文；任何字节被改动都会在此处失败。
	plaintext, err := gcmOpen(dek, env.nonce, env.ciphertext, buildPayloadAAD(env.keyID))
	if err != nil {
		return nil, fmt.Errorf("%w: payload open failed for key %q (format v%d): %v",
			ErrCiphertextModified, env.keyID, env.version, err)
	}
	return plaintext, nil
}

// encode 按 envelope 携带的版本号选择对应线格式输出。
func encode(e *envelope) []byte {
	switch e.version {
	case FormatV1:
		return encodeV1(e)
	case FormatV2:
		return encodeV2(e)
	default:
		// 内部不变量：写路径只可能产生受支持版本。
		panic(fmt.Sprintf("envelope: unsupported internal format version 0x%02x", e.version))
	}
}

// buildWrapAAD 构造 DEK 封装的附加认证数据，绑定密钥标识。
func buildWrapAAD(keyID string) []byte {
	aad := make([]byte, 0, len(aadDEKWrap)+1+len(keyID))
	aad = append(aad, aadDEKWrap...)
	aad = append(aad, 0)
	aad = append(aad, keyID...)
	return aad
}

// buildPayloadAAD 构造正文加密的附加认证数据，绑定密钥标识。
func buildPayloadAAD(keyID string) []byte {
	aad := make([]byte, 0, len(aadPayload)+1+len(keyID))
	aad = append(aad, aadPayload...)
	aad = append(aad, 0)
	aad = append(aad, keyID...)
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
