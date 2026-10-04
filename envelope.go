package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

// 附加认证数据（AAD）：将密文用途、格式版本与密钥标识绑定到认证标签上，
// 使“换一个密钥尝试解密”、跨上下文搬运密文、跨版本重排密文都无法通过校验。
var (
	aadDEKWrap = []byte("envelope-keyring/dek-wrap/v1")
	aadPayload = []byte("envelope-keyring/payload/v1")

	// v3 使用独立的域分离常量，AAD 内容为“域常量 || 0 || 头部字节”，
	// 使头部每一个字段都受 GCM 认证标签保护。
	aadDEKWrapV3 = []byte("envelope-keyring/dek-wrap/v3")
	aadPayloadV3 = []byte("envelope-keyring/payload/v3")

	// aadCtxCheck 是计算上下文校验值（CTXCHECK）时的域分离前缀。
	aadCtxCheck = []byte("envelope-keyring/ctx-check/v1")
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
// 等价于 SealWithContext(plaintext, nil)。新密文始终以当前格式（最高版本）写出。
func (s *EnvelopeService) Seal(plaintext []byte) ([]byte, error) {
	return s.SealWithContext(plaintext, nil)
}

// SealWithContext 与 Seal 相同，但额外绑定一段调用方提供的加密上下文
// （例如“租户标识‖用途”）。上下文本身不写入密文，而是以 DEK 为密钥的
// HMAC 校验值（CTXCHECK）形式受完整性保护：解密时必须提供逐字节一致的
// 上下文，否则以 ErrContextMismatch 明确拒绝。
func (s *EnvelopeService) SealWithContext(plaintext, context []byte) ([]byte, error) {
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

	wrapNonce, err := randomBytes(wrapNonceSize)
	if err != nil {
		return nil, fmt.Errorf("envelope: generate wrap nonce: %w", err)
	}
	payloadNonce, err := randomBytes(gcmStandardNonceSize)
	if err != nil {
		return nil, fmt.Errorf("envelope: generate payload nonce: %w", err)
	}

	env := &envelope{
		version:   currentFormat,
		keyID:     entry.id,
		nonce:     payloadNonce,
		timestamp: time.Now().Unix(),
		ctxCheck:  computeCtxCheck(dek, context),
	}

	// 1) 用激活 KEK 封装 DEK。封装 AAD 覆盖头部前缀（含 CTXCHECK），
	//    使头部前置字段与上下文校验值都受完整性保护。
	//    encDEK 长度由算法参数决定（nonce‖DEK‖tag），可预先确定，
	//    因此头部前缀先于封装构造；随后再回填真实字节。
	env.encDEK = make([]byte, wrapNonceSize+dekSize+gcmTagSize)
	headerPrefix := encodeV3HeaderPrefix(env)
	sealedDEK, err := gcmSeal(entry.key, wrapNonce, dek, buildV3WrapAAD(headerPrefix))
	if err != nil {
		return nil, err
	}
	env.encDEK = append(append([]byte{}, wrapNonce...), sealedDEK...)

	// 2) 用 DEK 加密真实明文。正文 AAD 覆盖完整头部（含 ENC_DEK），
	//    至此头部每一个字节都至少被一层 GCM 标签保护。
	header := make([]byte, 0, len(headerPrefix)+len(env.encDEK))
	header = append(header, headerPrefix...)
	header = append(header, env.encDEK...)
	ciphertext, err := gcmSeal(dek, payloadNonce, plaintext, buildV3PayloadAAD(header))
	if err != nil {
		return nil, err
	}
	env.ciphertext = ciphertext

	return encode(env), nil
}

// Open 按密文携带的密钥标识选择密钥解封装并验签解密。
// 等价于 OpenWithContext(raw, nil)。
func (s *EnvelopeService) Open(raw []byte) ([]byte, error) {
	return s.OpenWithContext(raw, nil)
}

// OpenWithContext 与 Open 相同，但要求调用方提供加密时绑定的同一段上下文。
// 上下文不一致返回 ErrContextMismatch；密文本身被改动返回 ErrCiphertextModified；
// 未知密钥、已撤销密钥、非法格式、未知版本均被明确拒绝，
// 绝不回退到其他密钥或静默返回明文。
func (s *EnvelopeService) OpenWithContext(raw, context []byte) ([]byte, error) {
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

	// 3) v3 走严格头部完整性 + 上下文绑定路径。
	if env.version == FormatV3 {
		return openV3(entry, env, raw, context)
	}

	// v1/v2 历史格式不携带上下文校验值，其隐式上下文为空：
	// 对历史密文提供非空上下文，视为上下文不匹配而明确拒绝。
	if len(context) != 0 {
		return nil, fmt.Errorf("%w: format v%d has no context binding (implicit empty context)",
			ErrContextMismatch, env.version)
	}

	// 4) 解封装 DEK。encDEK 内部前置了封装 nonce。
	if len(env.encDEK) < wrapNonceSize+gcmTagSize {
		return nil, fmt.Errorf("%w: wrapped DEK too short", ErrMalformedCiphertext)
	}
	wrapNonce := env.encDEK[:wrapNonceSize]
	sealedDEK := env.encDEK[wrapNonceSize:]
	dek, err := gcmOpen(entry.key, wrapNonce, sealedDEK, buildWrapAAD(env.version, env.keyID))
	if err != nil {
		// KEK 不匹配或封装块被改动，都表现为认证失败。
		return nil, fmt.Errorf("%w: DEK unwrap failed for key %q: %v",
			ErrCiphertextModified, env.keyID, err)
	}
	defer zeroize(dek)

	// 5) 用 DEK 验签并解密正文；任何字节被改动都会在此处失败。
	plaintext, err := gcmOpen(dek, env.nonce, env.ciphertext, buildPayloadAAD(env.version, env.keyID))
	if err != nil {
		return nil, fmt.Errorf("%w: payload open failed for key %q (format v%d): %v",
			ErrCiphertextModified, env.keyID, env.version, err)
	}
	return plaintext, nil
}

// openV3 按 v3 严格语义解密：头部全字段完整性保护 + 上下文绑定。
// raw 为原始密文字节，用于按线格式切片构造 AAD（与加密侧逐字节一致）。
func openV3(entry *keyEntry, env *envelope, raw, context []byte) ([]byte, error) {
	if len(env.encDEK) < wrapNonceSize+gcmTagSize {
		return nil, fmt.Errorf("%w: wrapped DEK too short", ErrMalformedCiphertext)
	}

	// 1) 解封装 DEK：AAD 覆盖 ENC_DEK 之前的全部头部字节。
	wrapNonce := env.encDEK[:wrapNonceSize]
	sealedDEK := env.encDEK[wrapNonceSize:]
	dek, err := gcmOpen(entry.key, wrapNonce, sealedDEK, buildV3WrapAAD(raw[:env.dekOff]))
	if err != nil {
		return nil, fmt.Errorf("%w: DEK unwrap failed for key %q (format v3): %v",
			ErrCiphertextModified, env.keyID, err)
	}
	defer zeroize(dek)

	// 2) 校验上下文：CTXCHECK 本身已被封装 AAD 保护，此处不匹配的
	//    唯一可能就是调用方提供的上下文与加密时不一致。
	if !hmac.Equal(computeCtxCheck(dek, context), env.ctxCheck) {
		return nil, fmt.Errorf("%w: key %q (format v3)", ErrContextMismatch, env.keyID)
	}

	// 3) 用 DEK 验签并解密正文：AAD 覆盖完整头部。
	plaintext, err := gcmOpen(dek, env.nonce, env.ciphertext, buildV3PayloadAAD(raw[:env.headerLen]))
	if err != nil {
		return nil, fmt.Errorf("%w: payload open failed for key %q (format v3): %v",
			ErrCiphertextModified, env.keyID, err)
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
	case FormatV3:
		return encodeV3(e)
	default:
		// 内部不变量：写路径只可能产生受支持版本。
		panic(fmt.Sprintf("envelope: unsupported internal format version 0x%02x", e.version))
	}
}

// buildWrapAAD 构造 v1/v2 的 DEK 封装附加认证数据，绑定格式版本与密钥标识。
// v1 保持最初的字节布局（历史兼容）；v2 起把版本字节纳入 AAD，
// 使任一版本的密文都无法按另一版本的布局重排后通过验签。
func buildWrapAAD(version byte, keyID string) []byte {
	aad := make([]byte, 0, len(aadDEKWrap)+1+1+1+len(keyID))
	aad = append(aad, aadDEKWrap...)
	aad = append(aad, 0)
	if version != FormatV1 {
		aad = append(aad, version, 0)
	}
	aad = append(aad, keyID...)
	return aad
}

// buildPayloadAAD 构造 v1/v2 的正文加密附加认证数据，规则同 buildWrapAAD。
func buildPayloadAAD(version byte, keyID string) []byte {
	aad := make([]byte, 0, len(aadPayload)+1+1+1+len(keyID))
	aad = append(aad, aadPayload...)
	aad = append(aad, 0)
	if version != FormatV1 {
		aad = append(aad, version, 0)
	}
	aad = append(aad, keyID...)
	return aad
}

// buildV3WrapAAD 构造 v3 DEK 封装的 AAD：域常量 || 头部前缀（MAGIC..DEKLEN）。
// 头部前缀包含 FLAGS/KEYID/NONCE/TIMESTAMP/CTXCHECK 等全部前置字段，
// 因此这些字段中任何一字节被改动都会使解封装验签失败。
func buildV3WrapAAD(headerPrefix []byte) []byte {
	aad := make([]byte, 0, len(aadDEKWrapV3)+1+len(headerPrefix))
	aad = append(aad, aadDEKWrapV3...)
	aad = append(aad, 0)
	aad = append(aad, headerPrefix...)
	return aad
}

// buildV3PayloadAAD 构造 v3 正文加密的 AAD：域常量 || 完整头部（MAGIC..ENC_DEK）。
// 与封装 AAD 合并后，v3 头部的每一个字节都至少被一层 GCM 标签覆盖。
func buildV3PayloadAAD(header []byte) []byte {
	aad := make([]byte, 0, len(aadPayloadV3)+1+len(header))
	aad = append(aad, aadPayloadV3...)
	aad = append(aad, 0)
	aad = append(aad, header...)
	return aad
}

// computeCtxCheck 以 DEK 为密钥对调用方上下文计算 HMAC-SHA256 校验值。
// 密钥是每次加密随机生成的 DEK，因此该校验值不泄露上下文内容，
// 也无法在不知道 DEK 的情况下被伪造或离线穷举。
func computeCtxCheck(dek, context []byte) []byte {
	mac := hmac.New(sha256.New, dek)
	mac.Write(aadCtxCheck)
	mac.Write([]byte{0})
	mac.Write(context)
	return mac.Sum(nil)
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
