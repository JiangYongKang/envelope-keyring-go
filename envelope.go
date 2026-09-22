package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// EnvelopeCipher 在密钥环之上执行信封加密：随机数据密钥 DEK 加密明文，
// DEK 再由激活 KEK 封装；密文自描述所使用的 KEK 标识与格式版本。
type EnvelopeCipher struct {
	keyring *Keyring
}

// NewEnvelopeCipher 绑定一个密钥环。
func NewEnvelopeCipher(kr *Keyring) *EnvelopeCipher {
	return &EnvelopeCipher{keyring: kr}
}

// gcmFromKey 用 KEK 材料构造 AES-256-GCM。
func gcmFromKey(k *Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.material)
	if err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot build AES cipher from key material: "+err.Error())
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot build GCM: "+err.Error())
	}
	return g, nil
}

// Encrypt 使用当前激活密钥封装新数据，密文始终以 currentFormat 写出。
// aad 作为附加认证数据同时绑定到 DEK 封装与数据加密两层。
func (c *EnvelopeCipher) Encrypt(plaintext, aad []byte) ([]byte, error) {
	k, err := c.keyring.ActiveKey()
	if err != nil {
		return nil, err
	}

	// 1. 生成随机数据密钥 DEK。
	dek := make([]byte, keyMaterialLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot generate DEK: "+err.Error())
	}

	// 2. 用激活 KEK 封装 DEK；封装 nonce 与数据 nonce 独立生成。
	kekAEAD, err := gcmFromKey(k)
	if err != nil {
		wipe(dek)
		return nil, err
	}
	wrapNonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(wrapNonce); err != nil {
		wipe(dek)
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot generate wrap nonce: "+err.Error())
	}
	// 封装层 AAD 绑定密钥标识与版本，防止跨密钥/跨格式重放。
	wrappedDEK := kekAEAD.Seal(nil, wrapNonce, dek, wrapAAD(k.id, currentFormat, aad))

	// 3. 用 DEK 加密明文（数据层使用独立 nonce）。
	dekBlock, err := aes.NewCipher(dek)
	wipe(dek)
	if err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot build DEK cipher: "+err.Error())
	}
	dataAEAD, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot build DEK GCM: "+err.Error())
	}
	dataNonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot generate data nonce: "+err.Error())
	}
	ct := dataAEAD.Seal(nil, dataNonce, plaintext, dataAAD(aad))

	// 两个 nonce 拼接存放（V1 固定 24 字节，V2 显式长度字段）。
	nonces := append(append([]byte{}, wrapNonce...), dataNonce...)
	return encode(currentFormat, k.id, nonces, wrappedDEK, ct)
}

// Decrypt 按密文携带的密钥标识选择对应密钥解封并验证明文。
// 未知/停用密钥、篡改、非法格式均被拒绝并返回对应哨兵原因，
// 任何一步认证失败都不会返回明文。
func (c *EnvelopeCipher) Decrypt(ciphertext, aad []byte) (plaintext []byte, err error) {
	p, err := decode(ciphertext)
	if err != nil {
		return nil, err
	}

	// 密钥选择只依据密文自描述的标识；找不到或已停用立即拒绝，绝不回退。
	k, err := c.keyring.KeyFor(p.keyID)
	if err != nil {
		return nil, err
	}

	// nonce 段为 封装nonce||数据nonce，各 12 字节。
	if len(p.nonce) != gcmNonceSize*2 {
		return nil, wrapErr(ErrInvalidFormat, p.keyID, "expected 24-byte concatenated nonce")
	}
	wrapNonce := p.nonce[:gcmNonceSize]
	dataNonce := p.nonce[gcmNonceSize:]

	kekAEAD, err := gcmFromKey(k)
	if err != nil {
		return nil, err
	}

	// 第一层：解封 DEK。认证失败 => 篡改（AAD 不一致、nonce/封装密文被改、密钥不符）。
	dek, err := kekAEAD.Open(nil, wrapNonce, p.wrappedDEK, wrapAAD(p.keyID, p.version, aad))
	if err != nil {
		return nil, wrapErr(ErrCiphertextTampered, p.keyID,
			"DEK unwrap authentication failed (wrong key context, AAD mismatch, or tampering)")
	}
	defer wipe(dek)

	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, wrapErr(ErrInvalidFormat, p.keyID, "unwrapped DEK is invalid")
	}
	dataAEAD, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, wrapErr(ErrInvalidFormat, p.keyID, "cannot build GCM from unwrapped DEK")
	}

	// 第二层：解密并认证数据。失败同样归类为篡改。
	pt, err := dataAEAD.Open(nil, dataNonce, p.ciphertext, dataAAD(aad))
	if err != nil {
		return nil, wrapErr(ErrCiphertextTampered, p.keyID,
			"payload authentication failed (ciphertext/AAD tampered)")
	}
	return pt, nil
}

// wrapAAD 构造封装层附加数据，区分两层、绑定版本与密钥标识。
func wrapAAD(keyID string, v formatVersion, aad []byte) []byte {
	out := make([]byte, 0, 16+len(keyID)+len(aad))
	out = append(out, []byte("envelope-wrap-v")...)
	out = append(out, byte(v))
	out = append(out, 0)
	out = append(out, []byte(keyID)...)
	out = append(out, 0)
	out = append(out, aad...)
	return out
}

// dataAAD 构造数据层附加数据（域分隔，避免两层 AAD 混用）。
func dataAAD(aad []byte) []byte {
	out := make([]byte, 0, 16+len(aad))
	out = append(out, []byte("envelope-data-v1")...)
	out = append(out, aad...)
	return out
}

// wipe 用零覆写敏感材料，尽量缩短 DEK 在内存中的停留时间。
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// encryptWithVersion 与 Encrypt 相同，但允许指定写出版本（用于生成历史格式密文）。
func (c *EnvelopeCipher) encryptWithVersion(v formatVersion, plaintext, aad []byte) ([]byte, error) {
	k, err := c.keyring.ActiveKey()
	if err != nil {
		return nil, err
	}
	dek := make([]byte, keyMaterialLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot generate DEK: "+err.Error())
	}
	kekAEAD, err := gcmFromKey(k)
	if err != nil {
		wipe(dek)
		return nil, err
	}
	wrapNonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(wrapNonce); err != nil {
		wipe(dek)
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot generate wrap nonce: "+err.Error())
	}
	wrappedDEK := kekAEAD.Seal(nil, wrapNonce, dek, wrapAAD(k.id, v, aad))

	dekBlock, err := aes.NewCipher(dek)
	wipe(dek)
	if err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot build DEK cipher: "+err.Error())
	}
	dataAEAD, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot build DEK GCM: "+err.Error())
	}
	dataNonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, wrapErr(ErrInvalidFormat, k.id, "cannot generate data nonce: "+err.Error())
	}
	ct := dataAEAD.Seal(nil, dataNonce, plaintext, dataAAD(aad))
	nonces := append(append([]byte{}, wrapNonce...), dataNonce...)
	return encode(v, k.id, nonces, wrappedDEK, ct)
}
