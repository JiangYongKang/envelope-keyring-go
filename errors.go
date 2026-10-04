// Package envelope 提供基于本地密钥环（keyring）的信封加密、
// 解密、密钥轮换以及密文格式版本演进能力。
package envelope

import "errors"

// 可区分的哨兵错误：调用方可通过 errors.Is 精确归类失败原因。
var (
	// ErrUnknownKey 密文携带的密钥标识在密钥环中不存在。
	ErrUnknownKey = errors.New("envelope: unknown key id")

	// ErrKeyRevoked 密钥标识存在但已被撤销，禁止用于任何解密。
	ErrKeyRevoked = errors.New("envelope: key revoked")

	// ErrKeyRetired 密钥已停用：仍可解密历史密文，但不能再封装新数据。
	ErrKeyRetired = errors.New("envelope: key retired, cannot seal new data")

	// ErrNoActiveKey 密钥环中没有可用于封装新数据的激活密钥。
	ErrNoActiveKey = errors.New("envelope: no active key in keyring")

	// ErrCiphertextModified 密文未通过认证标签校验，判定为被篡改或损坏。
	ErrCiphertextModified = errors.New("envelope: ciphertext authentication failed (tampered or corrupted)")

	// ErrMalformedCiphertext 密文字节序列不符合任一受支持版本的格式。
	ErrMalformedCiphertext = errors.New("envelope: malformed ciphertext")

	// ErrUnsupportedVersion 密文格式版本号无法识别。
	ErrUnsupportedVersion = errors.New("envelope: unsupported ciphertext format version")

	// ErrDuplicateKeyID 轮换时追加了密钥环中已存在的密钥标识。
	ErrDuplicateKeyID = errors.New("envelope: duplicate key id")

	// ErrInvalidKey 密钥材料不合法（例如长度不符合 AES-256 要求）。
	ErrInvalidKey = errors.New("envelope: invalid key material")

	// ErrEmptyPlaintext 不允许加密空明文。
	ErrEmptyPlaintext = errors.New("envelope: empty plaintext")

	// ErrContextMismatch 解密时提供的加密上下文与加密时绑定的上下文不一致。
	// 与 ErrCiphertextModified 明确区分：前者是“调用方拿错了上下文”，
	// 后者是“密文字节本身被改动”。
	ErrContextMismatch = errors.New("envelope: encryption context mismatch")
)
