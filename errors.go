package envelope

import (
	"errors"
	"strings"
)

// Error 是本包所有可归类失败的统一错误类型。
// Reason 为可比较的哨兵原因，KeyID/Debug 提供可解释的判定依据。
type Error struct {
	Reason error
	KeyID  string
	Detail string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Reason.Error())
	if e.KeyID != "" {
		b.WriteString(" (key id: ")
		b.WriteString(e.KeyID)
		b.WriteString(")")
	}
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	return b.String()
}

// Unwrap 使 errors.Is(err, ErrXxx) 可以命中具体原因。
func (e *Error) Unwrap() error { return e.Reason }

// wrapErr 构造携带判定依据的归类错误；reason 必须是包内哨兵错误。
func wrapErr(reason error, keyID, detail string) *Error {
	return &Error{Reason: reason, KeyID: keyID, Detail: detail}
}

// 可区分的失败原因。
var (
	// ErrUnknownKey 密文携带的密钥标识在密钥环中不存在。
	ErrUnknownKey = errors.New("envelope: unknown key id")
	// ErrKeyDisabled 密钥标识存在但已停用，不允许再用于解密或封装。
	ErrKeyDisabled = errors.New("envelope: key is disabled")
	// ErrCiphertextTampered 密文通过了格式校验但认证标签校验失败。
	ErrCiphertextTampered = errors.New("envelope: ciphertext is tampered or corrupted")
	// ErrInvalidFormat 密文结构非法（长度、编码等不符合任何已知版本）。
	ErrInvalidFormat = errors.New("envelope: invalid ciphertext format")
	// ErrUnsupportedVersion 密文版本号无法识别，拒绝按当前格式误解析。
	ErrUnsupportedVersion = errors.New("envelope: unsupported ciphertext version")
	// ErrNoActiveKey 密钥环中没有可用于封装的激活密钥。
	ErrNoActiveKey = errors.New("envelope: no active key")
)
