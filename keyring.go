package envelope

import (
	"fmt"
	"sync"
	"time"
)

// keyMaterialLen 是主密钥（KEK）要求的随机字节长度（AES-256）。
const keyMaterialLen = 32

// Key 表示密钥环中的一个版本的主密钥（KEK）。
// material 永不出现在密文或错误信息中。
type Key struct {
	id        string
	material  []byte
	active    bool
	disabled  bool
	createdAt int64
}

// ID 返回密钥标识（该标识会以明文形式写入密文头）。
func (k *Key) ID() string { return k.id }

// Keyring 是并发安全的多版本密钥环。
// 同一时刻至多有一个激活密钥；轮换只会追加新版本，历史密钥保留用于解密。
type Keyring struct {
	mu       sync.RWMutex
	keys     map[string]*Key
	activeID string
}

// NewKeyring 创建空密钥环。
func NewKeyring() *Keyring {
	return &Keyring{keys: map[string]*Key{}}
}

// AddKey 向密钥环登记一个密钥；activate 为 true 时同时将其置为激活。
// 重复标识、空标识或非法密钥材料会被拒绝。
func (kr *Keyring) AddKey(id string, material []byte, activate bool) error {
	if id == "" {
		return wrapErr(ErrInvalidFormat, id, "key id must not be empty")
	}
	if len(material) != keyMaterialLen {
		return wrapErr(ErrInvalidFormat, id,
			fmt.Sprintf("key material must be %d bytes, got %d", keyMaterialLen, len(material)))
	}

	kr.mu.Lock()
	defer kr.mu.Unlock()
	if _, exists := kr.keys[id]; exists {
		return wrapErr(ErrInvalidFormat, id, "key id already exists in keyring")
	}
	mat := make([]byte, len(material))
	copy(mat, material)
	kr.keys[id] = &Key{
		id:        id,
		material:  mat,
		active:    activate,
		createdAt: time.Now().UnixNano(),
	}
	if activate {
		kr.activeID = id
	}
	return nil
}

// Rotate 追加一个新的激活密钥；此前的激活密钥转为非激活但仍保留用于解密历史密文。
func (kr *Keyring) Rotate(id string, material []byte) error {
	if id == "" {
		return wrapErr(ErrInvalidFormat, id, "key id must not be empty")
	}
	if len(material) != keyMaterialLen {
		return wrapErr(ErrInvalidFormat, id,
			fmt.Sprintf("key material must be %d bytes, got %d", keyMaterialLen, len(material)))
	}

	kr.mu.Lock()
	defer kr.mu.Unlock()
	if _, exists := kr.keys[id]; exists {
		return wrapErr(ErrInvalidFormat, id, "key id already exists in keyring")
	}
	if prev := kr.keys[kr.activeID]; prev != nil {
		prev.active = false
	}
	mat := make([]byte, len(material))
	copy(mat, material)
	kr.keys[id] = &Key{
		id:        id,
		material:  mat,
		active:    true,
		createdAt: time.Now().UnixNano(),
	}
	kr.activeID = id
	return nil
}

// DisableKey 停用一个历史密钥：停用后其标识可识别但解密将被拒绝（ErrKeyDisabled）。
// 不允许直接停用当前激活密钥，以避免出现“新数据无密钥可用”的窗口。
func (kr *Keyring) DisableKey(id string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()
	k, ok := kr.keys[id]
	if !ok {
		return wrapErr(ErrUnknownKey, id, "cannot disable a key not present in keyring")
	}
	if kr.activeID == id {
		return wrapErr(ErrKeyDisabled, id, "refusing to disable the currently active key; rotate first")
	}
	k.active = false
	k.disabled = true
	return nil
}

// ActiveKey 返回当前激活密钥的快照（材料为拷贝）。
// 快照语义保证调用方在一次加解密中使用的密钥不会被并发轮换改变。
func (kr *Keyring) ActiveKey() (*Key, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	if kr.activeID == "" {
		return nil, wrapErr(ErrNoActiveKey, "", "keyring has no active key")
	}
	k := kr.keys[kr.activeID]
	return snapshotKey(k), nil
}

// KeyFor 按标识返回密钥快照：
// 未知标识返回 ErrUnknownKey；存在但停用返回 ErrKeyDisabled。
func (kr *Keyring) KeyFor(id string) (*Key, error) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	k, ok := kr.keys[id]
	if !ok {
		return nil, wrapErr(ErrUnknownKey, id, "no key with this id in keyring")
	}
	// 历史密钥在轮换后 active=false 但仍允许用于解密；
	// 只有被显式 DisableKey 停用的密钥才拒绝。
	if k.disabled {
		return nil, wrapErr(ErrKeyDisabled, id, "key retained in keyring but explicitly disabled")
	}
	return snapshotKey(k), nil
}

// snapshotKey 返回密钥的副本，使调用方无法通过指针修改密钥环内部状态。
func snapshotKey(k *Key) *Key {
	mat := make([]byte, len(k.material))
	copy(mat, k.material)
	return &Key{
		id:        k.id,
		material:  mat,
		active:    k.active,
		disabled:  k.disabled,
		createdAt: k.createdAt,
	}
}
