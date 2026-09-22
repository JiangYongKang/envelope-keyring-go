package envelope

import (
	"errors"
	"fmt"
	"sync"
)

// KeyStatus 表示密钥在密钥环中的生命周期状态。
type KeyStatus int

const (
	// StatusActive 激活：可用于封装新数据，也可解密。
	StatusActive KeyStatus = iota
	// StatusRetired 停用：仅保留用于解密历史密文，不能再封装新数据。
	StatusRetired
	// StatusRevoked 撤销：禁止任何用途，命中即失败。
	StatusRevoked
)

// String 返回状态的可解释名称，用于日志与错误信息。
func (s KeyStatus) String() string {
	switch s {
	case StatusActive:
		return "active"
	case StatusRetired:
		return "retired"
	case StatusRevoked:
		return "revoked"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// keyEntry 是密钥环中单个版本密钥的内部条目。
// key 为 AES-256（32 字节）主密钥材料，仅存在于内存且永不对外暴露。
type keyEntry struct {
	id     string
	key    []byte
	status KeyStatus
}

// KeyInfo 是对外暴露的密钥元信息（不含密钥材料）。
type KeyInfo struct {
	ID     string
	Status KeyStatus
}

// KeyRing 是并发安全的多版本本地密钥环。
// 同一时刻至多有一个激活密钥；轮换 = 追加新激活密钥并将旧激活密钥停用。
// 读路径（Seal/Open 查找密钥）持 RLock，轮换/撤销持 Lock，二者可安全并发。
type KeyRing struct {
	mu      sync.RWMutex
	entries map[string]*keyEntry
	active  string // 当前激活密钥标识；空串表示无激活密钥
}

// NewKeyRing 创建空密钥环。
func NewKeyRing() *KeyRing {
	return &KeyRing{entries: make(map[string]*keyEntry)}
}

// AddKey 向密钥环追加一个版本密钥。
// activate 为 true 时，该密钥成为唯一激活密钥，此前的激活密钥转为停用
// （仍保留用于解密历史密文）。
func (r *KeyRing) AddKey(id string, key []byte, activate bool) error {
	if id == "" {
		return fmt.Errorf("%w: empty key id", ErrInvalidKey)
	}
	if len(key) != dekSize {
		return fmt.Errorf("%w: key %q requires %d bytes, got %d",
			ErrInvalidKey, id, dekSize, len(key))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.entries[id]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateKeyID, id)
	}

	// 拷贝一份，避免调用方在外部切片被修改后影响内存中的密钥材料。
	material := make([]byte, len(key))
	copy(material, key)

	entry := &keyEntry{id: id, key: material, status: StatusRetired}
	r.entries[id] = entry

	if activate {
		if r.active != "" {
			r.entries[r.active].status = StatusRetired
		}
		entry.status = StatusActive
		r.active = id
	}
	return nil
}

// Rotate 追加新密钥并激活；旧激活密钥保留为停用，可继续解密历史密文。
// 与并发的 Seal/Open 安全共存：读操作要么看到轮换前、要么看到轮换后的
// 完整一致状态，不会观察到中间态。
func (r *KeyRing) Rotate(id string, key []byte) error {
	return r.AddKey(id, key, true)
}

// Revoke 将指定密钥标记为撤销。此后命中该密钥的密文一律拒绝解密，
// 且若撤销的是当前激活密钥，密钥环将进入无激活状态（直至再次轮换）。
func (r *KeyRing) Revoke(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.entries[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownKey, id)
	}
	e.status = StatusRevoked
	if r.active == id {
		r.active = ""
	}
	return nil
}

// ActiveKeyID 返回当前激活密钥标识；无激活密钥时返回 ErrNoActiveKey。
func (r *KeyRing) ActiveKeyID() (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.active == "" {
		return "", ErrNoActiveKey
	}
	return r.active, nil
}

// Keys 返回密钥环内所有密钥的元信息快照（不含密钥材料）。
func (r *KeyRing) Keys() []KeyInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]KeyInfo, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, KeyInfo{ID: e.id, Status: e.status})
	}
	return out
}

// lookupActive 在读锁下返回当前激活条目；供 Seal 使用。
func (r *KeyRing) lookupActive() (*keyEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.active == "" {
		return nil, ErrNoActiveKey
	}
	return r.entries[r.active], nil
}

// lookupByID 在读锁下按标识返回条目，并依据状态给出可区分的结论：
// 未知标识 -> ErrUnknownKey；已撤销 -> ErrKeyRevoked。
// 停用（retired）密钥正常返回，因为它仍须服务历史密文解密。
func (r *KeyRing) lookupByID(id string) (*keyEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	e, ok := r.entries[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, id)
	}
	if e.status == StatusRevoked {
		return nil, fmt.Errorf("%w: %s", ErrKeyRevoked, id)
	}
	return e, nil
}

// 保证未被意外删除的 errors 引用（后续实现复用）。
var _ = errors.Is
