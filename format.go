package envelope

import (
	"encoding/binary"
	"fmt"
)

// 密文格式版本号。
const (
	// FormatV1 线格式：
	//   MAGIC(4) | VER(1)=0x01 | KEYIDLEN(1) | KEYID |
	//   DEKLEN(2 BE) | ENC_DEK(=DEKLEN) | NONCE(12 定长) | CIPHERTEXT+TAG(变长)
	FormatV1 byte = 0x01

	// FormatV2 线格式：
	//   MAGIC(4) | VER(1)=0x02 | FLAGS(1) | KEYIDLEN(2 BE) | KEYID |
	//   DEKLEN(2 BE) | ENC_DEK(=DEKLEN) | NONCELEN(1) | NONCE |
	//   TIMESTAMP(8 BE) | CIPHERTEXT+TAG(变长)
	// 相对 v1 的演进：密钥标识长度扩展为 2 字节、nonce 长度自描述、
	// 新增 8 字节时间戳，并保留 FLAGS 位供未来特性协商。
	FormatV2 byte = 0x02

	// FormatV3 线格式（当前写出版本，严格头部完整性 + 上下文绑定）：
	//   MAGIC(4) | VER(1)=0x03 | FLAGS(1) | KEYIDLEN(2 BE) | KEYID |
	//   NONCELEN(1) | NONCE | TIMESTAMP(8 BE) | CTXCHECK(32) |
	//   DEKLEN(2 BE) | ENC_DEK(=DEKLEN) | CIPHERTEXT+TAG(变长)
	// 相对 v2 的演进：
	//   - 头部每一字节都被 GCM AAD 覆盖（见 envelope.go 的 v3 AAD 构造），
	//     改动头部任意字段都会在验签阶段被拒绝；
	//   - 新增 CTXCHECK：以 DEK 为密钥对调用方上下文计算的 HMAC-SHA256，
	//     用于把“上下文不匹配”与“密文被篡改”区分开；
	//   - ENC_DEK 移到头部末尾，使“ENC_DEK 之前的全部字节”可直接作为
	//     封装操作的 AAD 前缀切片。
	FormatV3 byte = 0x03

	// currentFormat 是新写入密文使用的格式版本。
	currentFormat = FormatV3
)

// 各字段边界，用于解析时严格拒绝长度欺骗/截断数据。
const (
	magicSize       = 4
	v1NonceSize     = 12
	gcmTagSize      = 16
	ctxCheckSize    = 32 // v3 CTXCHECK：HMAC-SHA256 输出长度
	maxKeyIDLenV2   = 65535
	maxDEKLenV2     = 65535
	maxNonceLenV2   = 255
	maxTimestampOff = 1<<63 - 1
)

// formatMagic 是所有受支持密文共有的魔数，用于快速排除非本格式数据。
var formatMagic = [4]byte{'E', 'K', 'R', '1'}

// envelope 是解析后的密文结构（与具体线格式版本无关的内部表示）。
type envelope struct {
	version    byte
	keyID      string
	encDEK     []byte // 经 KEK 封装后的数据密钥
	nonce      []byte
	ciphertext []byte // 含 GCM 认证标签
	timestamp  int64  // v2/v3 携带；v1 为零值
	flags      byte   // v2/v3 携带；v1 为零值
	ctxCheck   []byte // v3 携带：上下文的 HMAC 校验值；v1/v2 为 nil

	// 解析期记录的线格式偏移（仅 v3 的 AAD 构造与测试定位使用）：
	// dekOff 是 ENC_DEK 在原始字节中的起始偏移（其前为头部前缀，含 DEKLEN）；
	// headerLen 是 CIPHERTEXT 的起始偏移（即完整头部长度）。
	dekOff    int
	headerLen int
}

// encodeV1 按 v1 线格式序列化。
func encodeV1(e *envelope) []byte {
	keyID := []byte(e.keyID)
	out := make([]byte, 0, magicSize+1+1+len(keyID)+2+len(e.encDEK)+len(e.nonce)+len(e.ciphertext))
	out = append(out, formatMagic[:]...)
	out = append(out, FormatV1)
	out = append(out, byte(len(keyID)))
	out = append(out, keyID...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(e.encDEK)))
	out = append(out, e.encDEK...)
	out = append(out, e.nonce...)
	out = append(out, e.ciphertext...)
	return out
}

// encodeV2 按 v2 线格式序列化。
func encodeV2(e *envelope) []byte {
	keyID := []byte(e.keyID)
	out := make([]byte, 0, magicSize+1+1+2+len(keyID)+2+len(e.encDEK)+1+len(e.nonce)+8+len(e.ciphertext))
	out = append(out, formatMagic[:]...)
	out = append(out, FormatV2)
	out = append(out, e.flags)
	out = binary.BigEndian.AppendUint16(out, uint16(len(keyID)))
	out = append(out, keyID...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(e.encDEK)))
	out = append(out, e.encDEK...)
	out = append(out, byte(len(e.nonce)))
	out = append(out, e.nonce...)
	out = binary.BigEndian.AppendUint64(out, uint64(e.timestamp))
	out = append(out, e.ciphertext...)
	return out
}

// encodeV3HeaderPrefix 序列化 v3 头部前缀（MAGIC 起、DEKLEN 止，不含 ENC_DEK）。
// 该前缀同时作为 DEK 封装操作的 AAD 组成部分，因此序列化必须规范、确定。
// 调用前必须已填好 e.nonce、e.timestamp、e.ctxCheck、e.encDEK（长度）。
func encodeV3HeaderPrefix(e *envelope) []byte {
	keyID := []byte(e.keyID)
	out := make([]byte, 0, magicSize+1+1+2+len(keyID)+1+len(e.nonce)+8+ctxCheckSize+2)
	out = append(out, formatMagic[:]...)
	out = append(out, FormatV3)
	out = append(out, e.flags)
	out = binary.BigEndian.AppendUint16(out, uint16(len(keyID)))
	out = append(out, keyID...)
	out = append(out, byte(len(e.nonce)))
	out = append(out, e.nonce...)
	out = binary.BigEndian.AppendUint64(out, uint64(e.timestamp))
	out = append(out, e.ctxCheck...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(e.encDEK)))
	return out
}

// encodeV3 按 v3 线格式序列化：头部前缀 || ENC_DEK || CIPHERTEXT+TAG。
func encodeV3(e *envelope) []byte {
	prefix := encodeV3HeaderPrefix(e)
	out := make([]byte, 0, len(prefix)+len(e.encDEK)+len(e.ciphertext))
	out = append(out, prefix...)
	out = append(out, e.encDEK...)
	out = append(out, e.ciphertext...)
	return out
}

// parseEnvelope 严格解析任意受支持版本的密文。
// 错误归类：
//   - 魔数错误、截断、长度字段越界、字段过短：ErrMalformedCiphertext；
//   - 魔数正确但版本号无法识别：ErrUnsupportedVersion。
func parseEnvelope(raw []byte) (*envelope, error) {
	if len(raw) < magicSize+1 {
		return nil, fmt.Errorf("%w: input too short (%d bytes)", ErrMalformedCiphertext, len(raw))
	}
	for i := 0; i < magicSize; i++ {
		if raw[i] != formatMagic[i] {
			return nil, fmt.Errorf("%w: bad magic prefix", ErrMalformedCiphertext)
		}
	}
	version := raw[magicSize]
	switch version {
	case FormatV1:
		return parseV1(raw)
	case FormatV2:
		return parseV2(raw)
	case FormatV3:
		return parseV3(raw)
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, version)
	}
}

// parseV1 解析 v1 密文，所有长度均做边界校验。
func parseV1(raw []byte) (*envelope, error) {
	// 最小长度：MAGIC(4) VER(1) KEYIDLEN(1) DEKLEN(2) NONCE(12) TAG(16)
	const minV1 = magicSize + 1 + 1 + 2 + v1NonceSize + gcmTagSize

	pos := magicSize + 1 // 跳过魔数与版本号
	if len(raw) < minV1 {
		return nil, fmt.Errorf("%w: v1 input too short (%d bytes)", ErrMalformedCiphertext, len(raw))
	}

	keyIDLen := int(raw[pos])
	pos++
	if pos+keyIDLen+2 > len(raw) {
		return nil, fmt.Errorf("%w: v1 key id length %d exceeds bounds", ErrMalformedCiphertext, keyIDLen)
	}
	keyID := string(raw[pos : pos+keyIDLen])
	pos += keyIDLen

	dekLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	if dekLen == 0 {
		return nil, fmt.Errorf("%w: v1 zero-length wrapped DEK", ErrMalformedCiphertext)
	}
	if pos+dekLen+v1NonceSize+gcmTagSize > len(raw) {
		return nil, fmt.Errorf("%w: v1 dek length %d exceeds bounds", ErrMalformedCiphertext, dekLen)
	}
	dekOff := pos
	encDEK := raw[pos : pos+dekLen]
	pos += dekLen

	nonce := raw[pos : pos+v1NonceSize]
	pos += v1NonceSize

	// 剩余部分必须至少容纳 GCM 认证标签；正文允许为空（GCM 仍产出 16 字节标签）。
	ciphertext := raw[pos:]
	if len(ciphertext) < gcmTagSize {
		return nil, fmt.Errorf("%w: v1 payload shorter than GCM tag", ErrMalformedCiphertext)
	}

	return &envelope{
		version:    FormatV1,
		keyID:      keyID,
		encDEK:     encDEK,
		nonce:      nonce,
		ciphertext: ciphertext,
		dekOff:     dekOff,
		headerLen:  pos,
	}, nil
}

// parseV2 解析 v2 密文，所有长度均做边界校验。
func parseV2(raw []byte) (*envelope, error) {
	// 最小长度：MAGIC(4) VER(1) FLAGS(1) KEYIDLEN(2) DEKLEN(2)
	// NONCELEN(1) TIMESTAMP(8) TAG(16)
	const minV2 = magicSize + 1 + 1 + 2 + 2 + 1 + 8 + gcmTagSize

	pos := magicSize + 1
	if len(raw) < minV2 {
		return nil, fmt.Errorf("%w: v2 input too short (%d bytes)", ErrMalformedCiphertext, len(raw))
	}

	flags := raw[pos]
	pos++

	keyIDLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	if keyIDLen == 0 {
		return nil, fmt.Errorf("%w: v2 empty key id", ErrMalformedCiphertext)
	}
	if pos+keyIDLen+2 > len(raw) {
		return nil, fmt.Errorf("%w: v2 key id length %d exceeds bounds", ErrMalformedCiphertext, keyIDLen)
	}
	keyID := string(raw[pos : pos+keyIDLen])
	pos += keyIDLen

	dekLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	if dekLen == 0 {
		return nil, fmt.Errorf("%w: v2 zero-length wrapped DEK", ErrMalformedCiphertext)
	}
	if pos+dekLen+1 > len(raw) {
		return nil, fmt.Errorf("%w: v2 dek length %d exceeds bounds", ErrMalformedCiphertext, dekLen)
	}
	dekOff := pos
	encDEK := raw[pos : pos+dekLen]
	pos += dekLen

	nonceLen := int(raw[pos])
	pos++
	if nonceLen == 0 {
		return nil, fmt.Errorf("%w: v2 zero-length nonce", ErrMalformedCiphertext)
	}
	if pos+nonceLen+8+gcmTagSize > len(raw) {
		return nil, fmt.Errorf("%w: v2 nonce length %d exceeds bounds", ErrMalformedCiphertext, nonceLen)
	}
	nonce := raw[pos : pos+nonceLen]
	pos += nonceLen

	ts := int64(binary.BigEndian.Uint64(raw[pos : pos+8]))
	pos += 8

	ciphertext := raw[pos:]
	if len(ciphertext) < gcmTagSize {
		return nil, fmt.Errorf("%w: v2 payload shorter than GCM tag", ErrMalformedCiphertext)
	}

	return &envelope{
		version:    FormatV2,
		keyID:      keyID,
		encDEK:     encDEK,
		nonce:      nonce,
		ciphertext: ciphertext,
		timestamp:  ts,
		flags:      flags,
		dekOff:     dekOff,
		headerLen:  pos,
	}, nil
}

// parseV3 解析 v3 密文，所有长度均做边界校验。
// 布局：MAGIC(4) VER(1) FLAGS(1) KEYIDLEN(2) KEYID NONCELEN(1) NONCE
// TIMESTAMP(8) CTXCHECK(32) DEKLEN(2) ENC_DEK CIPHERTEXT+TAG。
func parseV3(raw []byte) (*envelope, error) {
	// 最小长度：MAGIC(4) VER(1) FLAGS(1) KEYIDLEN(2) NONCELEN(1)
	// TIMESTAMP(8) CTXCHECK(32) DEKLEN(2) TAG(16)
	const minV3 = magicSize + 1 + 1 + 2 + 1 + 8 + ctxCheckSize + 2 + gcmTagSize

	pos := magicSize + 1
	if len(raw) < minV3 {
		return nil, fmt.Errorf("%w: v3 input too short (%d bytes)", ErrMalformedCiphertext, len(raw))
	}

	flags := raw[pos]
	pos++

	keyIDLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	if keyIDLen == 0 {
		return nil, fmt.Errorf("%w: v3 empty key id", ErrMalformedCiphertext)
	}
	if pos+keyIDLen+1 > len(raw) {
		return nil, fmt.Errorf("%w: v3 key id length %d exceeds bounds", ErrMalformedCiphertext, keyIDLen)
	}
	keyID := string(raw[pos : pos+keyIDLen])
	pos += keyIDLen

	nonceLen := int(raw[pos])
	pos++
	if nonceLen == 0 {
		return nil, fmt.Errorf("%w: v3 zero-length nonce", ErrMalformedCiphertext)
	}
	if pos+nonceLen+8+ctxCheckSize+2 > len(raw) {
		return nil, fmt.Errorf("%w: v3 nonce length %d exceeds bounds", ErrMalformedCiphertext, nonceLen)
	}
	nonce := raw[pos : pos+nonceLen]
	pos += nonceLen

	ts := int64(binary.BigEndian.Uint64(raw[pos : pos+8]))
	pos += 8

	ctxCheck := raw[pos : pos+ctxCheckSize]
	pos += ctxCheckSize

	dekLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	if dekLen == 0 {
		return nil, fmt.Errorf("%w: v3 zero-length wrapped DEK", ErrMalformedCiphertext)
	}
	if pos+dekLen+gcmTagSize > len(raw) {
		return nil, fmt.Errorf("%w: v3 dek length %d exceeds bounds", ErrMalformedCiphertext, dekLen)
	}
	dekOff := pos
	encDEK := raw[pos : pos+dekLen]
	pos += dekLen

	ciphertext := raw[pos:]
	if len(ciphertext) < gcmTagSize {
		return nil, fmt.Errorf("%w: v3 payload shorter than GCM tag", ErrMalformedCiphertext)
	}

	return &envelope{
		version:    FormatV3,
		keyID:      keyID,
		encDEK:     encDEK,
		nonce:      nonce,
		ciphertext: ciphertext,
		timestamp:  ts,
		flags:      flags,
		ctxCheck:   ctxCheck,
		dekOff:     dekOff,
		headerLen:  pos,
	}, nil
}
