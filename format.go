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

	// FormatV2 线格式（当前写出版本）：
	//   MAGIC(4) | VER(1)=0x02 | FLAGS(1) | KEYIDLEN(2 BE) | KEYID |
	//   DEKLEN(2 BE) | ENC_DEK(=DEKLEN) | NONCELEN(1) | NONCE |
	//   TIMESTAMP(8 BE) | CIPHERTEXT+TAG(变长)
	// 相对 v1 的演进：密钥标识长度扩展为 2 字节、nonce 长度自描述、
	// 新增 8 字节时间戳，并保留 FLAGS 位供未来特性协商。
	FormatV2 byte = 0x02

	// currentFormat 是新写入密文使用的格式版本。
	currentFormat = FormatV2
)

// 各字段边界，用于解析时严格拒绝长度欺骗/截断数据。
const (
	magicSize       = 4
	v1NonceSize     = 12
	gcmTagSize      = 16
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
	timestamp  int64  // v2 携带；v1 为零值
	flags      byte   // v2 携带；v1 为零值
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
	}, nil
}
