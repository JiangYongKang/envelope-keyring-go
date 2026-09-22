package envelope

import "encoding/binary"

// formatVersion 是密文格式版本号。
type formatVersion byte

const (
	formatV1 formatVersion = 1
	formatV2 formatVersion = 2
	// currentFormat 是新写入密文使用的版本。
	currentFormat formatVersion = formatV2
)

// ciphertextMagic 是所有版本共享的魔数，用于快速识别本格式密文。
var ciphertextMagic = [4]byte{'E', 'N', 'V', 'K'}

const (
	gcmTagSize   = 16
	gcmNonceSize = 12
	// v1KeyIDMax V1 头用 1 字节承载 keyID 长度。
	v1KeyIDMax = 255
	// v2KeyIDMax V2 头用 2 字节承载 keyID 长度。
	v2KeyIDMax = 65535
)

// parsedCiphertext 是 decode 后的结构化密文。
type parsedCiphertext struct {
	version    formatVersion
	keyID      string
	nonce      []byte
	wrappedDEK []byte
	ciphertext []byte
}

// encode 把封装好的各部分序列化为自描述密文。
//
// 两种版本的线缆布局：
//
//	V1: "ENVK" | 0x01 | idLen uint8  | keyID | nonce[12] | wLen uint16BE | wrappedDEK | ciphertext
//	V2: "ENVK" | 0x02 | idLen uint16BE | keyID | nonceLen uint8 | nonce | wLen uint16BE | wrappedDEK | ciphertext
func encode(v formatVersion, keyID string, nonce, wrappedDEK, ciphertext []byte) ([]byte, error) {
	id := []byte(keyID)
	out := make([]byte, 0, 4+1+2+len(id)+len(nonce)+2+len(wrappedDEK)+len(ciphertext))
	out = append(out, ciphertextMagic[:]...)
	out = append(out, byte(v))

	switch v {
	case formatV1:
		if len(id) > v1KeyIDMax {
			return nil, wrapErr(ErrInvalidFormat, keyID, "v1 key id exceeds 255 bytes")
		}
		out = append(out, byte(len(id)))
		out = append(out, id...)
		if len(nonce) != gcmNonceSize*2 {
			return nil, wrapErr(ErrInvalidFormat, keyID, "v1 nonce field must be 24 bytes (wrap||data)")
		}
		out = append(out, nonce...)
	case formatV2:
		if len(id) > v2KeyIDMax {
			return nil, wrapErr(ErrInvalidFormat, keyID, "v2 key id exceeds 65535 bytes")
		}
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(id)))
		out = append(out, l[:]...)
		out = append(out, id...)
		out = append(out, byte(len(nonce)))
		out = append(out, nonce...)
	default:
		return nil, wrapErr(ErrUnsupportedVersion, keyID, "cannot encode unknown format version")
	}

	var wl [2]byte
	binary.BigEndian.PutUint16(wl[:], uint16(len(wrappedDEK)))
	out = append(out, wl[:]...)
	out = append(out, wrappedDEK...)
	out = append(out, ciphertext...)
	return out, nil
}

// decode 解析密文；版本不识别返回 ErrUnsupportedVersion，
// 结构非法（魔数、截断、越界、空载荷等）返回 ErrInvalidFormat。
// decode 只做结构校验，不做任何密码学校验，也不会因解析失败而返回明文。
func decode(raw []byte) (*parsedCiphertext, error) {
	if len(raw) < len(ciphertextMagic)+1 {
		return nil, wrapErr(ErrInvalidFormat, "", "ciphertext shorter than magic+version header")
	}
	for i := range ciphertextMagic {
		if raw[i] != ciphertextMagic[i] {
			return nil, wrapErr(ErrInvalidFormat, "", "magic prefix mismatch; not an envelope ciphertext")
		}
	}
	v := formatVersion(raw[4])
	pos := 5

	var keyID []byte
	var nonce []byte

	switch v {
	case formatV1:
		if pos+1 > len(raw) {
			return nil, wrapErr(ErrInvalidFormat, "", "v1 header truncated at key id length")
		}
		idLen := int(raw[pos])
		pos++
		if pos+idLen > len(raw) {
			return nil, wrapErr(ErrInvalidFormat, "", "v1 header truncated: key id overruns input")
		}
		keyID = raw[pos : pos+idLen]
		pos += idLen
		// V1 nonce 段固定为 封装nonce||数据nonce，各 12 字节，共 24 字节。
		if pos+gcmNonceSize*2 > len(raw) {
			return nil, wrapErr(ErrInvalidFormat, string(keyID), "v1 header truncated: nonce overruns input")
		}
		nonce = raw[pos : pos+gcmNonceSize*2]
		pos += gcmNonceSize * 2
	case formatV2:
		if pos+2 > len(raw) {
			return nil, wrapErr(ErrInvalidFormat, "", "v2 header truncated at key id length")
		}
		idLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
		pos += 2
		if pos+idLen > len(raw) {
			return nil, wrapErr(ErrInvalidFormat, "", "v2 header truncated: key id overruns input")
		}
		keyID = raw[pos : pos+idLen]
		pos += idLen
		if pos+1 > len(raw) {
			return nil, wrapErr(ErrInvalidFormat, string(keyID), "v2 header truncated at nonce length")
		}
		nonceLen := int(raw[pos])
		pos++
		if nonceLen != gcmNonceSize*2 || pos+nonceLen > len(raw) {
			return nil, wrapErr(ErrInvalidFormat, string(keyID),
				"v2 nonce length must be 24 (wrap||data) or overruns input")
		}
		nonce = raw[pos : pos+nonceLen]
		pos += nonceLen
	default:
		// 无法识别的版本：明确拒绝，绝不按当前格式误解析。
		return nil, wrapErr(ErrUnsupportedVersion, "",
			"ciphertext version byte is not one of {1,2}")
	}

	if pos+2 > len(raw) {
		return nil, wrapErr(ErrInvalidFormat, string(keyID), "truncated at wrapped-DEK length")
	}
	wLen := int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	pos += 2
	if wLen == 0 || pos+wLen > len(raw) {
		return nil, wrapErr(ErrInvalidFormat, string(keyID), "wrapped DEK is empty or overruns input")
	}
	wrapped := raw[pos : pos+wLen]
	pos += wLen

	ct := raw[pos:]
	if len(ct) < gcmTagSize {
		return nil, wrapErr(ErrInvalidFormat, string(keyID), "payload shorter than GCM authentication tag")
	}

	return &parsedCiphertext{
		version:    v,
		keyID:      string(keyID),
		nonce:      nonce,
		wrappedDEK: wrapped,
		ciphertext: ct,
	}, nil
}
