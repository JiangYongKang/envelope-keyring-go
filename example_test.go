package envelope_test

import (
	"crypto/rand"
	"errors"
	"fmt"

	envelope "github.com/highcumontoa/envelope-keyring-go"
)

func mustKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}

func Example() {
	kr := envelope.NewKeyring()
	_ = kr.AddKey("kek-2026-01", mustKey(), true)
	c := envelope.NewEnvelopeCipher(kr)

	// 用当前激活密钥封装
	ct, _ := c.Encrypt([]byte("季度财报"), []byte("tenant/a"))

	// 轮换：追加新激活密钥，旧密钥保留用于解密历史密文
	_ = kr.Rotate("kek-2026-04", mustKey())

	// 轮换前产生的密文仍可解出，结果与轮换前一致
	pt, err := c.Decrypt(ct, []byte("tenant/a"))
	if err != nil {
		fmt.Println("decrypt error:", err)
		return
	}
	fmt.Printf("历史密文解密: %s\n", pt)

	// 新数据由新密钥封装
	newCT, _ := c.Encrypt([]byte("新数据"), []byte("tenant/a"))
	fmt.Printf("新密文使用格式版本: v%d\n", newCT[4])

	// 篡改密文会被明确归类
	newCT[len(newCT)-1] ^= 0xFF
	_, err = c.Decrypt(newCT, []byte("tenant/a"))
	fmt.Println("篡改判定:", errors.Is(err, envelope.ErrCiphertextTampered))

	// Output:
	// 历史密文解密: 季度财报
	// 新密文使用格式版本: v2
	// 篡改判定: true
}
