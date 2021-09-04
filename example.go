package go_encrypt

import (
	"encoding/hex"
	"fmt"
)

// rsa的案例
func RsaExamples()  {
	// 获得rsa密钥对
	rsa := NewCoder().GetEncrypted().RsaCoder(BitSize2048,nil,nil).CreateKeyPairPem()
	// 打印公钥和私钥
	fmt.Printf("the public key : %s\nthe private key : %s",string(rsa.GetPublicKeyPemBytes()),string(rsa.GetPrivateKeyPemBytes()))
	// 加密
	src := "hello world"
	if err := rsa.Encode([]byte(src)).Err(); err != nil {
		panic(err)
	}
	fmt.Println(hex.EncodeToString(rsa.GetCipherText()))
	// 解密
	if err := rsa.Decode(rsa.GetCipherText()).Err(); err != nil {
		panic(err)
	}
	fmt.Println(src == string(rsa.GetPlainText()))
}
