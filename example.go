package go_encrypt

import (
	"encoding/hex"
	"fmt"
)

// rsa的案例
func rsaExamples()  {
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

func md5Examples()  {
	// BASE64 指定输出的编码为std base64
	base64 := NewCoder().GetAbstract().Md5Coder(BASE64).SumString("hello world")
	result, err := base64.Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))

	// HEX 指定输出的编码为 hex/16进制字符串
	hexCode := NewCoder().GetAbstract().Md5Coder(HEX).SumString("hello world")
	result, err = hexCode.Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))

	// SOURCE 指定输出的编码为原始数据
	src := NewCoder().GetAbstract().Md5Coder(SOURCE).SumString("hello world")
	result, err = src.Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(result)

	// 在原始字符串之后追加字符
	// SetJoinStr()为指定追加的字符间隔的字符串
	ap := NewCoder().GetAbstract().Md5Coder(BASE64).SetJoinStr(";;").Append("http").Append("code").SumString("hello world")
	result, err = ap.Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))
}

func shaExamples()  {
	// SHA1
	sha1Result,err := NewCoder().GetAbstract().Sha1Coder(BASE64).SumString("hello world").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(sha1Result))
	// SHA256
	sha256Result,err := NewCoder().GetAbstract().Sha256Coder(BASE64).SumString("hello world").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(sha256Result))
	// SHA512
	sha512Result,err := NewCoder().GetAbstract().Sha512Coder(BASE64).SumString("hello world").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(sha512Result))
	// SHA512 追加字符
	sha512ResultAppend,err := NewCoder().GetAbstract().Sha512Coder(BASE64).SumString("hello world").
		Append("append1").Append("append2").Append("append3").SetJoinStr(";").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(sha512ResultAppend))
}

func aesExamples() {
}