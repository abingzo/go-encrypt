package main

import (
	"encoding/hex"
	"fmt"
	"github.com/abingzo/go-encrypt"
)

// rsa的案例
func rsaExamples()  {
	// 获得rsa密钥对
	rsa := go_encrypt.NewCoder().GetEncrypted().RsaCoder(go_encrypt.BitSize2048,nil,nil).CreateKeyPairPem()
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
	base64 := go_encrypt.NewCoder().GetAbstract().Md5Coder(go_encrypt.BASE64).SumString("hello world")
	result, err := base64.Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))

	// HEX 指定输出的编码为 hex/16进制字符串
	hexCode := go_encrypt.NewCoder().GetAbstract().Md5Coder(go_encrypt.HEX).SumString("hello world")
	result, err = hexCode.Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))

	// SOURCE 指定输出的编码为原始数据
	src := go_encrypt.NewCoder().GetAbstract().Md5Coder(go_encrypt.SOURCE).SumString("hello world")
	result, err = src.Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(result)

	// 在原始字符串之后追加字符
	// SetJoinStr()为指定追加的字符间隔的字符串
	ap := go_encrypt.NewCoder().GetAbstract().Md5Coder(go_encrypt.BASE64).SetJoinStr(";;").Append("http").Append("code").SumString("hello world")
	result, err = ap.Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(result))
}

func shaExamples()  {
	// SHA1
	sha1Result,err := go_encrypt.NewCoder().GetAbstract().Sha1Coder(go_encrypt.BASE64).SumString("hello world").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(sha1Result))
	// SHA256
	sha256Result,err := go_encrypt.NewCoder().GetAbstract().Sha256Coder(go_encrypt.BASE64).SumString("hello world").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(sha256Result))
	// SHA512
	sha512Result,err := go_encrypt.NewCoder().GetAbstract().Sha512Coder(go_encrypt.BASE64).SumString("hello world").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(sha512Result))
	// SHA512 追加字符
	sha512ResultAppend,err := go_encrypt.NewCoder().GetAbstract().Sha512Coder(go_encrypt.BASE64).SumString("hello world").
		Append("append1").Append("append2").Append("append3").SetJoinStr(";").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println(string(sha512ResultAppend))
}

func aesExamples() {
	// aes 128
	_ = go_encrypt.NewCoder().GetEncrypted().AesCoder(go_encrypt.AES128)
	// aes 192
	_ = go_encrypt.NewCoder().GetEncrypted().AesCoder(go_encrypt.AES192)
	// aes 256
	aes256 := go_encrypt.NewCoder().GetEncrypted().AesCoder(go_encrypt.AES256)
	// 初始化密钥，小于该规定的长度会报错，大于则会截取
	if aes256.Init([]byte("12345678123456781234567812345678")).Err() != nil {
		panic(aes256.Err())
	}
	// 加密,默认使用pkcs7方式填充
	result1 := aes256.AppendSrc([]byte("hello world")).Encrypted()
	result2 := aes256.ResetSrcTexts().AppendSrc([]byte("hello world 2")).Encrypted()
	fmt.Printf("%v\n%v\n",result1,result2)
	// 解密，支持多条密文
	results := aes256.AppendCipher(result1).AppendCipher(result2).Decrypted()
	for _,v := range results {
		fmt.Println(v)
	}
}

func main()  {
	aesExamples()
}