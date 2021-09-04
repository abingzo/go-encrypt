# go-encrypt
>  Go标准库的加密&摘要算法实现的上层包装，将调用变得简单

> 开发中，预计覆盖标准库大部分的摘要&加密算法，目前只完成了`Rsa`的部分

#### 获得这个库

> go get github.com/abingzo/go-encrypt

#### 使用

> 链式API设计的尝试

```go
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
```

`Print`

```shell
the public key : -----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAusty+abO2pBhqai0v52s
ctVpbnj1arprryZ+I7VZoHtldD7+s4771mPLNsvUWX4OQugt3ghp4Y3F6NGFWcNs
61WnXh4QGDYhshYXimiNJKmhuxyfFlwHjDkWYKqJXz9gAMCZF1pH24XzymuEAReI
qL2Yv4KxDql/Tww4o0W9Y/MYagdPy4MWnYgmAvDTygzTgdNAQ0HlG+MA+pjc72Za
2I8cYqTDqIFTGwEEzrH2ikh5yNqoWl20Q2M4QCqbIPV8ZBuNftxDsbSnCOcFH4ai
9yjEcJapLI2i43Siz9sSD1l2jLykpFvw8s0A/PYb7J9ZcHh1wX434nljQDMD7605
gwIDAQAB
-----END PUBLIC KEY-----

the private key : -----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAusty+abO2pBhqai0v52sctVpbnj1arprryZ+I7VZoHtldD7+
s4771mPLNsvUWX4OQugt3ghp4Y3F6NGFWcNs61WnXh4QGDYhshYXimiNJKmhuxyf
FlwHjDkWYKqJXz9gAMCZF1pH24XzymuEAReIqL2Yv4KxDql/Tww4o0W9Y/MYagdP
y4MWnYgmAvDTygzTgdNAQ0HlG+MA+pjc72Za2I8cYqTDqIFTGwEEzrH2ikh5yNqo
Wl20Q2M4QCqbIPV8ZBuNftxDsbSnCOcFH4ai9yjEcJapLI2i43Siz9sSD1l2jLyk
pFvw8s0A/PYb7J9ZcHh1wX434nljQDMD7605gwIDAQABAoIBACxjqKD3KPT7lpnQ
w5M9jvuDB5j/GaMRRgHLbfJiaDgg2s0zIyfcdLBP6rzM11uk/xKbRjsbWL4HCN74
222naTzLkAhnsH9wbbV6VoHHsrLhtNNYS93uZMTH1C+IlziRQOks27SW+biLLpIN
1sLDqvAejiwEjLrlQKGyT8tNCWK0u+YBVoVs44DLrc5+sPbTKFDmTfh6sWoT9DgE
3DyN0PJ36XbBYjA2w68lpbPJXliOTOgSb7+ou/gX6onOUcAoDH0+8ETrF1frPseN
3MlhWltpk083Twm4WMWZOCgzCNf3XcwA1VT32E/cXrzfMvR2sJi1Ecx03obqOo0p
WtBa2sECgYEAyF80s9RqmFlLSyF90k4wfN9wxSbK2FL6cg9vEPtEImDgdkJKc79V
ECS1W5qwQbBAjpoqGuFeRbBtn4bmCkbwwKsWRwkVzfmMcZLzOF2mf13a18l0mva4
MoG464F9h2nJre8d1p8SHNOOHdJmHelDVjDhjXDUmQOVfjeZzBYEFZECgYEA7qdJ
8B0LIW6PyhyEmlyo9+tsZRrPdBD7QmsQNytt14vi6/m12reMZADTnocp4L3QNDE7
Wuiq0SdLbHH65klnP/3e81qIOPtpBwcWFUruLl6OrUoFHv4expTrliT9GeaeUYTS
bg+XhlgLABN8K9jKr7jfOY7JMpU8sxskR/bCw9MCgYB13LrNhQdmsi+98+dlC6Ut
7ukQry7mbHjxGu8EGCkN59pg9cGBsGxC4LTlO2quWRTATSKzSRoA+DSjf+BU70Gy
s3CZPFjdHgtky0HSSBQmG3kdMV0rwjC7VN8HeNX0D2AYtezhUBSBbFfOZvK2aX24
d2xVnKcRkrAe3GnVSKYCYQKBgHfNTMWXntXKja4VANAIgd3qtcBPZCLMv4UI/9vi
FkLk+yYgdZT1HSm6bIEhMvmZ76GzsSsir1VNV4R590yRPp6WD8yz/rw0IPYhLYnE
0qo+V3tQNB/py4M+kMEPkmrlJUag2Y3cj+El42fHYEcWjjEGKjDXp9KXrh/vGRhz
HDR3AoGBAKFQPabR6pOQ3ZLd58MXHlwWCt8AZ+JOIvJquG6FV+Qqq8Vf6nTukIph
t2UHwkzpzz+Tn8h7lzCRN4bV+jxs35VlNM/OSY6Qa2AZcHymf9vzQx7jU6G3niyw
Ki8BXHVJT2JiCcUn6mSc24kUMGLXmXlHy5wasaIiW5cHQmLE7zRr
-----END RSA PRIVATE KEY-----
975f686839c7c4b36eb9363d1c952016c2cf9292d273bed7e0f4efc3b2be17fe90e34f749a2104f4ed643a86b495c5ed5487c256e339f9b43f2b1577956dfef1eff38d2296b8621ffe9caaa5261f18b05a6e2751c91bc0d15d70828a63a8cb72eb158d29b198576c5d4afe1c711029e8dc2b820bf10d24a9466d1fb69368f9941181a9e3e9f11fe9a3f8fa0dd582d7ddb205d23ef778cc94bcd6d87d031919fe4a84a26a3213ff400e210739e63b20b868a7cd9d6fc849c1e9179e2e1470c4c8d17f084391d673b51cc82badc2f50086ceaeb787169bb6ef9b058fd1680d8297d574a517ff7afc95c3c9fb7c00e123cb77ee68c46be0f85f2587a47043d4271c
true
```

