package go_encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
)

type rsaCoder struct {
	// 加密的密钥位长度
	encryptSize Mode
	// 公钥的输出位置
	PubKeyPem io.WriteCloser
	// 私钥的输出位置
	PriKeyPem io.WriteCloser
	// default publicKey filename
	// default privateKey filename
	// key is pub & pri
	file map[string]string
	// 公钥的数据
	publicKey []byte
	// 私钥的数据
	privateKey []byte
	// Err
	err error
	// plain text
	plainText []byte
	// cipher Text
	cipherText []byte
}


func (r *rsaCoder) SetPubAndPriIow(pub, pri io.WriteCloser) {
	r.PubKeyPem = pub
	r.PriKeyPem = pri
}

func (r *rsaCoder) CreateKeyPairPem() *rsaCoder {
	// 生成并在文件中写入可用的RSA公私钥
	// 创建私钥
	private, _ := rsa.GenerateKey(rand.Reader, int(r.encryptSize))
	// 获得公钥
	public := private.PublicKey
	// 使用x509标准转换为pem格式
	derText := x509.MarshalPKCS1PrivateKey(private)
	// 创建私钥结构体
	block := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derText,
	}
	// 写入内存
	r.privateKey = pem.EncodeToMemory(&block)
	// 将公钥转换为pem格式
	derpText, _ := x509.MarshalPKIXPublicKey(&public)
	// 创建公钥结构体
	block = pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derpText,
	}
	// 写入内存
	r.publicKey = pem.EncodeToMemory(&block)
	return r
}

func (r *rsaCoder)GetPublicKeyPemBytes() []byte {
	return r.publicKey
}

func (r *rsaCoder)GetPrivateKeyPemBytes() []byte {
	return r.privateKey
}

func (r *rsaCoder)GetCipherText() []byte {
	return r.cipherText
}

func (r rsaCoder) GetPlainText() []byte {
	return r.plainText
}

func (r *rsaCoder)Err() error {
	return r.err
}

func (r *rsaCoder)SetPublicKeyPem(publicKey []byte) *rsaCoder {
	r.publicKey = publicKey
	return r
}

func (r *rsaCoder) SetPrivateKeyPem(privateKey []byte) *rsaCoder {
	r.privateKey = privateKey
	return r
}

func (r *rsaCoder) SetKeyPemPair(publicKey []byte, privateKey []byte) *rsaCoder {
	r.publicKey = publicKey
	r.privateKey = privateKey
	return r
}

// TODO: 创建pem数据流到io.WriteCloser中,未完成
func (r *rsaCoder) CreateWriteKeyPairPem() *rsaCoder {
	r.err = nil
	return r
}

func (r *rsaCoder)Encode(src []byte) *rsaCoder {
	// pem解码
	block, _ := pem.Decode(r.publicKey)

	// 使用x509标准转换成可以使用的公钥
	pk, _ := x509.ParsePKIXPublicKey(block.Bytes)

	// 强制转换
	publicKey := pk.(*rsa.PublicKey)

	// 使用公钥加密数据
	cipherText,err := rsa.EncryptPKCS1v15(rand.Reader,publicKey, src)
	r.err = err
	r.cipherText = cipherText
	return r
}

func (r *rsaCoder) Decode(cipherText []byte)  *rsaCoder {
	// 私钥解密
	// pem解密
	block, _ := pem.Decode(r.privateKey)
	privateKey,err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		r.err = err
		return r
	}
	// 使用私钥解密密文
	plainText,err := rsa.DecryptPKCS1v15(nil,privateKey,cipherText)
	r.err = err
	r.plainText = plainText
	return r
}