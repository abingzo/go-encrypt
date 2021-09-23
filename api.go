package go_encrypt

import (
	"github.com/abingzo/go-encrypt/padding"
	"io"
)

type Encrypted interface {
	RsaCoder(bitSize Mode,pub,pri io.WriteCloser) *rsaCoder
	AesCoder(typ Mode) *aesCoder
	DesCoder()
}

type Abstracted interface {
	Md5Coder(ptTyp Mode) *md5Coder
	Sha1Coder(ptTyp Mode) *shaCoder
	Sha256Coder(ptTyp Mode) *shaCoder
	Sha512Coder(ptTyp Mode) *shaCoder
	EccCoder()
}

type Coder interface {
	GetEncrypted() Encrypted
	GetAbstract() Abstracted
}

const (
	BitSize1024 Mode = 2 << (9 + iota)
	BitSize2048
	BitSize4096
)

// encode type
// 编码的类型
const (
	BASE64 Mode = iota
	HEX
	SOURCE
)

const (
	SHA1 Mode = iota
	SHA256
	SHA512
)

// aes mode
const (
	AES128 Mode = 8 * (2 + iota)
	AES192
	AES256
)

type Mode int

func NewCoder() Coder {
	return Coder(&coder{})
}

type coder struct {}

func (c *coder) GetEncrypted() Encrypted {
	return Encrypted(&encrypted{})
}

func (c *coder) GetAbstract() Abstracted {
	return Abstracted(&abstracted{})
}

type encrypted struct {}

func (e *encrypted) RsaCoder(bitSize Mode,pub,pri io.WriteCloser) *rsaCoder {
	return &rsaCoder{
		encryptSize: bitSize,
		PubKeyPem:   pub,
		PriKeyPem:   pri,
	}
}

// 默认使用pkcs7方式填充
// 根据选项初始化Aes128/192/256
func (e *encrypted) AesCoder(typ Mode) *aesCoder {
	tmp := &aesCoder{
		padding:     padding.PaddingForPkcs7,
		uPadding:    padding.UnPaddingForPkcs7,
	}
	switch typ {
	case AES128:
		tmp.keySize = AES128
		return tmp
	case AES192:
		tmp.keySize = AES192
		return tmp
	case AES256:
		tmp.keySize = AES256
		return tmp
	default:
		return nil
	}
}


func (e *encrypted) DesCoder() {
	panic("implement me")
}

type abstracted struct {}

func (a *abstracted) Md5Coder(ptTyp Mode) *md5Coder {
	return &md5Coder{
		typ:    ptTyp,
	}
}

func (a *abstracted) Sha1Coder(ptTyp Mode) *shaCoder {
	return &shaCoder{
		typ:     ptTyp,
		shaType: SHA1,
	}
}

func (a *abstracted) Sha256Coder(ptTyp Mode) *shaCoder {
	return &shaCoder{
		typ:     ptTyp,
		shaType: SHA256,
	}
}

func (a *abstracted) Sha512Coder(ptTyp Mode) *shaCoder {
	return &shaCoder{
		typ:     ptTyp,
		shaType: SHA512,
	}
}

func (a *abstracted) EccCoder() {
	panic("implement me")
}
