package go_encrypt

import "io"

type Encrypted interface {
	RsaCoder(bitSize Mode,pub,pri io.WriteCloser) *rsaCoder
	AesCoder()
	DesCoder()
}

type Abstracted interface {
	Md5Coder()
	Sha256Coder()
	Sha512Coder()
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

type Mode int

func NewCoder() Coder {
	return Coder(&coder{})
}

type coder struct {}

func (c *coder) GetEncrypted() Encrypted {
	return Encrypted(&encrypted{})
}

func (c *coder) GetAbstract() Abstracted {
	panic("implement me")
}

type encrypted struct {}

func (e *encrypted) RsaCoder(bitSize Mode,pub,pri io.WriteCloser) *rsaCoder {
	return &rsaCoder{
		encryptSize: bitSize,
		PubKeyPem:   pub,
		PriKeyPem:   pri,
	}
}

func (e *encrypted) AesCoder() {
	panic("implement me")
}

func (e *encrypted) DesCoder() {
	panic("implement me")
}
