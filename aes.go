package go_encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/abingzo/go-encrypt/padding"
)

type aesCoder struct {
	keySize Mode
	err error
	// 密文
	cipherTexts [][]byte
	// 明文
	srcTexts []byte
	// aes block
	aesBlock cipher.Block
	// 填充方式
	padding padding.Padding
	// 解填充方式
	uPadding padding.UnPadding
}

// 设置一个新的key，根据设定的keySize分割
// 可能会设定一个err
func (a *aesCoder) Init(key []byte) *aesCoder {
	a.Reset()
	a.aesBlock, a.err = aes.NewCipher(key[:a.keySize])
	return a
}

func (a *aesCoder) Reset() *aesCoder {
	a.srcTexts = make([]byte,0)
	a.cipherTexts = make([][]byte,1)
	a.err = nil
	return a
}

func (a *aesCoder) AppendSrc(src []byte) *aesCoder {
	a.srcTexts = append(a.srcTexts,src...)
	return a
}

func (a *aesCoder) AppendCipher(cipher []byte) *aesCoder {
	a.cipherTexts[len(a.cipherTexts) - 1] = cipher
	a.cipherTexts = append(a.cipherTexts,[]byte(""))
	return a
}

func (a *aesCoder) SetPadding(p padding.Padding) *aesCoder {
	a.padding = p
	return a
}

func (a *aesCoder) SetUnPadding(up padding.UnPadding) *aesCoder {
	a.uPadding = up
	return a
}

// 块大小为16,即aes中定义的BlockSize
func (a *aesCoder) Encrypted() []byte {
	pad := a.padding(a.srcTexts,aes.BlockSize)
	dst := make([]byte,len(pad))
	a.aesBlock.Encrypt(dst,pad)
	return dst
}

// 密文必须是
// 遍历次数为存储密文切片的一维长度减一，因为这跟密文的添加方式有关
func (a *aesCoder) Decrypted() [][]byte {
	dsts := make([][]byte,len(a.cipherTexts) - 1)
	for k := range dsts {
		dst := make([]byte,len(a.cipherTexts[k]))
		a.aesBlock.Decrypt(dst,a.cipherTexts[k])
		dsts[k] = a.uPadding(dst)
	}
	return dsts
}

// get method
func (a *aesCoder) KeySize() int {
	return int(a.keySize)
}

func (a *aesCoder) Err() error {
	return a.err
}