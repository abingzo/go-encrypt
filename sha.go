package go_encrypt

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

type shaCoder struct {
	// 输出字节切片的类型
	typ Mode
	// 使用的sha算法类型
	shaType Mode
	// 原始内容
	src []byte
	// 追加内容
	append []string
	// 连接追加内容使用的字符串
	Join string
	// 错误
	err error
}

func (c *shaCoder) Result() ([]byte,error) {
	joins := ""
	if len(c.append) > 0 {
		joins = strings.Join(c.append,c.Join)
	}
	var bytes []byte
	switch c.shaType {
	case SHA1:
		hash := sha1.New()
		_, err := hash.Write(append(c.src,[]byte(joins)...))
		if err != nil {
			return nil, err
		}
		bytes = hash.Sum(nil)
	case SHA256:
		hash := sha256.New()
		_, err := hash.Write(append(c.src,[]byte(joins)...))
		if err != nil {
			return nil, err
		}
		bytes = hash.Sum(nil)
	case SHA512:
		hash := sha512.New()
		_, err := hash.Write(append(c.src,[]byte(joins)...))
		if err != nil {
			return nil, err
		}
		bytes = hash.Sum(nil)
	default:
		return nil,errors.New("shaTyp type is not supported")
	}

	switch c.typ {
	case SOURCE:
		return bytes,nil
	case HEX:
		return []byte(hex.EncodeToString(bytes)),nil
	case BASE64:
		return []byte(base64.StdEncoding.EncodeToString(bytes)),nil
	default:
		return nil, errors.New("typ type is not supported")
	}
}

func (c *shaCoder) Err() error {
	return c.err
}

func (c *shaCoder) Append(s string) *shaCoder {
	c.append = append(c.append,s)
	return c
}

func (c *shaCoder) SumString(s string) *shaCoder  {
	c.src = []byte(s)
	return c
}

func (c *shaCoder) SumBytes(s []byte) *shaCoder {
	c.src = s
	return c
}

func (c *shaCoder) SetJoinStr(s string) *shaCoder {
	c.Join = s
	return c
}

