package go_encrypt

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

type md5Coder struct {
	// 输出字节切片的类型
	typ Mode
	// 原始内容
	src []byte
	// 追加内容
	append []string
	// 连接追加内容使用的字符串
	Join string
	// 错误
	err error
}

func (c *md5Coder) Result() ([]byte,error) {
	hash := md5.New()
	joins := ""
	if len(c.append) > 0 {
		joins = strings.Join(c.append,c.Join)
	}
	_, err := hash.Write(append(c.src,[]byte(joins)...))
	bytes := hash.Sum(nil)
	if err != nil {
		return nil, err
	}
	switch c.typ {
	case SOURCE:
		return bytes,nil
	case HEX:
		return []byte(hex.EncodeToString(bytes)),nil
	case BASE64:
		return []byte(base64.StdEncoding.EncodeToString(bytes)),nil
	default:
		return nil, errors.New("mod type is not supported")
	}
}

func (c *md5Coder) Err() error {
	return c.err
}

func (c *md5Coder) Append(s string) *md5Coder {
	c.append = append(c.append,s)
	return c
}

func (c *md5Coder) SumString(s string) *md5Coder  {
	c.src = []byte(s)
	return c
}

func (c *md5Coder) SumBytes(s []byte) *md5Coder {
	c.src = s
	return c
}

func (c *md5Coder) SetJoinStr(s string) *md5Coder {
	c.Join = s
	return c
}
