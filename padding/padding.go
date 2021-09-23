package padding

// 填充和解填充的方式
type Padding func(p []byte,size int) []byte
type UnPadding func(p []byte) []byte

// 使用pkcs7方式来填充块数据
func PaddingForPkcs7(src []byte,size int) []byte {
	if src == nil || len(src) == 0 {
		return make([]byte,0)
	}
	tmp := make([]byte,size - (len(src) % size))
	for k := range tmp {
		tmp[k] = byte(len(tmp))
	}
	return append(src,tmp...)
}

// 去掉数据中的pkcs7填充
func UnPaddingForPkcs7(src []byte) []byte {
	if src == nil || len(src) == 0 {
		return make([]byte,0)
	}
	pointer := (int)(src[len(src) - 1])
	return src[:len(src) - pointer]
}
