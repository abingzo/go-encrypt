package padding

import "testing"

func TestPKCS7(t *testing.T)  {
	data := make([]byte,0)
	for i := 65; i < 81; i++ {
		data = append(data,byte(i))
	}
	t.Log(PaddingForPkcs7(data,16))
	t.Log(UnPaddingForPkcs7(PaddingForPkcs7(data,16)))
}
