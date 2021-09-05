package go_encrypt

import "testing"

func TestEncodeAndDecode(t *testing.T) {
	rsa := NewCoder().GetEncrypted().RsaCoder(BitSize2048,nil,nil).CreateKeyPairPem()
	if err := rsa.Err(); err != nil {
		t.Error(err)
	}
	src := []byte("hello world")
	if err := rsa.Encode(src).Err(); err != nil {
		t.Error(err)
	} else {
		t.Log(rsa.GetCipherText())
	}
	cipherText := rsa.GetCipherText()
	// decode
	if err := rsa.Decode(cipherText).Err(); err != nil {
		t.Error(err)
	} else {
		t.Log(string(rsa.GetPlainText()))
	}
}

func TestExm(t *testing.T) {
	shaExamples()
}