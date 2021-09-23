package go_encrypt

import "testing"

func TestRsaEncodeAndDecode(t *testing.T) {
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

func TestAesEncodeAndDecode(t *testing.T) {
	key := make([]byte,32)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	aes := NewCoder().GetEncrypted().AesCoder(AES256).Init(key)
	if aes.Err() != nil {
		t.Error(aes.Err())
	}
	result1 := aes.AppendSrc([]byte("hello world")).Encrypted()
	t.Log(result1)
	t.Log(aes.AppendCipher(result1).Decrypted()[0])
}

func TestExm(t *testing.T) {
	shaExamples()
}