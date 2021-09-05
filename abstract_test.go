package go_encrypt

import "testing"

func TestAbstracted_Md5Coder(t *testing.T) {
	base64 := NewCoder().GetAbstract().Md5Coder(BASE64).SumString("hello world")
	result, err := base64.Result()
	if err != nil {
		t.Error(err)
	} else {
		t.Log(string(result))
	}
	hexCode := NewCoder().GetAbstract().Md5Coder(HEX).SumString("hello world")
	result, err = hexCode.Result()
	if err != nil {
		t.Error(err)
	} else {
		t.Log(string(result))
	}
	// source
	src := NewCoder().GetAbstract().Md5Coder(SOURCE).SumString("hello world")
	result, err = src.Result()
	if err != nil {
		t.Error(err)
	} else {
		t.Log(result)
	}
	// append
	ap := NewCoder().GetAbstract().Md5Coder(BASE64).SetJoinStr(";;").Append("http").Append("code").SumString("hello world")
	result, err = ap.Result()
	if err != nil {
		t.Error(err)
	} else {
		t.Log(string(result))
	}
}

func TestAbstracted_ShaCoder(t *testing.T)  {
	sha1 := NewCoder().GetAbstract().Sha1Coder(BASE64)
	result, err := sha1.SumString("hello world").Result()
	if err != nil {
		t.Error(err)
	} else {
		t.Log(string(result))
	}
	sha256 := NewCoder().GetAbstract().Sha256Coder(BASE64)
	result, err = sha256.SumString("hello world").Result()
	if err != nil {
		t.Error(err)
	} else {
		t.Log(string(result))
	}
	sha512 := NewCoder().GetAbstract().Sha512Coder(BASE64)
	result, err = sha512.SumString("hello world").Result()
	if err != nil {
		t.Error(err)
	} else {
		t.Log(string(result))
	}
}