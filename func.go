package vncpasswd

// two password functions for VNC protocol
func DecryptPasswd(data []byte) []byte {
	dk := deskey(vnckey, true)
	return desfunc(data, dk)
}

func GenerateResponse(passwd, challenge []byte) []byte {
	var key [8]byte
	copy(key[:], passwd)
	ek := deskey(key, false)
	return append(desfunc(challenge[:8], ek), desfunc(challenge[8:], ek)...)
}

func Crypt(password string) []byte {
	pwd := make([]byte, 8)
	copy(pwd, password)

	key := deskey(vnckey, false)
	return desfunc(pwd, key)
}

func Decrypt(value []byte) string {
	key := deskey(vnckey, true)
	return string(desfunc(value, key))
}
