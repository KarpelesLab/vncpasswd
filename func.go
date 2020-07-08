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

func Crypt(password string, decrypt bool) []byte {
	pwd := make([]byte, 8)
	copy(pwd, password)

	key := deskey(vnckey, decrypt)
	return desfunc(pwd, key)
}
