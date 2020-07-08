package vncpasswd

// GenerateResponse is used for VNC auth and is provided as is from the python implementation
func GenerateResponse(passwd, challenge []byte) []byte {
	var key [8]byte
	copy(key[:], passwd)
	ek := deskey(key, false)
	return append(desfunc(challenge[:8], ek), desfunc(challenge[8:], ek)...)
}

// Crypt will encrypt the given password in format expected by VNC
func Crypt(password string) []byte {
	pwd := make([]byte, 8)
	copy(pwd, password)

	key := deskey(vnckey, false)
	return desfunc(pwd, key)
}

// Decrypt will decrypt and return a VNC password
func Decrypt(value []byte) string {
	key := deskey(vnckey, true)
	return string(desfunc(value, key))
}
