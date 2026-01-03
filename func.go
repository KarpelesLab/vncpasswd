// Package vncpasswd provides functions for encrypting and decrypting VNC passwords.
//
// VNC uses a fixed, well-known key to encrypt passwords stored in ~/.vnc/passwd files.
// This implementation is compatible with the standard VNC password format used by
// most VNC servers and clients.
//
// Security Warning: VNC password encryption is inherently insecure because it uses
// the outdated DES algorithm with a fixed, publicly known key. Passwords are also
// limited to 8 characters. This package is intended for compatibility with existing
// VNC infrastructure, not for secure password storage.
//
// This implementation was ported from the Python vncpasswd.py project
// (https://github.com/trinitronx/vncpasswd.py) to maintain compatibility with
// VNC's specific DES implementation, which differs from standard DES.
package vncpasswd

// GenerateResponse generates a VNC authentication response for the RFB protocol.
//
// In VNC's challenge-response authentication (RFB Security Type 2), the server
// sends a 16-byte random challenge. The client encrypts this challenge using
// DES with the user's password as the key, then sends the 16-byte response back.
//
// Parameters:
//   - passwd: The VNC password (only first 8 bytes are used)
//   - challenge: A 16-byte challenge from the VNC server
//
// Returns a 16-byte encrypted response to send back to the server.
func GenerateResponse(passwd, challenge []byte) []byte {
	var key [8]byte
	copy(key[:], passwd)
	ek := deskey(key, false)
	return append(desfunc(challenge[:8], ek), desfunc(challenge[8:], ek)...)
}

// Crypt encrypts a password using the VNC password encryption scheme.
//
// The password is encrypted using DES with VNC's fixed key and can be written
// directly to a ~/.vnc/passwd file. Only the first 8 characters of the password
// are used; any additional characters are silently ignored.
//
// Example:
//
//	encrypted := vncpasswd.Crypt("mypassword")
//	// encrypted can be written to ~/.vnc/passwd
//
// Returns an 8-byte encrypted password.
func Crypt(password string) []byte {
	pwd := make([]byte, 8)
	copy(pwd, password)

	key := deskey(vnckey, false)
	return desfunc(pwd, key)
}

// Decrypt decrypts a VNC password that was encrypted with the standard VNC key.
//
// This function can be used to recover the plaintext password from an encrypted
// ~/.vnc/passwd file. The input should be the 8-byte encrypted password read
// from the file.
//
// Example:
//
//	data, _ := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".vnc", "passwd"))
//	password := vncpasswd.Decrypt(data[:8])
//
// Returns the decrypted password as a string. Note that the result may contain
// trailing null bytes if the original password was shorter than 8 characters.
func Decrypt(value []byte) string {
	key := deskey(vnckey, true)
	return string(desfunc(value, key))
}
