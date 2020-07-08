[![GoDoc](https://godoc.org/github.com/KarpelesLab/vncpasswd?status.svg)](https://godoc.org/github.com/KarpelesLab/vncpasswd)

# vncpasswd

Allows to easily encrypt passwords in order to generate value in `~/.vnc/passwd` files.

Note that this file is typically encrypted using the very outdated DES algorithm using a fixed not-so-secret secret, and as such is very insecure. Also the password is limited to 8 characters, and any characters after that will typically be ignored.

While it would have been nice to depend on Go's implementation of DES, the way it is implemented in VNC differs and generate different results. As such it was easier to copy an [existing implementation](https://github.com/trinitronx/vncpasswd.py) and port it to Go.

## Usage

```go
	// Encrypt
	pass := vncpasswd.Crypt("password")

	// Decrypt
	value := vncpasswd.Decrypt(pass)
```

