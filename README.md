[![GoDoc](https://godoc.org/github.com/KarpelesLab/vncpasswd?status.svg)](https://godoc.org/github.com/KarpelesLab/vncpasswd)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

# vncpasswd

A Go library for encrypting and decrypting VNC passwords. This package enables you to programmatically generate and read VNC password files (`~/.vnc/passwd`), which are used by most VNC servers and clients for authentication.

## Installation

```bash
go get github.com/KarpelesLab/vncpasswd
```

## Usage

### Encrypting a Password

Create an encrypted password suitable for writing to a VNC passwd file:

```go
package main

import (
    "os"
    "path/filepath"

    "github.com/KarpelesLab/vncpasswd"
)

func main() {
    // Encrypt the password
    encrypted := vncpasswd.Crypt("mypassword")

    // Write to ~/.vnc/passwd
    vncDir := filepath.Join(os.Getenv("HOME"), ".vnc")
    os.MkdirAll(vncDir, 0700)
    os.WriteFile(filepath.Join(vncDir, "passwd"), encrypted, 0600)
}
```

### Decrypting a Password

Read and decrypt an existing VNC password file:

```go
package main

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/KarpelesLab/vncpasswd"
)

func main() {
    // Read the encrypted password file
    passwdFile := filepath.Join(os.Getenv("HOME"), ".vnc", "passwd")
    data, err := os.ReadFile(passwdFile)
    if err != nil {
        panic(err)
    }

    // Decrypt (use first 8 bytes)
    password := vncpasswd.Decrypt(data[:8])

    // Trim null bytes (passwords shorter than 8 chars are null-padded)
    password = strings.TrimRight(password, "\x00")

    fmt.Printf("Password: %s\n", password)
}
```

### VNC Authentication Response

Generate a response for VNC challenge-response authentication (RFB Security Type 2):

```go
package main

import "github.com/KarpelesLab/vncpasswd"

func main() {
    password := []byte("secret")
    challenge := make([]byte, 16) // 16-byte challenge from server

    // Generate the authentication response
    response := vncpasswd.GenerateResponse(password, challenge)

    // Send response back to VNC server...
    _ = response
}
```

## API Reference

### `Crypt(password string) []byte`

Encrypts a password using the VNC password encryption scheme. Returns an 8-byte encrypted password. Only the first 8 characters of the password are used.

### `Decrypt(value []byte) string`

Decrypts an 8-byte VNC encrypted password. Returns the plaintext password (may contain trailing null bytes).

### `GenerateResponse(passwd, challenge []byte) []byte`

Generates a 16-byte VNC authentication response for the RFB protocol's challenge-response mechanism.

## Security Considerations

VNC password encryption has significant security limitations:

- **Weak encryption**: Uses the outdated DES algorithm (56-bit effective key)
- **Fixed key**: All VNC implementations use the same publicly known encryption key
- **Short passwords**: Limited to 8 characters maximum; longer passwords are truncated
- **No salt**: Identical passwords produce identical ciphertext
- **Easily reversible**: Anyone with access to the passwd file can decrypt the password

This package is intended for compatibility with existing VNC infrastructure. For new applications requiring secure password storage, use modern alternatives like bcrypt, scrypt, or Argon2.

## Why a Custom DES Implementation?

While Go's standard library includes a DES implementation, VNC uses a non-standard bit ordering in its DES operations. This causes Go's `crypto/des` package to produce different results than VNC expects. This package includes a DES implementation ported from [vncpasswd.py](https://github.com/trinitronx/vncpasswd.py) that matches VNC's behavior.

## License

MIT License - see [LICENSE](LICENSE) for details.

Copyright 2021 Karpeles Lab Inc.
