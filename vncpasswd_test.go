package vncpasswd

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestPasswd(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdef")
	var keyA [8]byte
	copy(keyA[:], key)

	plain, _ := hex.DecodeString("0123456789abcdef")
	cipher, _ := hex.DecodeString("6e09a37726dd560c")

	ek := deskey(keyA, false)
	dk := deskey(keyA, true)

	// expected value for ek & dk (extracted from python version)
	ekVal := []uint32{
		923729924, 926749207, 255208716, 1010761729, 1059456009, 840638978, 255466756, 977078784,
		926025745, 857604618, 523967232, 708578050, 925894929, 791544874, 977077025, 708708610,
		1008341508, 1060569144, 1059008544, 421926152, 1007357960, 759103800, 789390368, 490082604,
		690946090, 624886064, 789382176, 926224949, 591333410, 892940304, 453452810, 1041965570,
	}
	dkVal := []uint32{
		453452810, 1041965570, 591333410, 892940304, 789382176, 926224949, 690946090, 624886064,
		789390368, 490082604, 1007357960, 759103800, 1059008544, 421926152, 1008341508, 1060569144,
		977077025, 708708610, 925894929, 791544874, 523967232, 708578050, 926025745, 857604618,
		255466756, 977078784, 1059456009, 840638978, 255208716, 1010761729, 923729924, 926749207,
	}

	errCount := 0
	for a, b := range ekVal {
		if ek[a] != b {
			errCount += 1
		}
	}
	if errCount > 0 {
		t.Errorf("ek value not as expected, contains %d errors", errCount)
	}

	errCount = 0
	for a, b := range dkVal {
		if dk[a] != b {
			errCount += 1
		}
	}
	if errCount > 0 {
		t.Errorf("ek value not as expected, contains %d errors", errCount)
	}

	if !bytes.Equal(desfunc(plain, ek), cipher) {
		t.Errorf("desfunc(plain, ek) == cipher failed (got %s instead of %s)", hex.EncodeToString(desfunc(plain, ek)), hex.EncodeToString(cipher))
	}
	if !bytes.Equal(desfunc(desfunc(plain, ek), dk), plain) {
		t.Errorf("desfunc(desfunc(plain, ek), dk) == cipher failed")
	}
	if !bytes.Equal(desfunc(desfunc(plain, dk), ek), plain) {
		t.Errorf("desfunc(desfunc(plain, dk), ek) == cipher failed")
	}

}
