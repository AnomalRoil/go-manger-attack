// This contains modified copies of some of the code from the Go crypto package
// all credits goes to The Go Authors, it follows a BSD-style licence that can
// be found in the GO_LICENSE file
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
)

// fromBase16 returns a new Big.Int from an hexadecimal string, as found in the go crypto tests suite
func fromBase16(base16 string) *big.Int {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		panic("bad number: " + base16)
	}
	return i
}

// setKeyAndCipher allows one to generate a key, display it and to encrypt
// with this key a given message and display it. TODO: eventually put
// the key in a file instead and store the ciphertext in a file too, to allow
// easier key and cipher management.
func setKeyAndCipher() {

	s := mrand.NewSource(2)
	r := mrand.New(s)
	// We use 196 bits modulus to have quick encryption/decryption processes
	key, err := rsa.GenerateKey(r, 2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key)
	testKey := new(PublicKey)
	testKey.E = key.E
	testKey.N = key.N

	secretMessage := []byte("Very secret message nobody can decrypt? At least without the private key?")
	label := []byte("")

	rng := rand.Reader
	ciphertext, err := EncryptOAEP(sha256.New(), rng, testKey, secretMessage, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return
	}

	fmt.Printf("Ciphertext toDecipher: %x\n", ciphertext)
}

// setup allows one to setup the current test, ie it will generate a key and use it
// to encrypt a message thanks to encryptTest() after displaying it and so, it will
// also call decrypt to decrypt with the key set in the main file attack.go, so it
// won't work unless both key are the same... Currently they are, since the PRNG
// is seeded with 2 in the encryptTest() function.
func setup() {
	// We first set our things up :
	setKeyAndCipher()

	bytesToDecipher, _ := hex.DecodeString(toDecrypt)
	decipheredBytes, err := DecryptOAEP(sha256.New(), nil, test2048Key, bytesToDecipher, []byte(""))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("What we encrypted :", string(decipheredBytes))
}

// divCeil allows to perform a divison and ceil it instead of flooring as do the big.Int Div function
func divCeil(a, b *big.Int) *big.Int {
	zero := new(big.Int).SetInt64(0)
	one := new(big.Int).SetInt64(1)
	if zero.Cmp(b) == 0 {
		log.Fatalln("Divison by zero")
	}
	remainder := new(big.Int)
	ceiled, _ := new(big.Int).QuoRem(a, b, remainder)
	if remainder.Cmp(zero) > 0 {
		// we have to ceil it
		ceiled.Add(ceiled, one)
	}
	return ceiled
}

// unpad is simply the last part of the DecryptOAEP function, as it stands in
// the Go crypto/rsa package, we feed it with a foundPlaintext and it will
// unpad it as if it were padded in OAEP (even if it is not, useful for tests)
func unpad(k int, foundPlaintext *big.Int, hash hash.Hash, label []byte) []byte {
	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	em := leftPad(foundPlaintext.Bytes(), k)
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]
	mgf1XOR(seed, hash, db)
	mgf1XOR(db, hash, seed)
	lHash2 := db[0:hash.Size()]
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]
	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}
	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		log.Fatalln("There was an error when trying to unpad the found plaintext")
	}

	return rest[index+1:]
}
