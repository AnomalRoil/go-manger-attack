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

type sha25664 struct {
	h hash.Hash
}

func (s *sha25664) Reset() {
	s.h.Reset()
}

func (s *sha25664) Write(p []byte) (nn int, err error) {
	nn, err = s.h.Write(p)
	return
}

func (s *sha25664) BlockSize() int { return 64 }

func (s *sha25664) Size() int { return 8 }

func (s *sha25664) Sum(in []byte) []byte {
	d := *s
	hash := d.h.Sum(in)
	return hash[:8]
}

func New25664() hash.Hash {
	s := new(sha25664)
	s.h = sha256.New()
	s.Reset()
	return s
}

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

func fromBase16(base16 string) *big.Int {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		panic("bad number: " + base16)
	}
	return i
}

/*
var test2048Key = &PrivateKey{
	PublicKey: PublicKey{
		N: fromBase16("bbf82f090682ce9c2338ac2b9da871f7368d07eed41043a440d6b6f07454f51fb8dfbaaf035c02ab61ea48ceeb6fcd4876ed520d60e1ec4619719d8a5b8b807fafb8e0a3dfc737723ee6b4b7d93a2584ee6a649d060953748834b2454598394ee0aab12d7b61a51f527a9a41f6c1687fe2537298ca2a8f5946f8e5fd091dbdcb"),
		E: 17,
	},
	D: fromBase16("a5dafc5341faf289c4b988db30c1cdf83f31251e0668b42784813801579641b29410b3c7998d6bc465745e5c392669d6870da2c082a939e37fdcb82ec93edac97ff3ad5950accfbc111c76f1a9529444e56aaf68c56c092cd38dc3bef5d20a939926ed4f74a13eddfbe1a1cecc4894af9428c2b7b8883fe4463a4bc85b1cb3c1"),
	Primes: []*big.Int{
		fromBase16("eecfae81b1b9b3c908810b10a1b5600199eb9f44aef4fda493b81a9e3d84f632124ef0236e5d1e3b7e28fae7aa040a2d5b252176459d1f397541ba2a58fb6599"),
		fromBase16("c97fb1f027f453f6341233eaaad1d9353f6c42d08866b1d05a0f2035028b9d869840b41666b42e92ea0da3b43204b5cfce3352524d0416a5a441e700af461503"),
	},
}
*/

var test2048Key = &PrivateKey{
	PublicKey: PublicKey{
		N: fromBase10("74996017239120567164915083818865018336703341786730860076899"),
		E: 65537,
	},
	D: fromBase10("5923056978953691130897057751249065056477792980755807347713"),
	Primes: []*big.Int{
		fromBase10("269171492412515202869949927361"),
		fromBase10("278617979069590382200680986659"),
	},
}

// This function allows one to generate a key, outputting it and to encrypt with this key and outputting it
func encryptTest() {

	s := mrand.NewSource(2)
	r := mrand.New(s)
	// We use 196 bits modulus to have quick encryption/decryption processes
	key, err := rsa.GenerateKey(r, 196)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key)
	testKey := new(PublicKey)
	testKey.E = key.E
	testKey.N = key.N

	secretMessage := []byte("Msg")
	label := []byte("")

	rng := rand.Reader
	ciphertext, err := EncryptOAEP(New25664(), rng, testKey, secretMessage, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return
	}

	// Since encryption is a randomized function, ciphertext will be
	// different each time.
	fmt.Printf("Ciphertext toDecipher: %x\n", ciphertext)
}

func setup() {
	// We first set our things up :
	encryptTest()

	bytesToDecipher, _ := hex.DecodeString(toDecipher)
	decipheredBytes, err := DecryptOAEP(New25664(), nil, test2048Key, bytesToDecipher, []byte(""))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("What we encrypted :", string(decipheredBytes))
}

const (
	//SHA256:	toDecipher  = "1a3cbcc414c7fc0811247de36fde5b079f4072a5461efc94699b37a2de891728ba4d86524f163fe25b53966b9286ed6ff86a7b8cce8d7c7c29a8b79a0e880db2a4e70647f8f9697313562e12bb4fd592a772144034bc45974edcc0af78d0156ce898567b8f56104f27494ff4de4b8dfb9b8297160bac35e1760234a53e8becb7"
	// SHA256:	withPadding = "1cfef11f14bdc4b43d596aa537f68db1ec98f3723ae8b2f62c6f3c8d9bec82152013c59c56a44eca7da0b1ff34741f73efce1a002e35328ecdea6bb463a3677f9df532c0f7b22d7bfbaf79b4cb344f94d18672efc4add0b32feafbed4113b4e3466cd7f09c4285f81a508fd4f3edd23286fc6f37988a2d62445647f8fd0ca4"
	withPadding = "3dd210475802d1450899421303694e77c9d91b4feddb5593"
	toDecipher  = "077ed4d2affb36c82991b94b24433840a44f6e2ca1673ed583"
)

func DivCeil(a, b *big.Int) *big.Int {
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

//unpad is simply the last part of the DecryptOAEP function, we feed it a foundPlaintext and it will unpad it as if it were padded in OAEP
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
