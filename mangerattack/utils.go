// This contains modified copies of some of the code from the Go crypto package
// all credits goes to The Go Authors, it follows a BSD-style licence that can
// be found in the GO_LICENSE file
package mangerattack

import (
	"crypto/subtle"
	"fmt"
	"hash"
	"log"
	"math/big"

	"git.kudelski.com/go-manger-attack/moddedrsa"
)

// fromBase16 returns a new Big.Int from an hexadecimal string, as found in the go crypto tests suite
func FromBase16(base16 string) *big.Int {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		panic("bad number: " + base16)
	}
	return i
}

// divCeil allows to perform a divison and ceil it instead of flooring as do the big.Int Div function
func divCeil(a, b *big.Int) (*big.Int, error) {
	zero := new(big.Int).SetInt64(0)
	one := new(big.Int).SetInt64(1)
	// we want to avoid the runtime panic caused by QuoRem in case of 0
	if zero.Cmp(b) == 0 {
		return nil, fmt.Errorf("Division by zero")
	}
	remainder := new(big.Int)
	ceiled, _ := new(big.Int).QuoRem(a, b, remainder)
	if remainder.Cmp(zero) > 0 {
		// we have to ceil it
		ceiled.Add(ceiled, one)
	}
	return ceiled, nil
}

// unpad is simply the last part of the DecryptOAEP function, as it stands in
// the Go crypto/rsa package, we feed it with a paddedText and it will
// unpad it as if it were OEAP padded (even if it is not, useful for tests)
func unpad(k int, paddedText *big.Int, hash hash.Hash, label []byte) []byte {
	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	em := moddedrsa.LeftPad(paddedText.Bytes(), k)
	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]
	moddedrsa.Mgf1XOR(seed, hash, db)
	moddedrsa.Mgf1XOR(db, hash, seed)
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
