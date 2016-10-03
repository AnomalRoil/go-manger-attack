package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"hash"
	"log"
	"math/big"
	"os"
)

// this is our cheat: the oracle is the call to leftPad in the DecryptOAEP func from the rsa.go file
var numberOfZeros int

func fromBase16(base16 string) *big.Int {
	i, ok := new(big.Int).SetString(base16, 16)
	if !ok {
		panic("bad number: " + base16)
	}
	return i
}

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

func encryptTest() {
	secretMessage := []byte("This is a secret message you will never find.")
	label := []byte("")

	rng := rand.Reader

	ciphertext, err := EncryptOAEP(sha256.New(), rng, &test2048Key.PublicKey, secretMessage, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return

	}

	// Since encryption is a randomized function, ciphertext will be
	// different each time.
	fmt.Printf("Ciphertext: %x\n", ciphertext)
}

const (
	toDecipher  = "1a3cbcc414c7fc0811247de36fde5b079f4072a5461efc94699b37a2de891728ba4d86524f163fe25b53966b9286ed6ff86a7b8cce8d7c7c29a8b79a0e880db2a4e70647f8f9697313562e12bb4fd592a772144034bc45974edcc0af78d0156ce898567b8f56104f27494ff4de4b8dfb9b8297160bac35e1760234a53e8becb7"
	withPadding = "1cfef11f14bdc4b43d596aa537f68db1ec98f3723ae8b2f62c6f3c8d9bec82152013c59c56a44eca7da0b1ff34741f73efce1a002e35328ecdea6bb463a3677f9df532c0f7b22d7bfbaf79b4cb344f94d18672efc4add0b32feafbed4113b4e3466cd7f09c4285f81a508fd4f3edd23286fc6f37988a2d62445647f8fd0ca4"
)

func main() {
	// We first set our things up :
	/*encryptTest()
	bytesToDecipher, _ := hex.DecodeString(toDecipher)
	decipheredBytes, err := DecryptOAEP(sha256.New(), nil, test2048Key, bytesToDecipher, []byte(""))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(decipheredBytes))
	*/
	// Now we can try the attack :

	// This is the clear text padded (what we would like to find out)
	clearPadded, _ := hex.DecodeString(withPadding)

	// This is the ciphertext we want to decipher
	bytesToDecipher, _ := hex.DecodeString(toDecipher)
	c := new(big.Int).SetBytes(bytesToDecipher)
	// The public key gives us N and e :
	N := test2048Key.N
	e := big.NewInt(int64(test2048Key.E))

	// A few useful big.Int :
	zero := new(big.Int).SetInt64(int64(0))
	one := new(big.Int).SetInt64(int64(1))
	two := new(big.Int).SetInt64(int64(2))

	// We know that clearPadded € [0,B)
	k := (N.BitLen() + 7) / 8
	B := new(big.Int).Exp(two, big.NewInt(int64((k-1)*8)), nil)
	m := new(big.Int).SetBytes(clearPadded)
	fmt.Println("\nWhat we want to recover:", leftPad(m.Bytes(), k))

	// Assert:
	// we assume that 2B < n
	if new(big.Int).Mul(two, B).Cmp(N) >= 0 {
		log.Fatalln("2B >= N")
	}

	if m.Cmp(B) != -1 {
		log.Fatalln("The plaintext is bigger than B")
	}

	// Step 1
	// 1.1
	f1 := new(big.Int).SetInt64(int64(2))
	// 1.2
	endStep1 := false
	for !endStep1 {
		tryOracle(f1, c, e, N) // we are sure this ends with either numberOfZero == 0 or > 0
		// 1.3a
		if numberOfZeros > 0 { // Then we are still < B
			f1 = new(big.Int).Mul(two, f1)
		} else { // 1.3b
			// Then numberOfZeros == 0, so we are >= B
			// this implies that f1*m € [B,2B)
			endStep1 = true
		}
	}
	fmt.Println("Step 1 finished: f1=", f1)
	f12 := new(big.Int).Div(f1, two) // so f1/2 € [B/2,B)
	B12 := new(big.Int).Div(B, two)
	fmt.Println("  Checking f1/2*m € [B/2,B):", B12.Cmp(new(big.Int).Mul(f12, m)) == -1 && B.Cmp(new(big.Int).Mul(f12, m)) == 1)

	// Step 2
	// 2.1
	nB := new(big.Int).Add(N, B)
	nBB := new(big.Int).Div(nB, B)
	f2 := new(big.Int).Mul(nBB, f12)

	// 2.2
	endStep2 := false
	queries := new(big.Int).SetInt64(int64(1))
	for !endStep2 {
		tryOracle(f2, c, e, N)
		// 2.3a
		if numberOfZeros == 0 { // ie we are >= B
			f2 = new(big.Int).Add(f2, f12)
			queries.Add(queries, one)
		} else { // 2.3b
			// ie numberOfZeros > 0, so we are < B
			// this implies that we have found a f2 such that f2*m € [N,N+B)
			endStep2 = true
		}
	}
	fmt.Println("Step 2 finished: f2=", f2, "\n found in ", queries, "steps.")

	// Step 3
	mFound := false
	stepsFor3 := 0
	// 3.1
	remainder := new(big.Int)
	mmin, _ := new(big.Int).QuoRem(N, f2, remainder)
	if remainder.Cmp(zero) > 0 {
		mmin.Add(mmin, one)
	}
	mmax := new(big.Int).Div(nB, f2)
	diff := new(big.Int).Sub(mmax, mmin)
	fmt.Println("diff: ", diff)
	fmt.Println("Sanity check : (mmax-mmin)*f2 ~B", new(big.Int).Sub(B, new(big.Int).Mul(f2, diff)))
	for !mFound {
		stepsFor3++
		// 3.2
		BB := new(big.Int).Mul(two, B)
		ftmp := new(big.Int).Div(BB, diff)
		// 3.3
		ftmpmmin := new(big.Int).Mul(ftmp, mmin)
		i := new(big.Int).Div(ftmpmmin, N)
		// 3.4
		iN := new(big.Int).Mul(i, N)
		remainder.SetInt64(int64(0))
		f3, _ := new(big.Int).QuoRem(iN, mmin, remainder)
		if remainder.Cmp(zero) > 0 {
			f3.Add(f3, one)
		}
		tryOracle(f3, c, e, N)
		// 3.5a
		iNB := new(big.Int).Add(iN, B)
		if numberOfZeros == 0 {
			remainder.SetInt64(int64(0))
			mmin, _ = new(big.Int).QuoRem(iNB, f3, remainder)
			if remainder.Cmp(zero) > 0 {
				mmin.Add(mmin, one)
			}
		} else { // 3.5b
			mmax = new(big.Int).Div(iNB, f3)
		}

		diff = new(big.Int).Sub(mmax, mmin)
		if diff.Cmp(zero) <= 0 {
			mFound = true
		}
	}
	fmt.Println("Step 3 finished: \nfound m=", mmin, "\nreal  m=", m)
	fmt.Println(" found in ", stepsFor3, "steps")
	recoveredPlaintext := unpad(k, mmin, sha256.New(), []byte(""))
	fmt.Println("And we have recovered:\n", string(recoveredPlaintext))
}

func tryOracle(f, c, e, N *big.Int) {
	numberOfZeros = -1
	// we calculate c*f^e mod N
	fe := new(big.Int).Exp(f, e, N)
	cfe := new(big.Int).Mul(c, fe)
	mcfe := new(big.Int).Mod(cfe, N)
	// and we try to decrypt it
	_, err := DecryptOAEP(sha256.New(), nil, test2048Key, mcfe.Bytes(), []byte(""))
	if err == nil {
		log.Fatalln("Decryption was succesful, this makes no sense")
	}
	if numberOfZeros == -1 { // If leftPad wasn't called, then it means decrypt() failed
		log.Fatalln("There was an unexpected error too early in decryption stage")
	}
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
