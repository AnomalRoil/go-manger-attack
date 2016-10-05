package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
)

// this is our cheat: the oracle is the call to leftPad in the DecryptOAEP func from the rsa.go file
// which will populate this variable with the number of zero it leftPadded.
var numberOfZeros int

// a counter to know how many queries were necessary
var countQueries int

func main() {
	/*
		setup()
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

	// Assert and sanity checks:
	// we assume that 2B < n
	if new(big.Int).Mul(two, B).Cmp(N) >= 0 {
		log.Fatalln("unsupported case: 2B >= N")
	}

	if m.Cmp(B) != -1 {
		log.Fatalln("The plaintext is bigger than B, it is not OAEP compliant")
	}

	// We can now begin the attack, following James Manger "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) au Standardized in PKCS #1 v2.0" article and notation
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
	mmin := DivCeil(N, f2)
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
		f3 := DivCeil(iN, mmin)
		tryOracle(f3, c, e, N)
		// 3.5a
		iNB := new(big.Int).Add(iN, B)
		if numberOfZeros == 0 {
			mmin = DivCeil(iNB, f3)
		} else { // 3.5b
			// here we can just floor, as Div already does
			mmax = new(big.Int).Div(iNB, f3)
		}

		diff = new(big.Int).Sub(mmax, mmin)
		if diff.Cmp(zero) <= 0 {
			mFound = true
		}
	}
	fmt.Println("Step 3 finished: \nfound m=", mmin, "\nreal  m=", m)
	fmt.Println(" found in ", stepsFor3, "steps")

	// We now have found m = mmin, we can unpad it:
	recoveredPlaintext := unpad(k, mmin, New25664(), []byte(""))

	fmt.Println("And we have recovered:\n", string(recoveredPlaintext))
	fmt.Println("in ", countQueries, " queries, with a k=", k, "!")
}

func tryOracle(f, c, e, N *big.Int) {
	// we increment our counter
	countQueries++
	// we reset the number of zeros to its error value
	numberOfZeros = -1

	// we calculate c*f^e mod N
	fe := new(big.Int).Exp(f, e, N)
	cfe := new(big.Int).Mul(c, fe)
	mcfe := new(big.Int).Mod(cfe, N)

	// and we try to decrypt it
	_, err := DecryptOAEP(New25664(), nil, test2048Key, mcfe.Bytes(), []byte(""))
	if err == nil {
		log.Fatalln("Decryption was succesful, this makes no sense")
	}
	if numberOfZeros == -1 { // If leftPad wasn't called, then it means decrypt() failed
		log.Fatalln("There was an unexpected error too early in decryption stage")
	}
	// that's it, now if numberOfZeros == 0, then we know mcfe >= B otherwise mcfe < B
}
