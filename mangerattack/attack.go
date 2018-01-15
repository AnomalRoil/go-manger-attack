package mangerattack

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
)

// countQueries is a counter to know how many queries were necessary
var countQueries int

// A few useful big.Int :
var (
	zero = new(big.Int).SetInt64(int64(0))
	two  = new(big.Int).SetInt64(int64(2))
)

// Oracle is an interface to allow anyone to easily provide its own oracle queries.
// The Decrypt function is provided with the modified ciphertext we want the oracle
// to be fed with, while the Query function is returning the bool we need to attack.
type Oracle interface {
	// `Decrypt(*big.Int)` function that will send the said big Integer to the oracle
	Decrypt(*big.Int)
	// Query() bool will provide your oracle's answer whether the decrypted plaintext is >= B (true, then is has no leading 0 after decryption) or not (false, it has one or more leading zeros after decryption).
	Query() bool
}

// tryOracle is a function which "ask the oracle"
func tryOracle(f, c, e, N *big.Int, O Oracle) bool {
	// We increment our counter
	countQueries++

	// We calculate c*f^e mod N, cf Step 1.2 in Manger's article
	fe := new(big.Int).Exp(f, e, N)
	cfe := new(big.Int).Mul(c, fe)
	mcfe := new(big.Int).Mod(cfe, N)

	// we send the value to our oracle
	O.Decrypt(mcfe)
	// we query our oracle's answer
	return O.Query()
}

// See the 2 modifications made in rsa.go and the file utils.go to get a better understanding.
func MangerAttack(toDecrypt string, N, e *big.Int, O Oracle) string {
	// We reset the query counter
	countQueries = 0
	// This is the ciphertext we want to decipher
	bytesToDecipher, _ := hex.DecodeString(toDecrypt)
	// We take the byte to decipher and cast them as bit integer
	c := new(big.Int).SetBytes(bytesToDecipher)

	// We setup k and B
	k := (N.BitLen() + 7) / 8
	B := new(big.Int).Exp(two, big.NewInt(int64((k-1)*8)), nil)

	// Assert and sanity checks:
	// we assume that 2B < n
	if new(big.Int).Mul(two, B).Cmp(N) >= 0 {
		log.Fatalln("Unsupported case: 2B >= N")
	}

	// We can now begin the attack, following James Manger "A Chosen Ciphertext Attack
	//  on RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1 v2.0"
	//  article and notation. The steps are direct references to this article, which can be
	//	found at: http://archiv.infsec.ethz.ch/education/fs08/secsem/Manger01.pdf
	// Step 1
	fmt.Println("Starting step 1")
	stepsFor1 := 0
	// 1.1
	f1 := new(big.Int).SetInt64(int64(2))
	// 1.2
	for !tryOracle(f1, c, e, N, O) { // We are sure it returns MSB != 0 or == 0
		stepsFor1++
		// 1.3a
		// Then we are still < B, it returned false
		f1.Mul(two, f1)
	} // 1.3b
	// Then MSB != 0, tryOracle returned true, so we are >= B
	// this implies that f1*m ∈ [B,2B[
	fmt.Println("Step 1 finished: f1=", f1, "found in", stepsFor1, "queries")

	// f12 is the "return value" of the step 1
	f12 := new(big.Int).Div(f1, two) // So f1/2 ∈ [B/2,B[

	// Step 2
	fmt.Println("Starting step 2")
	stepsFor2 := 0
	// 2.1
	nB := new(big.Int).Add(N, B)
	nBB := new(big.Int).Div(nB, B)
	f2 := new(big.Int).Mul(nBB, f12)

	// 2.2
	for tryOracle(f2, c, e, N, O) { // 2.3a
		stepsFor2++
		// i.e. we are >= B, tryOracle returned true
		f2.Add(f2, f12)
	} // 2.3b

	// i.e. tryOracle returned false so we are < B
	// this implies that we have found a f2 such that f2*m ∈ [N,N+B[
	fmt.Println("Step 2 finished: f2=", f2, "\n\tfound in ", stepsFor2, "steps.")

	// Step 3
	fmt.Println("Starting step 3, this can take a bit longer than the previous ones")
	stepsFor3 := 0
	// 3.1
	mmin, _ := divCeil(N, f2)
	mmax := new(big.Int).Div(nB, f2)
	BB := new(big.Int).Mul(two, B)
	diff := new(big.Int).Sub(mmax, mmin)
	fmt.Println("\tSanity check : (mmax-mmin)*f2 ~B? Okay if this is 'small': B-(mmax-mmin)*f2=",
		new(big.Int).Sub(B, new(big.Int).Mul(f2, diff)))

	for diff.Sub(mmax, mmin).Cmp(zero) > 0 {
		stepsFor3++
		// 3.2
		ftmp := new(big.Int).Div(BB, diff)
		// 3.3
		ftmpmmin := new(big.Int).Mul(ftmp, mmin)
		i := new(big.Int).Div(ftmpmmin, N)
		// 3.4
		iN := new(big.Int).Mul(i, N)
		f3, _ := divCeil(iN, mmin)
		// 3.5a
		iNB := new(big.Int).Add(iN, B)
		if tryOracle(f3, c, e, N, O) { // then it wasn't padded, >=B
			mmin, _ = divCeil(iNB, f3)
		} else { // 3.5b <B
			mmax.Div(iNB, f3)
		}
	}

	fmt.Println("Step 3 finished: \n\tfound m=", mmin)
	fmt.Println("\tfound in ", stepsFor3, "steps")

	// We now have found m = mmin, we can unpad it:
	recoveredPlaintext := unpad(k, mmin, sha256.New(), []byte(""))

	fmt.Printf("And we have recovered:\n\t\t\"%s\"\n", string(recoveredPlaintext))
	fmt.Println("\tin ", countQueries, " queries, with k=", k)

	return string(recoveredPlaintext)
}
