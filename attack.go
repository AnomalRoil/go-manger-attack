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

// The private key used by our Oracle to try and decrypt:
/*var test2048Key = &PrivateKey{
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
*/

var test2048Key = &PrivateKey{
	PublicKey: PublicKey{
		N: fromBase10("63542581176726430029479937913057195347314181385476859100369"),
		E: 65537,
	},
	D: fromBase10("44700965295509335643669119085712502188906652768901750600321"),
	Primes: []*big.Int{
		fromBase10("246798075899583082988988890053"),
		fromBase10("257467895343643450077796700573"),
	},
}

// The ciphertext we want to decipher, the commented one uses a private key found in utils.go in comments
const (
	//SHA256:	toDecipher  = "1a3cbcc414c7fc0811247de36fde5b079f4072a5461efc94699b37a2de891728ba4d86524f163fe25b53966b9286ed6ff86a7b8cce8d7c7c29a8b79a0e880db2a4e70647f8f9697313562e12bb4fd592a772144034bc45974edcc0af78d0156ce898567b8f56104f27494ff4de4b8dfb9b8297160bac35e1760234a53e8becb7"
	// SHA256:	withPadding = "1cfef11f14bdc4b43d596aa537f68db1ec98f3723ae8b2f62c6f3c8d9bec82152013c59c56a44eca7da0b1ff34741f73efce1a002e35328ecdea6bb463a3677f9df532c0f7b22d7bfbaf79b4cb344f94d18672efc4add0b32feafbed4113b4e3466cd7f09c4285f81a508fd4f3edd23286fc6f37988a2d62445647f8fd0ca4"
	//	withPadding = "3dd210475802d1450899421303694e77c9d91b4feddb5593"
	//	toDecipher  = "077ed4d2affb36c82991b94b24433840a44f6e2ca1673ed583"
	withPadding = "55cf82d56909ba2e31f3449ea69de547bb9ff45c27da4bd7"
	toDecipher  = "0981bb39e5236474ac9ed0c0db93f1b3865c0f8238dbae4f20"
)

// See the 2 modifications made in rsa.go and the file utils.go to get a better understanding.

func main() {
	/*
		// If you want to use another key or another ciphertext, cf:
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

	// We can now begin the attack, following James Manger "A Chosen Ciphertext Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) au Standardized in PKCS #1 v2.0" article and notation. The steps are direct references to this article
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
