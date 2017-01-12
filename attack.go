package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
)

// numberOfZeros is  where we cheat: the oracle is the call to our modifed version of
// leftPad in the DecryptOAEP func from the rsa.go file which will populate this variable
// with the number of zeros it leftPadded.
var numberOfZeros int

// countQueries is a counter to know how many queries were necessary
var countQueries int

// The private key used by our Oracle to try and decrypt:
var test2048Key = &PrivateKey{
	PublicKey: PublicKey{
		N: fromBase16("b3a6b8dac202f283b94ed148cf5eedd6a9990ee2cc42e9955c5b06ec40c23a205de3c0ed7f0fbc29b3d38cdffc9129f2e8b2f54a0df471e7f27c0f2eac1298b68a802ae1f2dccf2ebae134b4cbc3866b3b1e65b44ab541b80609a62c09322e46e5e1ff3e05eb2af7ca5f4df2c62f3107d4647bee1a77d3f5c787c583ee834b25bbb0fcbb4ed9e97cef8e8f2b8f947ebdefda9c1e0af23ac7b2445ba3b3d483a76f007fca88cd1f13b2f85b1d435c3000bd1d6fa245489c6239e8b1b6648dcbcb2463589f76df043188e84cb458858ed1f1de3ae89025111854602d9bd6cc6da5369e9c7c32430d25129f23ce37d281883f4de1bd5787d52815c13c2009829fdd"),
		E: 17,
	},
	D: fromBase16("3f680501ea1f286ab9df9528c1a908a61dbd8cc88453d9f87af2f36271357ded4e506235b45fe80eb7f04fd6956069288e5d47838c74646ffb3ad82e97159f4f7c2d3c4fbf20c19805b8e56cfc9f5c9e5119c98aed30ea04b6d63aa6215d0146330478340216c3defc21a30a6410a7e4a550a435eb3959de466c2797f9d3fc671416ef3451c534b74e2793f123adba26ebfd2daca1ea8a7d60737528b85dcbae2c310adc1d9d931e4c016fe24a938f13c5b98226ce19320866c73b006d07f0066a5d009f83be55fd8f994fcdc08679ae13ff7a7b581de3523cee82f3955087f2cbcd648087839ebbb2876498fbb9ed78e69bf0903794a30a77409c614f2d9719"),
	Primes: []*big.Int{
		fromBase16("e15e6eb27860142b2b68b68b4260dc9c595fdc9dfa5eb2f9ed4a530c70ffbb1a6c201ff4a292d58134a5ebd52776806ece5168d1e7becdf20ddb4212dc57e1994f197b858e5202163831bbbbeef99a9a0c3a0aef8080582a7a4e188bbd27780d6cd6e1c65753b54a0969589f35c494e5654d75c0be6c46f04070d9a3fa69b94b"),
		fromBase16("cc1192f49975bff51160601fbd7212b34f2d68c19b25aa1533b2e74e8dcb0774db0016663cfbd36751a3b246f3439a2f3e93c0b7c0426b585e2e4877a89f6cca5297b0ab489c63cce4842edc1d644620025054f0eb500a2f82c3a2089d40c9bd3301c89f05a5161c8f60d8d2e37f2121a1f14263fba1159a2e1952130417ba77"),
	},
}

// The ciphertext we want to decipher, withPadding is the padded message, unencrypted
const (
	withPadding = "70047fc306336e67941dc080cc257dfa88c56d4fcc3b2162506e71e52953a61c8bc6b2ba9fbdd2d63e7857806574e4be5b832039737dfd858468c4b7ad82f1c8653aa063cc416e94aa5dda2297c3b80ea7c7b3ee6ecf7daf7acfb899ec1096c1038c5cc344098402bb195d9b914a105458e04ea05a8fa331f5278b09db2c4761ae189e568117d63e39ad36d2425fe9667fda740f265f5409ecbecf13846197af1bcfea18e9e33eebbf1717835b3589c61379a9826baef0184c13766c6004754b4a8f26a11123e1ef7ed004c38b239b69aef564719490a2a2395488965726336ad30d79d9fe6e268dc00925027fb083f7094e80731c3be5df0d8e131c458edd"
	toDecrypt   = "7c691962f62e3e2a49a4b7ba8c3fa00f299a233b50cc52faa77c2fbeda868aa443eb10f858a00e8a3bd9a570e4e638fd389eeef12db680ddb824ba6ae6c635f072bea25198305f494dc909713146a0ab9ea8d2e388f1dcea299e66d99741a988bcfb0e4973bf4e791542813120112b5dd06949a1989a9e2a3e596f36541117dd9384837df6c85ec1113378c6309495822e7bca72ab40710707e4fbd8dda38d986a673647f579791a6966e1e533c3713e487a23b8136c6fdcbf38ddd3e976ab3783cc44533ee231f08f604c66312474005fb2f8dbf2c00068aa16dacfb9c41f2beda5bd277e9922bcb92f9ab3f8a83eebce60c03cbb537f722f8fa96f11c272e3"
)

// tryOracle is a function which "ask the oracle", this is the hardest part and
//  where I cheat: I'm getting the number of leading zeros from a modified version
//  of DecryptOAEP through the global variable numberOfZeros instead of being able
//  to get it through some timing leaks.
func tryOracle(f, c, e, N *big.Int) bool {
	// We increment our counter
	countQueries++
	// We reset the number of zeros to its error value
	numberOfZeros = -1

	// We calculate c*f^e mod N, cf Step 1.2 in Manger's article
	fe := new(big.Int).Exp(f, e, N)
	cfe := new(big.Int).Mul(c, fe)
	mcfe := new(big.Int).Mod(cfe, N)

	// And we try to decrypt it, since we modified leftPad, it will set the numberOfZeros variable
	DecryptOAEP(sha256.New(), nil, test2048Key, mcfe.Bytes(), []byte(""))
	// That's it, now if numberOfZeros == 0, then we know mcfe >= B
	if numberOfZeros == 0 {
		return true
	} else if numberOfZeros > 0 { // otherwise mcfe < B, ie it had a zero MSB
		return false
	} else { // If leftPad wasn't called, then it means that decrypt() itself failed
		log.Fatalln("There was an unexpected error too early in decryption stage")
	}
	return false
}

// See the 2 modifications made in rsa.go and the file utils.go to get a better understanding.
func main() {

	// If you want to use another key or another ciphertext, cf:
	//setup()

	// Now we can try the attack :

	// This is the clear text padded (what we would like to find out)
	clearPadded, _ := hex.DecodeString(withPadding)

	// This is the ciphertext we want to decipher
	bytesToDecipher, _ := hex.DecodeString(toDecrypt)
	c := new(big.Int).SetBytes(bytesToDecipher)
	// The public key gives us N and e :
	N := test2048Key.N
	e := big.NewInt(int64(test2048Key.E))

	// A few useful big.Int :
	zero := new(big.Int).SetInt64(int64(0))
	two := new(big.Int).SetInt64(int64(2))

	// We know that clearPadded	∈ [0,B[
	k := (N.BitLen() + 7) / 8
	B := new(big.Int).Exp(two, big.NewInt(int64((k-1)*8)), nil)
	m := new(big.Int).SetBytes(clearPadded)

	// Assert and sanity checks:
	// we assume that 2B < n
	if new(big.Int).Mul(two, B).Cmp(N) >= 0 {
		log.Fatalln("Unsupported case: 2B >= N")
	}

	if m.Cmp(B) != -1 {
		log.Fatalln("The plaintext is bigger than B, it is not OAEP compliant")
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
	for !tryOracle(f1, c, e, N) { // We are sure it returns either numberOfZeros == 0 or > 0
		stepsFor1++
		// 1.3a
		// Then we are still < B, it returned false
		f1.Mul(two, f1)
	} // 1.3b
	// Then numberOfZeros == 0, tryOracle returned true, so we are >= B
	// this implies that f1*m ∈ [B,2B[
	fmt.Println("Step 1 finished: f1=", f1, "found in", stepsFor1, "queries")

	f12 := new(big.Int).Div(f1, two) // So f1/2 ∈ [B/2,B[
	B12 := new(big.Int).Div(B, two)
	fmt.Println("\tChecking f1/2*m ∈ [B/2,B[:", B12.Cmp(new(big.Int).Mul(f12, m)) == -1 && B.Cmp(new(big.Int).Mul(f12, m)) == 1)

	// Step 2
	fmt.Println("Starting step 2")
	stepsFor2 := 0
	// 2.1
	nB := new(big.Int).Add(N, B)
	nBB := new(big.Int).Div(nB, B)
	f2 := new(big.Int).Mul(nBB, f12)

	// 2.2
	for tryOracle(f2, c, e, N) { // 2.3a
		stepsFor2++
		// i.e. we are >= B, tryOracle returned true
		f2.Add(f2, f12)
	} // 2.3b
	// i.e. numberOfZeros > 0, tryOracle returned false so we are < B
	// this implies that we have found a f2 such that f2*m ∈ [N,N+B[
	fmt.Println("Step 2 finished: f2=", f2, "\n\tfound in ", stepsFor2, "steps.")

	// Step 3
	fmt.Println("Starting step 3, this can take a bit longer than the previous ones")
	stepsFor3 := 0
	// 3.1
	mmin := divCeil(N, f2)
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
		f3 := divCeil(iN, mmin)
		// 3.5a
		iNB := new(big.Int).Add(iN, B)
		if tryOracle(f3, c, e, N) { // then it wasn't padded, >=B
			mmin = divCeil(iNB, f3)
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
}
