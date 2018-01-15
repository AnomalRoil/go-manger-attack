package mangerattack_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"testing"

	. "git.kudelski.com/go-manger-attack/mangerattack"
	"git.kudelski.com/go-manger-attack/moddedrsa"
)

// The test private key used by our Oracle to try and decrypt:
var testKey = &moddedrsa.PrivateKey{
	PublicKey: moddedrsa.PublicKey{
		N: FromBase16("b3a6b8dac202f283b94ed148cf5eedd6a9990ee2cc42e9955c5b06ec40c23a205de3c0ed7f0fbc29b3d38cdffc9129f2e8b2f54a0df471e7f27c0f2eac1298b68a802ae1f2dccf2ebae134b4cbc3866b3b1e65b44ab541b80609a62c09322e46e5e1ff3e05eb2af7ca5f4df2c62f3107d4647bee1a77d3f5c787c583ee834b25bbb0fcbb4ed9e97cef8e8f2b8f947ebdefda9c1e0af23ac7b2445ba3b3d483a76f007fca88cd1f13b2f85b1d435c3000bd1d6fa245489c6239e8b1b6648dcbcb2463589f76df043188e84cb458858ed1f1de3ae89025111854602d9bd6cc6da5369e9c7c32430d25129f23ce37d281883f4de1bd5787d52815c13c2009829fdd"),
		E: 17,
	},
	D: FromBase16("3f680501ea1f286ab9df9528c1a908a61dbd8cc88453d9f87af2f36271357ded4e506235b45fe80eb7f04fd6956069288e5d47838c74646ffb3ad82e97159f4f7c2d3c4fbf20c19805b8e56cfc9f5c9e5119c98aed30ea04b6d63aa6215d0146330478340216c3defc21a30a6410a7e4a550a435eb3959de466c2797f9d3fc671416ef3451c534b74e2793f123adba26ebfd2daca1ea8a7d60737528b85dcbae2c310adc1d9d931e4c016fe24a938f13c5b98226ce19320866c73b006d07f0066a5d009f83be55fd8f994fcdc08679ae13ff7a7b581de3523cee82f3955087f2cbcd648087839ebbb2876498fbb9ed78e69bf0903794a30a77409c614f2d9719"),
	Primes: []*big.Int{
		FromBase16("e15e6eb27860142b2b68b68b4260dc9c595fdc9dfa5eb2f9ed4a530c70ffbb1a6c201ff4a292d58134a5ebd52776806ece5168d1e7becdf20ddb4212dc57e1994f197b858e5202163831bbbbeef99a9a0c3a0aef8080582a7a4e188bbd27780d6cd6e1c65753b54a0969589f35c494e5654d75c0be6c46f04070d9a3fa69b94b"),
		FromBase16("cc1192f49975bff51160601fbd7212b34f2d68c19b25aa1533b2e74e8dcb0774db0016663cfbd36751a3b246f3439a2f3e93c0b7c0426b585e2e4877a89f6cca5297b0ab489c63cce4842edc1d644620025054f0eb500a2f82c3a2089d40c9bd3301c89f05a5161c8f60d8d2e37f2121a1f14263fba1159a2e1952130417ba77"),
	},
}

// The ciphertext we want to decipher
var (
	CiphertextToDecrypt = "7c691962f62e3e2a49a4b7ba8c3fa00f299a233b50cc52faa77c2fbeda868aa443eb10f858a00e8a3bd9a570e4e638fd389eeef12db680ddb824ba6ae6c635f072bea25198305f494dc909713146a0ab9ea8d2e388f1dcea299e66d99741a988bcfb0e4973bf4e791542813120112b5dd06949a1989a9e2a3e596f36541117dd9384837df6c85ec1113378c6309495822e7bca72ab40710707e4fbd8dda38d986a673647f579791a6966e1e533c3713e487a23b8136c6fdcbf38ddd3e976ab3783cc44533ee231f08f604c66312474005fb2f8dbf2c00068aa16dacfb9c41f2beda5bd277e9922bcb92f9ab3f8a83eebce60c03cbb537f722f8fa96f11c272e3"
)

// setKeyAndCipher allows one to generate a key, display it and to encrypt
// with this key a given message and display it. TODO: eventually put
// the key in a file instead and store the ciphertext in a file too, to allow
// easier key and cipher management.
func setKeyAndCipher() {
	s := mrand.NewSource(2)
	r := mrand.New(s)
	key, err := rsa.GenerateKey(r, 2048)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key)
	testKey = &moddedrsa.PrivateKey{
		PublicKey: moddedrsa.PublicKey{
			N: key.N,
			E: key.E,
		},
		D:      key.D,
		Primes: key.Primes,
	}

	secretMessage := []byte("Very secret message nobody can decrypt? At least without the private key?")
	label := []byte("")

	rng := rand.Reader
	ciphertext, err := moddedrsa.EncryptOAEP(sha256.New(), rng, &testKey.PublicKey, secretMessage, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from encryption: %s\n", err)
		return
	}
	CiphertextToDecrypt = hex.EncodeToString(ciphertext)

	fmt.Printf("Ciphertext toDecipher: %x\n", ciphertext)
}

// We instantiate a test structure
type testOracle struct{}

func (testOracle) Decrypt(mcfe *big.Int) {
	// We set the number of zeros to its error value
	moddedrsa.NumberOfZeros = -1

	// And we try to decrypt it, since we modified leftPad, it will set the numberOfZeros variable
	moddedrsa.DecryptOAEP(sha256.New(), nil, testKey, mcfe.Bytes(), []byte(""))
}

// Query() is the hardest part and where I cheat: I'm getting the number of
// leading zeros from a modified version of DecryptOAEP through the global
// variable NumberOfZeros instead of being able to get it through some timing leaks.
func (testOracle) Query() bool {
	// That's it, now if numberOfZeros == 0, then we know mcfe >= B
	if moddedrsa.NumberOfZeros == 0 {
		return true
	} else if moddedrsa.NumberOfZeros > 0 { // otherwise mcfe < B, ie it had a zero MSB
		return false
	}

	// If leftPad wasn't called, then it means that decrypt() itself failed
	log.Fatalln("There was an unexpected error, probably early in decryption stage")
	return false
}

func TestOracleWithModdedRSA(t *testing.T) {
	// The public key gives us N and e
	N := testKey.N
	// we need to cast e to a big int since it is an int
	e := big.NewInt(int64(testKey.E))

	recoveredString := MangerAttack(CiphertextToDecrypt, N, e, testOracle{})

	bytesToDecrypt, _ := hex.DecodeString(CiphertextToDecrypt)
	decryptedBytes, err := moddedrsa.DecryptOAEP(sha256.New(), nil, testKey, bytesToDecrypt, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	if string(decryptedBytes) != recoveredString {
		t.Errorf("Expected to recover the message %s correctly, but got %s instead", string(decryptedBytes), recoveredString)
	}

}

func TestOracleWithModdedRSAWithRandomKey(t *testing.T) {
	// let us use a random key and encrypt with it our ciphertext
	setKeyAndCipher()

	N := testKey.N
	e := big.NewInt(int64(testKey.E))
	recoveredString := MangerAttack(CiphertextToDecrypt, N, e, testOracle{})

	bytesToDecrypt, _ := hex.DecodeString(CiphertextToDecrypt)
	decryptedBytes, err := moddedrsa.DecryptOAEP(sha256.New(), nil, testKey, bytesToDecrypt, []byte(""))
	if err != nil {
		log.Fatal(err)
	}

	if string(decryptedBytes) != recoveredString {
		t.Errorf("Expected to recover the message %s correctly, but got %s instead", string(decryptedBytes), recoveredString)
	}

}
