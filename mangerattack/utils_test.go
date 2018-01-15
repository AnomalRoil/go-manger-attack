package mangerattack

import (
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestFromBase16(t *testing.T) {
	if new(big.Int).SetInt64(2).Cmp(FromBase16("2")) != 0 {
		t.Errorf("Error when evaluating FromBase16(\"2\").")
	}
	if new(big.Int).SetInt64(12).Cmp(FromBase16("c")) != 0 {
		t.Errorf("Error when evaluating FromBase16(\"c\").")
	}
	if new(big.Int).SetInt64(65537).Cmp(FromBase16("10001")) != 0 {
		t.Errorf("Error when evaluating FromBase16(\"10001\").")
	}
	if new(big.Int).SetInt64(65536).Cmp(FromBase16("10001")) != -1 {
		t.Errorf("Error when evaluating FromBase16(\"10001\").")
	}
	if new(big.Int).SetInt64(65538).Cmp(FromBase16("10001")) != 1 {
		t.Errorf("Error when evaluating FromBase16(\"10001\").")
	}
}

// divCeil allows to perform a divison and ceil it instead of flooring as do the big.Int Div function
func TestDivCeil(t *testing.T) {
	if res, _ := divCeil(new(big.Int).SetInt64(15), new(big.Int).SetInt64(4)); res.Cmp(new(big.Int).SetInt64(4)) != 0 {
		t.Errorf("Error when doing divCeil(15,4), it gave: %s", res.Text(10))
	}
	if res, _ := divCeil(new(big.Int).SetInt64(13), new(big.Int).SetInt64(4)); res.Cmp(new(big.Int).SetInt64(4)) != 0 {
		t.Errorf("Error when doing divCeil(13,4), it gave: %s", res.Text(10))
	}
	if res, _ := divCeil(new(big.Int).SetInt64(-15), new(big.Int).SetInt64(4)); res.Cmp(new(big.Int).SetInt64(-3)) != 0 {
		t.Errorf("Error when doing divCeil(-15,4), it gave: %s", res.Text(10))
	}
	if res, _ := divCeil(new(big.Int).SetInt64(15), new(big.Int).SetInt64(5)); res.Cmp(new(big.Int).SetInt64(3)) != 0 {
		t.Errorf("Error when doing divCeil(15,5), it gave: %s", res.Text(10))
	}
	if res, _ := divCeil(new(big.Int).SetInt64(0), new(big.Int).SetInt64(5)); res.Cmp(new(big.Int).SetInt64(0)) != 0 {
		t.Errorf("Error when doing divCeil(0,5), it gave: %s", res.Text(10))
	}
	if _, err := divCeil(new(big.Int).SetInt64(15), new(big.Int).SetInt64(0)); err.Error() != "Division by zero" {
		t.Errorf("Error when doing divCeil(15,0), it didn't gave the correct error: %v", err)
	}
}

func TestUnpad(t *testing.T) {
	paddedText := "70047fc306336e67941dc080cc257dfa88c56d4fcc3b2162506e71e52953a61c8bc6b2ba9fbdd2d63e7857806574e4be5b832039737dfd858468c4b7ad82f1c8653aa063cc416e94aa5dda2297c3b80ea7c7b3ee6ecf7daf7acfb899ec1096c1038c5cc344098402bb195d9b914a105458e04ea05a8fa331f5278b09db2c4761ae189e568117d63e39ad36d2425fe9667fda740f265f5409ecbecf13846197af1bcfea18e9e33eebbf1717835b3589c61379a9826baef0184c13766c6004754b4a8f26a11123e1ef7ed004c38b239b69aef564719490a2a2395488965726336ad30d79d9fe6e268dc00925027fb083f7094e80731c3be5df0d8e131c458edd"
	clearText := "Very secret message nobody can decrypt? At least without the private key?"

	padded := FromBase16(paddedText)

	unpadText := unpad(256, padded, sha256.New(), []byte(""))
	if string(unpadText) != clearText {
		t.Errorf("Unable to unpad as intended. Produced %x instead of %s", unpadText, clearText)
	}
}
