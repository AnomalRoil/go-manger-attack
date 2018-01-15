# go-manger-attack

This is a toy implementation in Go of the well-known chosen-ciphertext attack against RSA-OAEP found by Manger.

James Manger [showed](http://iacr.org/archive/crypto2001/21390229.pdf) that, despite being formally secure, normal implementations of PKCS #1 v2.0 RSA-OAEP decoding were vulnerable to an adaptive chosen ciphertext attack, whose principle is relatively simple.

The present repo is an implementation of that attack in Go, against a *modified*, **vulnerable** RSA-OAEP decryption function instead of the one from the crypto/rsa package. The current crypto/rsa package implementation *may* have a timing discrepancy in the leftPad function which *could* lead to Manger attack, but if it does, then the signal is too low to be exploitable, even locally (according to my benchmarks).

# To test it

You can use the modded RSA library I included to test the code by simply running:
```
go test -v ./mangerattack -run TestOracleWithModdedRSA
```

# To use it with your own oracle

You can call this as a package and provide the `MangerAttack(Oracle)` function with your oracle.
It needs to satisfy the interface "Oracle" so that it accepts a `Decrypt(*big.Int)` function that will send the said big Integer to the oracle, and a `Query() bool` function that will provide your oracle's answer whether the decrypted plaintext is >= B (true, then is has no leading 0 after decryption) or not (false, it has one or more leading zeros after decryption).

An example is provided in [attack_test.go](mangerattack/attack_test.go) that uses Go's "blackbox testing" to show how to implement the interface.


## Intellectual property

Copyright (c) 2016 Nagravision SA, all rights are reserved.

[rsa.go](rsa.go) and parts of [utils.go](utils.go) are copyright The Go Authors, with modifications copyright Nagravision SA.
