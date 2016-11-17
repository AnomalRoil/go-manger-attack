# go-manger-attack

This is a toy implementation in Go of the well known chosen ciphertext attack against RSA-OAEP found by Manger.

James Manger showed that, despite being formally secure, normal implementations of PKCS #1 v2.0 RSA OAEP decoding were vulnerable to an adaptive chosen ciphertext attack, whose principle is relatively simple.

The present repo is an implementation of that attack in Go, against a *modified*, **vulnerable** RSA OEAP decryption function instead of the one from the crypto/rsa package. The current crypto/rsa package implementation *may* have a timing discrepancy in the leftPad function which *could* lead to Manger attack, but if it does, then the signal is too low to be exploitable, even locally (according to my benchmarks).

## Intellectual property

Copyright (c) 2016 Nagravision SA, all rights are reserved.
[rsa.go](rsa.go) and parts of [utils.go](utils.go) are copyright The Go Authors, with modifications copyright Nagravision SA.
