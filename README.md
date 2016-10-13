# go-manger-attack

This is a toy implementation in Go of the well known chosen ciphertext attack against RSA-OAEP found by Manger.

James Manger showed that, despite being formally secure, normal implementations of PKCS #1 v2.0 RSA OAEP decoding were vulnerable to an adaptive chosen ciphertext attack, whose principle is relatively simple.
The present repo is an implementation of that attack in go, using a modified, vulnerable RSA OEAP decryption function instead of the one from the crypto/rsa package.
