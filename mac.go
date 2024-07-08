// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"hash"

	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/pbkdf2"
)

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

var (
	oidSHA1   = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
	oidSHA256 = asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1})
	oidSM3    = asn1.ObjectIdentifier([]int{1, 2, 156, 10197, 1, 401})
	oidPBMAC1 = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 14})
)

func doMac(macData *macData, message, password []byte) ([]byte, error) {
	var hFn func() hash.Hash
	var key []byte
	switch {
	case macData.Mac.Algorithm.Algorithm.Equal(oidSHA1):
		hFn = sha1.New
		key = pbkdfMAC(sha1Hash, macData.MacSalt, password, macData.Iterations, 20)
	case macData.Mac.Algorithm.Algorithm.Equal(oidSHA256):
		hFn = sha256.New
		key = pbkdfMAC(sha256Hash, macData.MacSalt, password, macData.Iterations, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(oidSM3):
		hFn = sm3.New
		key = pbkdfMAC(sm3Hash, macData.MacSalt, password, macData.Iterations, 32)
	case macData.Mac.Algorithm.Algorithm.Equal(oidPBMAC1):
		var params pbmac1Params
		var kdfparams pbkdf2Params
		if err := unmarshal(macData.Mac.Algorithm.Parameters.FullBytes, &params); err != nil {
			return nil, err
		}
		if err := unmarshal(params.Kdf.Parameters.FullBytes, &kdfparams); err != nil {
			return nil, err
		}
		originalPassword, err := decodeBMPString(password)
		if err != nil {
			return nil, err
		}
		utf8Password := []byte(originalPassword)
		var keyLen int
		var prf func() hash.Hash
		switch {
		case params.MessageAuthScheme.Algorithm.Equal(oidHmacWithSHA1):
			hFn = sha1.New
			keyLen = 20
		case params.MessageAuthScheme.Algorithm.Equal(oidHmacWithSHA256):
			hFn = sha256.New
			keyLen = 32
		case params.MessageAuthScheme.Algorithm.Equal(oidHmacWithSM3):
			hFn = sm3.New
			keyLen = 32
		default:
			return nil, NotImplementedError("unknown message auth scheme: " + params.MessageAuthScheme.Algorithm.String())
		}
		if kdfparams.KeyLength > 0 {
			keyLen = kdfparams.KeyLength
		}
		switch {
		case kdfparams.Prf.Algorithm.Equal(oidHmacWithSHA1):
			prf = sha1.New
		case kdfparams.Prf.Algorithm.Equal(oidHmacWithSHA256):
			prf = sha256.New
		case kdfparams.Prf.Algorithm.Equal(oidHmacWithSM3):
			prf = sm3.New
		default:
			return nil, NotImplementedError("unknown PRF algorithm: " + kdfparams.Prf.Algorithm.String())
		}
		key = pbkdf2.Key(utf8Password, kdfparams.Salt.Bytes, kdfparams.Iterations, keyLen, prf)

	default:
		return nil, NotImplementedError("unknown digest algorithm: " + macData.Mac.Algorithm.Algorithm.String())
	}

	mac := hmac.New(hFn, key)
	mac.Write(message)
	return mac.Sum(nil), nil
}

func verifyMac(macData *macData, message, password []byte) error {
	expectedMAC, err := doMac(macData, message, password)
	if err != nil {
		return err
	}
	if !hmac.Equal(macData.Mac.Digest, expectedMAC) {
		return ErrIncorrectPassword
	}
	return nil
}

func computeMac(macData *macData, message, password []byte) error {
	digest, err := doMac(macData, message, password)
	if err != nil {
		return err
	}
	macData.Mac.Digest = digest
	return nil
}

//	PBMAC1-params ::= SEQUENCE {
//		keyDerivationFunc AlgorithmIdentifier {{PBMAC1-KDFs}},
//		messageAuthScheme AlgorithmIdentifier {{PBMAC1-MACs}}
//	}
type pbmac1Params struct {
	Kdf               pkix.AlgorithmIdentifier
	MessageAuthScheme pkix.AlgorithmIdentifier
}

// createPBMAC1Parameters creates a PBMAC1-params structure.
func createPBMAC1Parameters(prf, messageAuthScheme asn1.ObjectIdentifier, salt []byte, iterations int) ([]byte, error) {
	var err error

	if messageAuthScheme == nil {
		messageAuthScheme = oidHmacWithSHA256
	}

	var kdfparams pbkdf2Params
	if kdfparams.Salt.FullBytes, err = asn1.Marshal(salt); err != nil {
		return nil, err
	}
	kdfparams.Iterations = iterations
	kdfparams.Prf.Algorithm = prf

	switch {
	case messageAuthScheme.Equal(oidHmacWithSHA1):
		kdfparams.KeyLength = 20
	case messageAuthScheme.Equal(oidHmacWithSHA256):
		kdfparams.KeyLength = 32
	case messageAuthScheme.Equal(oidHmacWithSM3):
		kdfparams.KeyLength = 32
	default:
		return nil, NotImplementedError("unknown message auth scheme: " + messageAuthScheme.String())
	}

	var params pbmac1Params
	params.Kdf.Algorithm = oidPBKDF2
	if params.Kdf.Parameters.FullBytes, err = asn1.Marshal(kdfparams); err != nil {
		return nil, err
	}
	params.MessageAuthScheme.Algorithm = messageAuthScheme

	return asn1.Marshal(params)
}
