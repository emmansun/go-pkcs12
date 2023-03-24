# package pkcs12

[![ci](https://github.com/emmansun/go-pkcs12/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/go-pkcs12/actions/workflows/ci.yml)
[![Documentation](https://pkg.go.dev/badge/software.sslmate.com/src/go-pkcs12)](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12)
![GitHub go.mod Go version (branch)](https://img.shields.io/github/go-mod/go-version/emmansun/go-pkcs12)
[![Release](https://img.shields.io/github/release/emmansun/go-pkcs12/all.svg)](https://github.com/emmansun/go-pkcs12/releases)

    import "github.com/emmansun/go-pkcs12" 

Package pkcs12 implements some of PKCS#12 (also known as P12 or PFX).
It is intended for decoding DER-encoded P12/PFX files for use with the `crypto/tls` and/or `tlcp` implementation
packages, and for encoding P12/PFX files for use by legacy applications which
do not support newer formats.  Since PKCS#12 uses weak encryption
primitives, it SHOULD NOT be used for new applications.

Note that only DER-encoded PKCS#12 files are supported, even though PKCS#12
allows BER encoding.  This is because encoding/asn1 only supports DER.

This package is forked from `https://github.com/SSLMate/go-pkcs12`, which is forked from `golang.org/x/crypto/pkcs12`, which is frozen.
The implementation is distilled from https://tools.ietf.org/html/rfc7292
and referenced documents.
