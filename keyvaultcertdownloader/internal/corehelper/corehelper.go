// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

// Package that provides some core functionality functions.

package corehelper

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	gpkcs12 "software.sslmate.com/src/go-pkcs12"
)

// GetBlocksFromPEM - Gets decoded data block from PEM
func GetBlocksFromPEM(data []byte, blocks []*pem.Block) []*pem.Block {
	block, rest := pem.Decode(data)
	if block == nil {
		return blocks
	}

	blocks = append(blocks, block)
	return GetBlocksFromPEM(rest, blocks)
}

// GetBlocksFromPCKS12 - Gets decoded data block from PKCS12
func GetBlocksFromPCKS12(certString string) (blocks []*pem.Block, err error) {
	decodedData, _ := base64.StdEncoding.DecodeString(certString)

	// Decoding PKCS12 blob
	privateKey, firstCert, certList, err := gpkcs12.DecodeChain(decodedData, "")
	if err != nil {
		return nil, err
	}

	// Extracting private key and creating private key pem.block
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	blocks = append(blocks, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})

	// Checking if first certificate is non-CA cert and converting to pem.block if true
	if !firstCert.IsCA {
		blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: firstCert.Raw})
		return blocks, nil
	}

	// Iterating over the caCerts list since we cannot assume that cert returned by pkcs12.DecodeChain
	// is the leaf certificate
	for _, cert := range certList {
		if !cert.IsCA {
			blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			break
		}
	}

	return blocks, nil
}

// WritePEMfile - Writes the output PEM file
func WritePEMfile(filename string, certificate, privateKey interface{}) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("unable to create pem file %v: %v", filename, err)
	}
	defer f.Close()

	err = pem.Encode(f, &pem.Block{Type: certificate.(*pem.Block).Type, Bytes: certificate.(*pem.Block).Bytes})
	if err != nil {
		return fmt.Errorf("an error ocurred writting certificate to pem file %v", err)
	}

	err = pem.Encode(f, &pem.Block{Type: privateKey.(*pem.Block).Type, Bytes: privateKey.(*pem.Block).Bytes})
	if err != nil {
		return fmt.Errorf("an error ocurred writting private key to pem file %v", err)
	}

	return nil
}

// GetCertificateFromPEMBLocks - Gets a certificate from PEM Blocks
func GetCertificateFromPEMBLocks(blocks interface{}) (certificate interface{}, err error) {
	for _, b := range blocks.([]*pem.Block) {
		if strings.Contains(b.Type, "CERTIFICATE") {
			x509cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %v", err)
			}
			if !x509cert.IsCA {
				certificate = b
				break
			}
		}
	}
	if certificate == nil {
		return nil, fmt.Errorf("unable to find non-CA certificate")
	}

	return certificate, nil
}

// GetPrivateKeyFromPEMBlocks - Gets private key from PEM Blocks
func GetPrivateKeyFromPEMBlocks(blocks interface{}) (privateKey interface{}, err error) {
	for _, b := range blocks.([]*pem.Block) {
		if strings.Contains(b.Type, "PRIVATE KEY") {
			privateKey = b
			break
		}
	}
	if privateKey == nil {
		return nil, fmt.Errorf("unable to find private key")
	}

	return privateKey, nil
}

//
//!SECTION - SDK dependent functions
//

//!SECTION - Internal functions

func getAKVCertificateBundle(cntx context.Context, client *azcertificates.Client, certURL url.URL) (azcertificates.CertificateBundle, error) {
	cert, err := client.GetCertificate(cntx, certURL.Path, "", nil)
	if err != nil {
		return azcertificates.CertificateBundle{}, err
	}

	return cert.CertificateBundle, nil
}

//!SECTION - Public functions

// GetAKVCertificate - Gets a certificate from AKV
func GetAKVCertificate(cntx context.Context, client *azsecrets.Client, certURL url.URL) (azsecrets.SecretBundle, error) {
	certSecret, err := client.GetSecret(cntx, certURL.Path, "", nil)
	if err != nil {
		return azsecrets.SecretBundle{}, err
	}
	return certSecret.SecretBundle, nil
}

// GetAKVCertThumbprint - Gets thumbprint from bundle
func GetAKVCertThumbprint(cntx context.Context, client *azcertificates.Client, certURL url.URL) (thumbprint string, err error) {
	certBundle, err := getAKVCertificateBundle(cntx, client, certURL)
	if err != nil {
		return "", fmt.Errorf("unable to get certificate bundle: %v", err)
	}

	return string(certBundle.X509Thumbprint), nil
}
