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
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
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
//!SECTION - Azcore SDK related functions
// Source: https://github.com/Azure/azure-workload-identity/tree/main/examples
//

// clientAssertionCredential authenticates an application with assertions provided by a callback function.
type clientAssertionCredential struct {
	assertion, file string
	client          confidential.Client
	lastRead        time.Time
}

// clientAssertionCredentialOptions contains optional parameters for ClientAssertionCredential.
type clientAssertionCredentialOptions struct {
	azcore.ClientOptions
}

// NewClientAssertionCredential constructs a clientAssertionCredential. Pass nil for options to accept defaults.
func NewClientAssertionCredential(tenantID, clientID, authorityHost, file string, options *clientAssertionCredentialOptions) (*clientAssertionCredential, error) {
	c := &clientAssertionCredential{file: file}

	if options == nil {
		options = &clientAssertionCredentialOptions{}
	}

	cred := confidential.NewCredFromAssertionCallback(
		func(ctx context.Context, _ confidential.AssertionRequestOptions) (string, error) {
			return c.getAssertion(ctx)
		},
	)

	client, err := confidential.New(clientID, cred, confidential.WithAuthority(fmt.Sprintf("%s%s/oauth2/token", authorityHost, tenantID)))
	if err != nil {
		return nil, fmt.Errorf("failed to create confidential client: %w", err)
	}
	c.client = client

	return c, nil
}

// GetToken implements the TokenCredential interface
func (c *clientAssertionCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	// get the token from the confidential client
	token, err := c.client.AcquireTokenByCredential(ctx, opts.Scopes)
	if err != nil {
		return azcore.AccessToken{}, err
	}

	return azcore.AccessToken{
		Token:     token.AccessToken,
		ExpiresOn: token.ExpiresOn,
	}, nil
}

// getAssertion reads the assertion from the file and returns it
// if the file has not been read in the last 5 minutes
func (c *clientAssertionCredential) getAssertion(context.Context) (string, error) {
	if now := time.Now(); c.lastRead.Add(5 * time.Minute).Before(now) {
		content, err := os.ReadFile(c.file)
		if err != nil {
			return "", err
		}
		c.assertion = string(content)
		c.lastRead = now
	}
	return c.assertion, nil
}

//
//!SECTION - Keyvault SDK related functions
//

func getAKVCertificateBundle(cntx context.Context, client *azcertificates.Client, certURL url.URL) (azcertificates.CertificateBundle, error) {
	cert, err := client.GetCertificate(cntx, certURL.Path, "", nil)
	if err != nil {
		return azcertificates.CertificateBundle{}, err
	}

	return cert.CertificateBundle, nil
}

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
