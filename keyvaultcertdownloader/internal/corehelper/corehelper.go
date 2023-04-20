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
	"internal/utils"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	gpkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	ERR_AUTHORIZER                                  = 2
	ERR_INVALID_ARGUMENT                            = 3
	ERR_INVALID_URL                                 = 4
	ERR_GET_AKV_CERT_SECRET                         = 5
	ERR_GET_PEM_PRIVATE_KEY                         = 6
	ERR_GET_PEM_CERTIFICATE                         = 7
	ERR_CREATE_PEM_FILE                             = 8
	ERR_X509_THUMBPRINT                             = 9
	ERR_OUTPUTFOLDER_NOT_FOUND                      = 10
	ERR_INVALID_AZURE_ENVIRONMENT                   = 11
	ERR_CREDENTIALS                                 = 12
	ERR_INVALID_CREDENTIAL_ARGS                     = 13
	ERR_CLOUD_CONFIG_FILE_ONLY_FOR_CUSTOM_CLOUD     = 180
	ERR_CLOUD_CONFIG_FILE_NOT_FOUND                 = 181
	ERR_CLOUD_CONFIG_FILE_REQUIRED_FOR_CUSTOM_CLOUD = 182
)

var (
	Stdout = log.New(os.Stdout, "", log.LstdFlags)
	Stderr = log.New(os.Stderr, "", log.LstdFlags)
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
// Azcore SDK related functions
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

func GetTokenCredentials(managedIdentityId string, useSystemManagedIdentity bool) (azcore.TokenCredential, error) {
	var cred azcore.TokenCredential
	var err error

	tokenFilePath := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	if tokenFilePath == "" {
		// Not running within a container with azwi webhook configured
		utils.ConsoleOutput("Obtaining credentials", Stdout)

		if managedIdentityId == "" && !useSystemManagedIdentity {
			cred, err = azidentity.NewDefaultAzureCredential(nil)
		} else if useSystemManagedIdentity {
			cred, err = azidentity.NewManagedIdentityCredential(nil)
		} else if managedIdentityId != "" {
			opts := azidentity.ManagedIdentityCredentialOptions{}

			if strings.Contains(managedIdentityId, "/") {
				opts = azidentity.ManagedIdentityCredentialOptions{
					ID: azidentity.ResourceID(managedIdentityId),
				}
			} else {
				opts = azidentity.ManagedIdentityCredentialOptions{
					ID: azidentity.ClientID(managedIdentityId),
				}
			}

			cred, err = azidentity.NewManagedIdentityCredential(&opts)
		} else {
			return nil, fmt.Errorf("authentication method not supported")
		}

		if err != nil {
			return nil, fmt.Errorf("an error ocurred while obtaining : %v", err)
		}
	} else {

		// NOTE: following block is based on azure workload identity sample:
		//       https://github.dev/Azure/azure-workload-identity/blob/main/examples/msal-net/akvdotnet/TokenCredential.cs
		//

		// Azure AD Workload Identity webhook will inject the following env vars
		// 	AZURE_CLIENT_ID with the clientID set in the service account annotation
		// 	AZURE_TENANT_ID with the tenantID set in the service account annotation. If not defined, then
		// 	the tenantID provided via azure-wi-webhook-config for the webhook will be used.
		// 	AZURE_FEDERATED_TOKEN_FILE is the service account token path
		// 	AZURE_AUTHORITY_HOST is the AAD authority hostname
		clientID := os.Getenv("AZURE_CLIENT_ID")
		tenantID := os.Getenv("AZURE_TENANT_ID")
		tokenFilePath := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
		authorityHost := os.Getenv("AZURE_AUTHORITY_HOST")

		if clientID == "" {
			return nil, fmt.Errorf("an error ocurred: AZURE_CLIENT_ID environment variable is not set")
		}
		if tenantID == "" {
			return nil, fmt.Errorf("an error ocurred: AZURE_TENANT_ID environment variable is not set")
		}
		if authorityHost == "" {
			return nil, fmt.Errorf("an error ocurred: AZURE_AUTHORITY_HOST environment variable is not set")
		}

		cred, err = NewClientAssertionCredential(tenantID, clientID, authorityHost, tokenFilePath, nil)
		if err != nil {
			utils.ConsoleOutput(fmt.Sprintf("<error> failed to create client assertion credential: %v\n", err), Stderr)
			return nil, fmt.Errorf("an error ocurred: AZURE_CLIENT_ID environment variable is not set")
		}
	}

	return cred, nil
}

func getCloudConfiguration(environment, cloudConfigFile string) (cloud.Configuration, error) {
	cloudConfig := cloud.Configuration{}

	if environment == "AZUREUSGOVERNMENTCLOUD" {
		cloudConfig = cloud.AzureGovernment
	} else if environment == "AZURECHINACLOUD" {
		cloudConfig = cloud.AzureChina
	} else if environment == "CUSTOMCLOUD" {

		// This is the mapping between values expected on cloud.Configuration
		// and the output of az cloud show -n AzureCloud -o json
		//
		// ActiveDirectoryAuthorityHost = endpoints.activeDirectory (e.g."https://login.microsoftonline.us")
		// Endpoint = endpoints.resourceManager (e.g. "https://management.usgovcloudapi.net")
		// Audience = endpoints.activeDirectoryResourceId (e.g. "https://management.core.usgovcloudapi.net")

		if cloudConfigFile != "" {
			cloudInfo, err := utils.ImportCloudConfigJson(cloudConfigFile)
			if err != nil {
				return cloud.Configuration{}, fmt.Errorf("an error ocurred while importing cloud config information from json file: %v", err)
			}

			cloudConfig = cloud.Configuration{
				ActiveDirectoryAuthorityHost: cloudInfo.Endpoints.ActiveDirectoryAuthorityHost,
				Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
					cloud.ResourceManager: {
						Endpoint: cloudInfo.Endpoints.ResourceManagerEndpoint,
						Audience: cloudInfo.Endpoints.ResourceManagerEndpoint,
					},
				},
			}
		}

	} else {
		cloudConfig = cloud.AzurePublic
	}

	return cloudConfig, nil
}

// GetCertsClient returns a certs client
func GetCertsClient(keyVaultUrl, environment, cloudConfigFile string, cred azcore.TokenCredential) (azcertificates.Client, error) {
	cloudConfig, err := getCloudConfiguration(environment, cloudConfigFile)
	if err != nil {
		return azcertificates.Client{}, fmt.Errorf("failed to create cloudConfig object: %v\n", err)
	}

	options := azcertificates.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud: cloudConfig,
		},
	}

	azcertsClient, err := azcertificates.NewClient(keyVaultUrl, cred, &options)
	if err != nil {
		return azcertificates.Client{}, fmt.Errorf("failed to create azcerts client: %v\n", err)
	}

	return *azcertsClient, nil
}

// GetSecretsClient returns an azsecrets.Client
func GetSecretsClient(keyVaultUrl, environment, cloudConfigFile string, cred azcore.TokenCredential) (azsecrets.Client, error) {

	cloudConfig, err := getCloudConfiguration(environment, cloudConfigFile)
	if err != nil {
		return azsecrets.Client{}, fmt.Errorf("failed to create cloudConfig object: %v\n", err)
	}

	options := azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Cloud: cloudConfig,
		},
	}

	azsecretsClient, err := azsecrets.NewClient(keyVaultUrl, cred, &options)
	if err != nil {
		return azsecrets.Client{}, fmt.Errorf("failed to create azsecrets client: %v\n", err)
	}

	return *azsecretsClient, nil
}

//
// Keyvault SDK related functions
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
