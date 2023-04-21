module keyvaultcertdownloader

go 1.20

require (
	internal/corehelper v1.0.0
	internal/utils v1.0.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.5.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.2.2 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.3.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates v0.10.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets v0.13.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v0.8.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.0.0 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20210911075715-681adbf594b8 // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	internal/models v0.0.0-00010101000000-000000000000 // indirect
	software.sslmate.com/src/go-pkcs12 v0.2.0 // indirect
)

replace (
	internal/corehelper => ./internal/corehelper
	internal/models => ./internal/models
	internal/utils => ./internal/utils
)
