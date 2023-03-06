module keyvaultcertdownloader

go 1.20

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.4.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.2.1
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates v0.8.0
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets v0.11.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.1.2 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/internal v0.7.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v0.8.1 // indirect
	github.com/golang-jwt/jwt/v4 v4.4.2 // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20210115035449-ce105d075bb4 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
	golang.org/x/net v0.7.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	internal/models v1.0.0 // indirect
	software.sslmate.com/src/go-pkcs12 v0.2.0 // indirect
)

require (
	internal/corehelper v1.0.0
	internal/utils v1.0.0
)

replace (
	internal/corehelper => ./internal/corehelper
	internal/models => ./internal/models
	internal/utils => ./internal/utils
)
