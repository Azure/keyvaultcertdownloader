//module github.com/Azure/keyvaultcertdownloader/keyvaultcertdownloader
module keyvaultcertdownloader

go 1.18

require (
	github.com/Azure/azure-sdk-for-go v67.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.28
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.11
	software.sslmate.com/src/go-pkcs12 v0.2.0
)

require (
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.18 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.5 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/golang-jwt/jwt/v4 v4.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa // indirect
)


require (
	internal/utils v1.0.0
	internal/iam v1.0.0
	internal/models v1.0.0
)

replace (
	internal/utils => ./internal/utils
	internal/iam => ./internal/iam
	internal/models => ./internal/models
)