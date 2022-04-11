module github.com/trussworks/setup-new-aws-user

go 1.16

require (
	github.com/99designs/aws-vault v1.0.1-0.20200507051055-ae369037cc75
	github.com/99designs/keyring v1.1.6
	github.com/aws/aws-sdk-go v1.43.36
	github.com/danieljoos/wincred v1.1.0 // indirect
	github.com/go-playground/universal-translator v0.17.0 // indirect
	github.com/keybase/go-keychain v0.0.0-20200502122510-cda31fe0c86d // indirect
	github.com/leodido/go-urn v1.2.0 // indirect
	github.com/pkg/browser v0.0.0-20180916011732-0a3d74bf9ce4
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	github.com/spf13/cobra v1.4.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.10.1
	github.com/stretchr/testify v1.7.1
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
	gopkg.in/go-playground/validator.v9 v9.31.0
	gopkg.in/ini.v1 v1.66.4
)

// Update to ignore compiler warnings on macOS catalina
// https://github.com/keybase/go-keychain/pull/55
// https://github.com/99designs/aws-vault/pull/427
replace github.com/keybase/go-keychain => github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4
