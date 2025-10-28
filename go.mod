module github.com/synacktiv/octoscan

go 1.23.0

toolchain go1.23.2

// well I have a PR that is not merged: https://github.com/rhysd/actionlint/pull/332
// and I can"t use go install with replace directive: https://github.com/golang/go/issues/44840
// do you have any idea ?
replace github.com/rhysd/actionlint => github.com/hugo-syn/actionlint v0.0.0-20240620182217-ad2709b475db

require (
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/fatih/color v1.18.0
	github.com/google/go-github v17.0.0+incompatible
	github.com/google/osv-scanner v1.9.2
	github.com/hashicorp/go-version v1.7.0
	github.com/rhysd/actionlint v1.7.3
	golang.org/x/oauth2 v0.27.0
)

require (
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/package-url/packageurl-go v0.1.3 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
