module gitlab.cyber-threat-intelligence.com/software/alvarium/bee

go 1.19

require (
	github.com/deepmap/oapi-codegen v1.12.4
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.3.0
	github.com/sirupsen/logrus v1.9.0
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	golang.org/x/sys v0.2.0 // indirect
)

// Until all the functionality from https://github.com/konradh/gopacket are in a release.
replace github.com/google/gopacket => github.com/konradh/gopacket v0.0.0-20230315132540-4626c973decb
