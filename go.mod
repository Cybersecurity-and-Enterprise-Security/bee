module github.com/Cybersecurity-and-Enterprise-Security/bee

go 1.19

require (
	github.com/deepmap/oapi-codegen v1.12.4
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.3.0
	github.com/prometheus/procfs v0.10.1
	github.com/sirupsen/logrus v1.9.2
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20220608195807-1a118fe229fc
	github.com/vishvananda/netns v0.0.4
	golang.org/x/sys v0.8.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sync v0.2.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20230325221338-052af4a8072b // indirect
)

// Until all the functionality from https://github.com/konradh/gopacket are in a release.
replace github.com/google/gopacket => github.com/konradh/gopacket v0.0.0-20230315132540-4626c973decb
