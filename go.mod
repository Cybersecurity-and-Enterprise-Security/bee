module gitlab.cyber-threat-intelligence.com/software/alvarium/bee

go 1.19

require (
	github.com/deepmap/oapi-codegen v1.12.4
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.3.0
	github.com/sirupsen/logrus v1.9.0
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20220608195807-1a118fe229fc
	github.com/vishvananda/netns v0.0.4
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230215201556-9c5414ab4bde
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.1 // indirect
	github.com/mdlayher/netlink v1.7.1 // indirect
	github.com/mdlayher/socket v0.4.0 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20230317141804-1417a47c8fa8 // indirect
)

// Until all the functionality from https://github.com/konradh/gopacket are in a release.
replace github.com/google/gopacket => github.com/konradh/gopacket v0.0.0-20230315132540-4626c973decb
