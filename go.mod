module github.com/Cybersecurity-and-Enterprise-Security/bee

go 1.22

require (
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.6.0
	github.com/oapi-codegen/oapi-codegen/v2 v2.3.0
	github.com/oapi-codegen/runtime v1.1.1
	github.com/prometheus/procfs v0.15.1
	github.com/sirupsen/logrus v1.9.3
	github.com/vishvananda/netlink v1.2.1-beta.2.0.20240713210050-d13535d71ed3
	github.com/vishvananda/netns v0.0.4
	golang.org/x/sys v0.22.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/net v0.27.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173 // indirect
)

// Until all the functionality from https://github.com/konradh/gopacket are in a release.
replace github.com/google/gopacket => github.com/konradh/gopacket v0.0.0-20230315132540-4626c973decb
