package socket

func ipv4DestinationAddress(packet []byte) []byte {
	return packet[16:20]
}
