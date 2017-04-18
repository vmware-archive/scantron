package tls

func mutualCipherSuite(have []uint16, want uint16) bool {
	for _, id := range have {
		if id == want {
			return true
		}
	}
	return false
}
