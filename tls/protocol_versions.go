package tls

type ProtocolVersion struct {
	ID   uint16
	Name string
}

var ProtocolVersions = []ProtocolVersion{
	{ID: VersionSSL30, Name: "VersionSSL30"},
	{ID: VersionTLS10, Name: "VersionTLS10"},
	{ID: VersionTLS11, Name: "VersionTLS11"},
	{ID: VersionTLS12, Name: "VersionTLS12"},
}
