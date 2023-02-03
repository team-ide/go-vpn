package vpn_tcp

var BufferSize = 64 * 1024

type Config struct {
	Address                string // 服务 监听地址
	CertificateFilePath    string // 证书
	CertificateKeyFilePath string // 证书Key
	Compress               bool   // 压缩
}
