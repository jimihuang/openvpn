package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	tlsCertificateFile = "server.crt"
	tlsPrivateKeyFile  = "server.key"
)

type tlsCertificateStatus struct {
	Configured bool
	Subject    string
	NotAfter   time.Time
}

func tlsMaterialPaths() (string, string) {
	dir := filepath.Join(ovData, "tls")
	return filepath.Join(dir, tlsCertificateFile), filepath.Join(dir, tlsPrivateKeyFile)
}

func validateTLSMaterial(certPEM, keyPEM []byte) (*x509.Certificate, error) {
	if len(strings.TrimSpace(string(certPEM))) == 0 || len(strings.TrimSpace(string(keyPEM))) == 0 {
		return nil, fmt.Errorf("HTTPS 证书链和私钥均不能为空")
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("HTTPS 证书或私钥无效，或二者不匹配: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("HTTPS 证书链中没有证书")
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("解析 HTTPS 证书失败: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("HTTPS 证书尚未生效，生效时间: %s", leaf.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("HTTPS 证书已过期，过期时间: %s", leaf.NotAfter.Format(time.RFC3339))
	}

	return leaf, nil
}

func writeTLSMaterial(certPEM, keyPEM []byte) error {
	if _, err := validateTLSMaterial(certPEM, keyPEM); err != nil {
		return err
	}

	certPath, keyPath := tlsMaterialPaths()
	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("创建 HTTPS 证书目录失败: %w", err)
	}

	certTmp, err := os.CreateTemp(dir, ".server.crt-")
	if err != nil {
		return fmt.Errorf("创建 HTTPS 证书临时文件失败: %w", err)
	}
	certTmpPath := certTmp.Name()
	defer os.Remove(certTmpPath)
	if err := certTmp.Chmod(0644); err != nil {
		certTmp.Close()
		return err
	}
	if _, err := certTmp.Write(certPEM); err != nil {
		certTmp.Close()
		return fmt.Errorf("写入 HTTPS 证书失败: %w", err)
	}
	if err := certTmp.Sync(); err != nil {
		certTmp.Close()
		return err
	}
	if err := certTmp.Close(); err != nil {
		return err
	}

	keyTmp, err := os.CreateTemp(dir, ".server.key-")
	if err != nil {
		return fmt.Errorf("创建 HTTPS 私钥临时文件失败: %w", err)
	}
	keyTmpPath := keyTmp.Name()
	defer os.Remove(keyTmpPath)
	if err := keyTmp.Chmod(0600); err != nil {
		keyTmp.Close()
		return err
	}
	if _, err := keyTmp.Write(keyPEM); err != nil {
		keyTmp.Close()
		return fmt.Errorf("写入 HTTPS 私钥失败: %w", err)
	}
	if err := keyTmp.Sync(); err != nil {
		keyTmp.Close()
		return err
	}
	if err := keyTmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(keyTmpPath, keyPath); err != nil {
		return fmt.Errorf("替换 HTTPS 私钥失败: %w", err)
	}
	if err := os.Rename(certTmpPath, certPath); err != nil {
		return fmt.Errorf("替换 HTTPS 证书失败: %w", err)
	}
	return nil
}

func getTLSCertificateStatus() tlsCertificateStatus {
	certPath, keyPath := tlsMaterialPaths()
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		return tlsCertificateStatus{}
	}
	leaf, err := validateTLSMaterial(certPEM, keyPEM)
	if err != nil {
		return tlsCertificateStatus{}
	}
	return tlsCertificateStatus{
		Configured: true,
		Subject:    leaf.Subject.String(),
		NotAfter:   leaf.NotAfter,
	}
}
