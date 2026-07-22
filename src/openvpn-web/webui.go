package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// New Vue SPA assets are copied from web/dist by scripts/build_web.sh.
//
//go:embed all:webdist
var webUIFS embed.FS

var validCertificateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type fileUpdate struct {
	path string
	data []byte
	mode os.FileMode
}

type originalFile struct {
	exists bool
	data   []byte
	mode   os.FileMode
}

func serveSPAIndex(c *gin.Context) {
	data, err := webUIFS.ReadFile("webdist/index.html")
	if err != nil {
		c.String(http.StatusInternalServerError, "web ui not built")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

// registerWebUI registers public assets and SPA route fallback.
func registerWebUI(r *gin.Engine) {
	assets, err := fs.Sub(webUIFS, "webdist/assets")
	if err == nil {
		r.StaticFS("/assets", http.FS(assets))
	}

	r.NoRoute(func(c *gin.Context) {
		if c.Request.Method == http.MethodGet {
			serveSPAIndex(c)
			return
		}
		c.Status(http.StatusNotFound)
	})
}

func parseCertificatePEM(content []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("内容不是有效的 PEM CERTIFICATE")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("证书内容只能包含一个 PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("无法解析证书: %w", err)
	}
	return cert, nil
}

func parseCRLPEM(content []byte) (*x509.RevocationList, error) {
	block, rest := pem.Decode(content)
	if block == nil || block.Type != "X509 CRL" {
		return nil, fmt.Errorf("内容不是有效的 PEM X509 CRL")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("CRL 内容只能包含一个 PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("无法解析 CRL: %w", err)
	}
	return crl, nil
}

func parsePrivateKeyPEM(content []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("内容不是有效的 PEM 私钥")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("私钥内容只能包含一个 PEM block")
	}
	if x509.IsEncryptedPEMBlock(block) || block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("不支持需要密码的加密私钥")
	}

	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("不支持的私钥类型: %s", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("无法解析私钥: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("私钥类型不支持签名")
	}
	return signer, nil
}

func validateCertificateTime(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("证书尚未生效: %s", cert.NotBefore.Local().Format("2006-01-02 15:04:05"))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("证书已过期: %s", cert.NotAfter.Local().Format("2006-01-02 15:04:05"))
	}
	return nil
}

func validateCertificateAndKey(cert *x509.Certificate, key crypto.Signer) error {
	certPublic, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(certPublic, keyPublic) {
		return fmt.Errorf("证书与私钥不匹配")
	}
	return nil
}

func hasExtendedKeyUsage(cert *x509.Certificate, usage x509.ExtKeyUsage) bool {
	for _, item := range cert.ExtKeyUsage {
		if item == usage || item == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func readCurrentCA() (*x509.Certificate, error) {
	data, err := os.ReadFile(filepath.Join(ovData, "pki", "ca.crt"))
	if err != nil {
		return nil, err
	}
	return parseCertificatePEM(data)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// applyFileUpdates creates recoverable backups, then atomically replaces each target.
// If any replacement fails, already replaced targets are restored.
func applyFileUpdates(updates []fileUpdate) error {
	if len(updates) == 0 {
		return nil
	}

	originals := make(map[string]originalFile, len(updates))
	timestamp := time.Now().Format("20060102150405.000000000")
	for _, update := range updates {
		if _, exists := originals[update.path]; exists {
			return fmt.Errorf("重复的更新目标: %s", update.path)
		}
		info, err := os.Stat(update.path)
		if err != nil {
			if os.IsNotExist(err) {
				originals[update.path] = originalFile{}
				continue
			}
			return err
		}
		data, err := os.ReadFile(update.path)
		if err != nil {
			return err
		}
		originals[update.path] = originalFile{exists: true, data: data, mode: info.Mode().Perm()}
		if err := writeFileAtomic(update.path+".bak-"+timestamp, data, info.Mode().Perm()); err != nil {
			return fmt.Errorf("备份 %s 失败: %w", update.path, err)
		}
	}

	written := make([]string, 0, len(updates))
	for _, update := range updates {
		if err := writeFileAtomic(update.path, update.data, update.mode); err != nil {
			for i := len(written) - 1; i >= 0; i-- {
				path := written[i]
				original := originals[path]
				if original.exists {
					if restoreErr := writeFileAtomic(path, original.data, original.mode); restoreErr != nil {
						logger.Error(context.Background(), "restore %s: %v", path, restoreErr)
					}
				} else if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
					logger.Error(context.Background(), "remove %s: %v", path, removeErr)
				}
			}
			return fmt.Errorf("替换 %s 失败: %w", update.path, err)
		}
		written = append(written, update.path)
	}
	return nil
}

func replaceInlineBlock(content []byte, tag string, replacement []byte) ([]byte, error) {
	startMarker := []byte("<" + tag + ">")
	endMarker := []byte("</" + tag + ">")
	start := bytes.Index(content, startMarker)
	if start < 0 {
		return nil, fmt.Errorf("配置中缺少 <%s> block", tag)
	}
	endRelative := bytes.Index(content[start+len(startMarker):], endMarker)
	if endRelative < 0 {
		return nil, fmt.Errorf("配置中缺少 </%s> block", tag)
	}
	end := start + len(startMarker) + endRelative

	var out bytes.Buffer
	out.Write(content[:start+len(startMarker)])
	out.WriteByte('\n')
	out.Write(bytes.TrimSpace(replacement))
	out.WriteByte('\n')
	out.Write(content[end:])
	return out.Bytes(), nil
}

func inlineUpdatesForAllClients(tag string, replacement []byte) ([]fileUpdate, error) {
	clientsDir := filepath.Join(ovData, "clients")
	entries, err := os.ReadDir(clientsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	updates := make([]fileUpdate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".ovpn") {
			continue
		}
		path := filepath.Join(clientsDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		updated, err := replaceInlineBlock(content, tag, replacement)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		updates = append(updates, fileUpdate{path: path, data: updated, mode: 0644})
	}
	return updates, nil
}

func syncInlineCAFromPKI() error {
	caPath := filepath.Join(ovData, "pki", "ca.crt")
	caData, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	updates, err := inlineUpdatesForAllClients("ca", caData)
	if err != nil {
		return err
	}
	return applyFileUpdates(updates)
}

func syncInlinePKIFromDisk() error {
	caData, err := os.ReadFile(filepath.Join(ovData, "pki", "ca.crt"))
	if err != nil {
		return err
	}
	caBlock, _ := pem.Decode(caData)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("当前 CA 证书无法解析")
	}
	caPEM := pem.EncodeToMemory(caBlock)

	clientsDir := filepath.Join(ovData, "clients")
	entries, err := os.ReadDir(clientsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	updates := make([]fileUpdate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".ovpn") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".ovpn")
		certData, err := os.ReadFile(filepath.Join(ovData, "pki", "issued", name+".crt"))
		if err != nil {
			return fmt.Errorf("读取客户端证书 %s 失败: %w", name, err)
		}
		certBlock, _ := pem.Decode(certData)
		if certBlock == nil || certBlock.Type != "CERTIFICATE" {
			return fmt.Errorf("客户端证书 %s 无法解析", name)
		}

		path := filepath.Join(clientsDir, entry.Name())
		ovpnContent, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		ovpnContent, err = replaceInlineBlock(ovpnContent, "ca", caPEM)
		if err == nil {
			ovpnContent, err = replaceInlineBlock(ovpnContent, "cert", pem.EncodeToMemory(certBlock))
		}
		if err != nil {
			return fmt.Errorf("%s: %w", entry.Name(), err)
		}
		updates = append(updates, fileUpdate{path: path, data: ovpnContent, mode: 0644})
	}
	return applyFileUpdates(updates)
}

func getCertificateMaterial(c *gin.Context) {
	materialType := c.Query("type")
	name := strings.TrimSpace(c.Query("name"))
	pkiDir := filepath.Join(ovData, "pki")
	var path string

	switch materialType {
	case "ca":
		path = filepath.Join(pkiDir, "ca.crt")
	case "crl":
		path = filepath.Join(pkiDir, "crl.pem")
	case "server":
		path = filepath.Join(pkiDir, "issued", viper.GetString("system.base.server_name")+".crt")
	case "client":
		if !validCertificateName.MatchString(name) {
			c.JSON(http.StatusBadRequest, gin.H{"message": "客户端名称格式不正确"})
			return
		}
		path = filepath.Join(pkiDir, "issued", name+".crt")
	default:
		c.JSON(http.StatusBadRequest, gin.H{"message": "不支持的证书类型"})
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"content": string(data)})
}

func replaceCertificateMaterial(c *gin.Context) {
	materialType := c.PostForm("type")
	name := strings.TrimSpace(c.PostForm("name"))
	content := []byte(strings.TrimSpace(c.PostForm("content")) + "\n")
	privateKeyContent := strings.TrimSpace(c.PostForm("privateKey"))
	pkiDir := filepath.Join(ovData, "pki")
	updates := make([]fileUpdate, 0)

	if len(bytes.TrimSpace(content)) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"message": "PEM 内容不能为空"})
		return
	}

	switch materialType {
	case "ca":
		cert, err := parseCertificatePEM(content)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"message": "证书不是可用于签发证书的 CA"})
			return
		}
		if err := validateCertificateTime(cert); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "CA 证书不是有效的自签名根证书: " + err.Error()})
			return
		}
		updates = append(updates, fileUpdate{path: filepath.Join(pkiDir, "ca.crt"), data: content, mode: 0644})
		inlineUpdates, err := inlineUpdatesForAllClients("ca", content)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		updates = append(updates, inlineUpdates...)

	case "crl":
		crl, err := parseCRLPEM(content)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		ca, err := readCurrentCA()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		if err := crl.CheckSignatureFrom(ca); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "CRL 不是由当前 CA 签发: " + err.Error()})
			return
		}
		if !crl.NextUpdate.IsZero() && time.Now().After(crl.NextUpdate) {
			c.JSON(http.StatusBadRequest, gin.H{"message": "CRL 已过期"})
			return
		}
		updates = append(updates, fileUpdate{path: filepath.Join(pkiDir, "crl.pem"), data: content, mode: 0644})

	case "server", "client":
		cert, err := parseCertificatePEM(content)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		if err := validateCertificateTime(cert); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		ca, err := readCurrentCA()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		if err := cert.CheckSignatureFrom(ca); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "证书不是由当前 CA 签发: " + err.Error()})
			return
		}

		certificateName := viper.GetString("system.base.server_name")
		usage := x509.ExtKeyUsageServerAuth
		if materialType == "client" {
			if !validCertificateName.MatchString(name) {
				c.JSON(http.StatusBadRequest, gin.H{"message": "客户端名称格式不正确"})
				return
			}
			certificateName = name
			usage = x509.ExtKeyUsageClientAuth
			if _, err := os.Stat(filepath.Join(ovData, "clients", name+".ovpn")); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "客户端配置不存在: " + name + ".ovpn"})
				return
			}
		}
		if cert.Subject.CommonName != certificateName {
			c.JSON(http.StatusBadRequest, gin.H{"message": fmt.Sprintf("证书 CN 必须为 %s", certificateName)})
			return
		}
		if !hasExtendedKeyUsage(cert, usage) {
			c.JSON(http.StatusBadRequest, gin.H{"message": "证书用途与所选类型不匹配"})
			return
		}

		keyPath := filepath.Join(pkiDir, "private", certificateName+".key")
		keyData := []byte(privateKeyContent)
		if privateKeyContent == "" {
			keyData, err = os.ReadFile(keyPath)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "未填写私钥且现有私钥不可用: " + err.Error()})
				return
			}
		} else {
			keyData = append(keyData, '\n')
		}
		key, err := parsePrivateKeyPEM(keyData)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}
		if err := validateCertificateAndKey(cert, key); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			return
		}

		certPath := filepath.Join(pkiDir, "issued", certificateName+".crt")
		updates = append(updates, fileUpdate{path: certPath, data: content, mode: 0644})
		if privateKeyContent != "" {
			updates = append(updates, fileUpdate{path: keyPath, data: keyData, mode: 0600})
		}
		if materialType == "client" {
			ovpnPath := filepath.Join(ovData, "clients", name+".ovpn")
			ovpnContent, err := os.ReadFile(ovpnPath)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			ovpnContent, err = replaceInlineBlock(ovpnContent, "cert", content)
			if err == nil {
				ovpnContent, err = replaceInlineBlock(ovpnContent, "key", keyData)
			}
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
				return
			}
			updates = append(updates, fileUpdate{path: ovpnPath, data: ovpnContent, mode: 0644})
		}

	default:
		c.JSON(http.StatusBadRequest, gin.H{"message": "不支持的证书类型"})
		return
	}

	if err := applyFileUpdates(updates); err != nil {
		logger.Error(context.Background(), err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "证书材料已验证并替换，原文件已备份；请重启 OpenVPN 使服务端变更生效"})
}
