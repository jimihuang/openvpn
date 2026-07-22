package main

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gpkaes "github.com/gavintan/gopkg/aes"
	"github.com/glebarez/sqlite"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

func TestParseExpireDate(t *testing.T) {
	tests := []struct {
		value string
		hour  int
	}{
		{value: "2030-01-02", hour: 0},
		{value: "2030-01-02/15:04:05", hour: 15},
		{value: "2030-01-02 16:04:05", hour: 16},
		{value: "2030-01-02T17:04:05+08:00", hour: 17},
	}
	for _, test := range tests {
		parsed, err := parseExpireDate(test.value)
		if err != nil {
			t.Fatalf("parseExpireDate(%q): %v", test.value, err)
		}
		if parsed.Year() != 2030 || parsed.Month() != time.January || parsed.Day() != 2 || parsed.Hour() != test.hour {
			t.Fatalf("parseExpireDate(%q) returned %s", test.value, parsed)
		}
	}
	if _, err := parseExpireDate("not-a-date"); err == nil {
		t.Fatal("parseExpireDate accepted an invalid date")
	}
}

func TestUpdateProtocolManagesExplicitExitNotify(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(configPath, []byte("port 1194\nproto udp\nexplicit-exit-notify 1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := initVPNConfigForTest(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Update("openvpn.ovpn_proto", "tcp")
	cfg.Save()
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "explicit-exit-notify") {
		t.Fatalf("TCP config retained explicit-exit-notify: %s", content)
	}

	cfg.Update("openvpn.ovpn_proto", "udp")
	cfg.Save()
	content, err = os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "explicit-exit-notify 1") {
		t.Fatalf("UDP config did not add explicit-exit-notify: %s", content)
	}
}

func initVPNConfigForTest(configPath string) (*VPNConfig, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSuffix(string(content), "\n"), "\n")
	return &VPNConfig{ConfigPath: configPath, Lines: lines}, nil
}

func TestReplaceInlineBlock(t *testing.T) {
	original := []byte("client\n<ca>\nold\n</ca>\n<cert>\nclient-cert\n</cert>\n")
	updated, err := replaceInlineBlock(original, "ca", []byte("new-ca\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "<ca>\nnew-ca\n</ca>") {
		t.Fatalf("CA block was not replaced: %s", updated)
	}
	if !strings.Contains(string(updated), "<cert>\nclient-cert\n</cert>") {
		t.Fatalf("unrelated certificate block changed: %s", updated)
	}
}

func TestGenMfaIncludesQRCode(t *testing.T) {
	secret, uri, qrCode, err := GenMfa("regression-user")
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || !strings.HasPrefix(uri, "otpauth://") {
		t.Fatalf("invalid MFA setup data: secret=%q uri=%q", secret, uri)
	}
	if !strings.HasPrefix(qrCode, "data:image/png;base64,") {
		t.Fatalf("invalid MFA QR code: %q", qrCode)
	}
}

func TestPasswordPolicySwitch(t *testing.T) {
	original := viper.Get("system.base.enforce_password_policy")
	t.Cleanup(func() { viper.Set("system.base.enforce_password_policy", original) })

	viper.Set("system.base.enforce_password_policy", true)
	if !isValidPassword("Vpn@2026Secure") {
		t.Fatal("strong password was rejected while policy was enabled")
	}
	if isValidPassword("123456") {
		t.Fatal("weak password was accepted while policy was enabled")
	}

	viper.Set("system.base.enforce_password_policy", false)
	if !isValidPassword("123456") {
		t.Fatal("six-character password was rejected while policy was disabled")
	}
	if isValidPassword("12345") {
		t.Fatal("five-character password was accepted while policy was disabled")
	}
}

func TestTLSMaterialValidationAndStorage(t *testing.T) {
	certPEM, keyPEM := makeTestTLSMaterial(t, "vpn.example.com", time.Now().Add(24*time.Hour))
	if _, err := validateTLSMaterial(certPEM, keyPEM); err != nil {
		t.Fatalf("valid TLS material was rejected: %v", err)
	}

	_, otherKey := makeTestTLSMaterial(t, "vpn.example.com", time.Now().Add(24*time.Hour))
	if _, err := validateTLSMaterial(certPEM, otherKey); err == nil {
		t.Fatal("mismatched TLS certificate and key were accepted")
	}

	originalData := ovData
	t.Cleanup(func() { ovData = originalData })
	ovData = t.TempDir()
	if err := writeTLSMaterial(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	status := getTLSCertificateStatus()
	if !status.Configured || !strings.Contains(status.Subject, "vpn.example.com") {
		t.Fatalf("unexpected TLS status: %#v", status)
	}
	_, keyPath := tlsMaterialPaths()
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("private key permissions are %o, want 600", info.Mode().Perm())
	}
}

func TestTLSMaterialRejectsExpiredCertificate(t *testing.T) {
	certPEM, keyPEM := makeTestTLSMaterial(t, "expired.example.com", time.Now().Add(-time.Hour))
	if _, err := validateTLSMaterial(certPEM, keyPEM); err == nil {
		t.Fatal("expired TLS certificate was accepted")
	}
}

func makeTestTLSMaterial(t *testing.T, commonName string, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestListClientConfigsExcludesBackupsAndSelectsDefault(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"staff.ovpn", "ops.ovpn", "staff.ovpn.bak-20260720075127", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("client\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	original := viper.Get("system.base.default_ovpn_config")
	t.Cleanup(func() { viper.Set("system.base.default_ovpn_config", original) })
	viper.Set("system.base.default_ovpn_config", "ops.ovpn")

	clients, err := listClientConfigs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 2 {
		t.Fatalf("expected 2 .ovpn clients, got %d: %#v", len(clients), clients)
	}
	for _, client := range clients {
		if strings.Contains(client.FullName, ".bak-") {
			t.Fatalf("backup leaked into client list: %s", client.FullName)
		}
		if client.FullName == "ops.ovpn" && !client.IsDefault {
			t.Fatal("configured default client was not marked as default")
		}
	}
}

func TestUserPasswordIsEncryptedExactlyOnceOnCreateAndUpdate(t *testing.T) {
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := testDB.AutoMigrate(&User{}); err != nil {
		t.Fatal(err)
	}

	originalDB, originalSecret, originalAdmin := db, secretKey, adminUsername
	originalPolicy := viper.Get("system.base.enforce_password_policy")
	t.Cleanup(func() {
		db, secretKey, adminUsername = originalDB, originalSecret, originalAdmin
		viper.Set("system.base.enforce_password_policy", originalPolicy)
	})
	db = testDB
	secretKey = "password-regression-test-key"
	adminUsername = "admin"
	viper.Set("system.base.enforce_password_policy", false)

	enabled := true
	user := User{Username: "password-regression", Password: "a<b&c1", IsEnable: &enabled}
	if err := user.Create(); err != nil {
		t.Fatal(err)
	}
	assertStoredPasswordEncryptedOnce(t, testDB, user.ID, "a<b&c1")

	user.Password = "new<2x"
	if err := user.Update(); err != nil {
		t.Fatal(err)
	}
	assertStoredPasswordEncryptedOnce(t, testDB, user.ID, "new<2x")

	loaded := User{Username: user.Username}.Info()
	if loaded.Password != "new<2x" {
		t.Fatal("loaded password did not match the exact updated value")
	}
}

func assertStoredPasswordEncryptedOnce(t *testing.T, testDB *gorm.DB, id uint, expected string) {
	t.Helper()
	var stored string
	if err := testDB.Raw(`SELECT password FROM user WHERE id = ?`, id).Scan(&stored).Error; err != nil {
		t.Fatal(err)
	}
	decrypted, err := gpkaes.AesDecrypt(stored, secretKey)
	if err != nil {
		t.Fatalf("stored password was not decryptable: %v", err)
	}
	if decrypted != expected {
		t.Fatal("one decryption did not yield the original password")
	}
	if _, err := gpkaes.AesDecrypt(decrypted, secretKey); err == nil {
		t.Fatal("password remained decryptable after one layer was removed")
	}
}

func TestLegacyDoubleEncryptedPasswordIsReadable(t *testing.T) {
	originalSecret := secretKey
	t.Cleanup(func() { secretKey = originalSecret })
	secretKey = "legacy-password-test-key"

	first, err := gpkaes.AesEncrypt("legacy1", secretKey)
	if err != nil {
		t.Fatal(err)
	}
	second, err := gpkaes.AesEncrypt(first, secretKey)
	if err != nil {
		t.Fatal(err)
	}
	user := User{Password: second}
	if err := user.AfterFind(nil); err != nil {
		t.Fatal(err)
	}
	if user.Password != "legacy1" {
		t.Fatal("legacy double-encrypted password was not fully unwrapped")
	}
}
