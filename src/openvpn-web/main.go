package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gavintan/gopkg/aes"
	"github.com/gavintan/gopkg/tools"
	"github.com/gin-contrib/sessions"
	gormsessions "github.com/gin-contrib/sessions/gorm"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/patrickmn/go-cache"
	"github.com/robfig/cron/v3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	gLogger "gorm.io/gorm/logger"
)

type ClientData struct {
	ID             string  `json:"id"`
	Rip            string  `json:"rip"`
	Vip            string  `json:"vip"`
	Vip6           string  `json:"vip6"`
	RecvBytes      float64 `json:"recvBytes"`
	SendBytes      float64 `json:"sendBytes"`
	ConnDate       string  `json:"connDate"`
	OnlineTime     string  `json:"onlineTime"`
	Username       string  `json:"username"`
	CommonName     string  `json:"commonName"`
	IsNftBlacklist bool    `json:"isNftBlacklist"`
}

type ServerData struct {
	RunDate    string
	Status     string
	StatusDesc string
	Address    string
	Nclients   string
	BytesIn    string
	BytesOut   string
	Mode       string
	Version    string
}

type ClientConfigData struct {
	Name      string `json:"name"`
	FullName  string `json:"fullName"`
	File      string `json:"file"`
	Date      string `json:"date"`
	IsDefault bool   `json:"isDefault"`
}

type Params struct {
	Draw        int    `json:"draw" form:"draw"`
	Offset      int    `json:"offset" form:"offset"`
	Limit       int    `json:"limit" form:"limit"`
	OrderColumn string `json:"orderColumn" form:"orderColumn"`
	Order       string `json:"order" form:"order"`
	Search      string `json:"search" form:"search"`
	Qt          string `json:"qt" form:"qt"`
}

type CertData struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	ExpiresIn string `json:"expiresIn"`
	Status    string `json:"status"`
	SerialNo  string `json:"serialNo"`
}

type ovpn struct {
	address string
}

var (
	version = "1.0.0"
	//go:embed templates
	FS embed.FS

	cc     = cache.New(5*time.Minute, 10*time.Minute)
	db     *gorm.DB
	logger = gLogger.New(
		log.New(os.Stdout, "[OPENVPN-WEB] "+time.Now().Format("2006-01-02 15:04:05.000")+" MAIN ", 0),
		gLogger.Config{
			SlowThreshold:             time.Second,
			LogLevel:                  gLogger.Error,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		},
	)
	ovData = os.Getenv("OVPN_DATA")
	conf   config
)

func (ov *ovpn) sendCommand(command string) (string, error) {
	var data string
	var sb strings.Builder

	conn, err := net.DialTimeout("tcp", ov.address, time.Second*3)
	if err != nil {
		logger.Error(context.Background(), err.Error())
		return data, err
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Second * 3))
	conn.Write([]byte(fmt.Sprintf("%s\n", command)))

	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)

		re := regexp.MustCompile(">INFO(.)*\r\n")
		if str := re.ReplaceAllString(string(buf[:n]), ""); str != "" {
			sb.Write([]byte(str))
		}

		if err != nil || strings.HasSuffix(sb.String(), "\r\nEND\r\n") || strings.HasPrefix(sb.String(), "SUCCESS:") {
			break
		}
	}

	data = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(sb.String(), "\r\nEND\r\n"), "\r\n"), "SUCCESS: ")

	return data, nil
}

func (ov *ovpn) getClient() []ClientData {
	clients := make([]ClientData, 0)

	data, err := ov.sendCommand("status 3")
	if err != nil {
		return clients
	}

	for _, v := range strings.Split(data, "\r\n") {
		cdSlice := strings.Split(v, "\t")

		if cdSlice[0] == "CLIENT_LIST" {
			recv, _ := strconv.ParseFloat(cdSlice[5], 64)
			send, _ := strconv.ParseFloat(cdSlice[6], 64)
			connDate, _ := time.ParseInLocation("2006-01-02 15:04:05", cdSlice[7], time.Local)

			rip := cdSlice[2]
			if strings.Count(cdSlice[2], ":") == 1 {
				rip = cdSlice[2][:strings.IndexByte(cdSlice[2], ':')]
			}

			cd := ClientData{
				Rip:            rip,
				Vip:            cdSlice[3],
				Vip6:           cdSlice[4],
				RecvBytes:      recv,
				SendBytes:      send,
				ConnDate:       cdSlice[7],
				Username:       cdSlice[9],
				CommonName:     cdSlice[1],
				ID:             cdSlice[10],
				OnlineTime:     (time.Duration(time.Now().Unix()-connDate.Unix()) * time.Second).String(),
				IsNftBlacklist: getNftTableSetElement("blacklist", cdSlice[3]) || getNftTableSetElement("blacklist", cdSlice[4]),
			}

			clients = append(clients, cd)
		}
	}

	return clients

}

func (ov *ovpn) getServer() ServerData {
	var sd ServerData

	data, err := ov.sendCommand("state")
	if err != nil {
		return sd
	}

	sateSlice := strings.Split(data, ",")
	if len(sateSlice) >= 3 {
		runDate, _ := strconv.ParseInt(sateSlice[0], 10, 64)
		sd.RunDate = time.Unix(runDate, 0).Format("2006-01-02 15:04:05")
		sd.Status = sateSlice[1]
		sd.StatusDesc = sateSlice[2]
		sd.Address = sateSlice[3]
	}

	data, err = ov.sendCommand("load-stats")
	if err != nil {
		return sd
	}

	statsSlice := strings.Split(data, ",")
	for _, v := range statsSlice {
		statsKeySlice := strings.Split(v, "=")

		switch statsKeySlice[0] {
		case "nclients":
			sd.Nclients = statsKeySlice[1]
		case "bytesin":
			in, _ := strconv.ParseFloat(statsKeySlice[1], 64)
			sd.BytesIn = tools.FormatBytes(in)
		case "bytesout":
			out, _ := strconv.ParseFloat(statsKeySlice[1], 64)
			sd.BytesOut = tools.FormatBytes(out)
		}
	}

	data, err = ov.sendCommand("version")
	if err != nil {
		return sd
	}

	for _, v := range strings.Split(data, "\n") {
		if strings.HasPrefix(v, "OpenVPN Version: ") {
			sd.Version = strings.TrimPrefix(v, "OpenVPN Version: ")
		}
	}

	return sd

}

func (ov *ovpn) killClient(cid string) {
	ov.sendCommand(fmt.Sprintf("client-kill %s HALT", cid))
}

func parseCrl(crlPath string) (*CertData, error) {
	crlData, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(crlData)
	if block == nil {
		return nil, fmt.Errorf("无法解析证书文件")
	}

	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresIn := crl.NextUpdate.Sub(now)

	var status string
	var expiresInStr string

	if now.After(crl.NextUpdate) {
		status = "已过期"
		expiresInStr = fmt.Sprintf("已过期 %d 天", int(now.Sub(crl.NextUpdate).Hours()/24))
	} else if expiresIn < 30*24*time.Hour {
		status = "即将过期"
		expiresInStr = fmt.Sprintf("%d 天后过期", int(expiresIn.Hours()/24))
	} else {
		status = "正常"
		expiresInStr = fmt.Sprintf("%d 天后过期", int(expiresIn.Hours()/24))
	}

	return &CertData{
		Name:      strings.TrimSuffix(filepath.Base(crlPath), filepath.Ext(crlPath)),
		Type:      "CRL证书",
		Subject:   "",
		Issuer:    crl.Issuer.String(),
		NotBefore: crl.ThisUpdate.Local().Format("2006-01-02 15:04:05"),
		NotAfter:  crl.NextUpdate.Local().Format("2006-01-02 15:04:05"),
		ExpiresIn: expiresInStr,
		Status:    status,
		SerialNo:  "",
	}, nil
}

func parseCert(certPath string) (*CertData, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("无法解析证书文件")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	expiresIn := cert.NotAfter.Sub(now)

	var status string
	var expiresInStr string

	if now.After(cert.NotAfter) {
		status = "已过期"
		expiresInStr = fmt.Sprintf("已过期 %d 天", int(now.Sub(cert.NotAfter).Hours()/24))
	} else if expiresIn < 30*24*time.Hour {
		status = "即将过期"
		expiresInStr = fmt.Sprintf("%d 天后过期", int(expiresIn.Hours()/24))
	} else {
		status = "正常"
		expiresInStr = fmt.Sprintf("%d 天后过期", int(expiresIn.Hours()/24))
	}

	certType := "客户端证书"
	if cert.IsCA {
		certType = "CA证书"
	} else if strings.Contains(cert.Subject.CommonName, "server") {
		certType = "服务器证书"
	}

	return &CertData{
		Name:      strings.TrimSuffix(filepath.Base(certPath), filepath.Ext(certPath)),
		Type:      certType,
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.Local().Format("2006-01-02 15:04:05"),
		NotAfter:  cert.NotAfter.Local().Format("2006-01-02 15:04:05"),
		ExpiresIn: expiresInStr,
		Status:    status,
		SerialNo:  cert.SerialNumber.String(),
	}, nil
}

func getCerts(ovData string) []CertData {
	cers := make([]CertData, 0)
	pkiDir := filepath.Join(ovData, "pki")

	caPath := filepath.Join(pkiDir, "ca.crt")
	if cert, err := parseCert(caPath); err == nil {
		cers = append(cers, *cert)
	} else {
		logger.Error(context.Background(), err.Error())
	}

	crlPath := filepath.Join(pkiDir, "crl.pem")
	if cert, err := parseCrl(crlPath); err == nil {
		cers = append(cers, *cert)
	} else {
		logger.Error(context.Background(), err.Error())
	}

	issuedDir := filepath.Join(pkiDir, "issued")
	if files, err := os.ReadDir(issuedDir); err == nil {
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".crt") {
				certPath := filepath.Join(issuedDir, file.Name())
				if cert, err := parseCert(certPath); err == nil {
					cers = append(cers, *cert)
				} else {
					logger.Error(context.Background(), err.Error())
				}
			}
		}
	} else {
		logger.Error(context.Background(), err.Error())
	}

	return cers
}

func isValidPassword(pw string) bool {
	if !viper.GetBool("system.base.enforce_password_policy") {
		return utf8.RuneCountInString(pw) >= 6
	}

	lower := regexp.MustCompile(`[a-z]`)
	upper := regexp.MustCompile(`[A-Z]`)
	digit := regexp.MustCompile(`[0-9]`)
	special := regexp.MustCompile(`[^A-Za-z0-9]`)

	count := 0
	if len(pw) >= 12 {
		count++
	}
	if lower.MatchString(pw) {
		count++
	}
	if upper.MatchString(pw) {
		count++
	}
	if digit.MatchString(pw) {
		count++
	}
	if special.MatchString(pw) {
		count++
	}

	return count == 5
}

func passwordPolicyMessage() string {
	if viper.GetBool("system.base.enforce_password_policy") {
		return "密码不满足要求（长度至少12位，包含大小写字母、数字、特殊字符）"
	}
	return "密码不满足要求（长度至少6位）"
}

func listClientConfigs(clientsDir string) ([]ClientConfigData, error) {
	clients := make([]ClientConfigData, 0)
	files, err := os.ReadDir(clientsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return clients, nil
		}
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".ovpn") {
			continue
		}
		finfo, err := file.Info()
		if err != nil {
			return nil, err
		}
		clients = append(clients, ClientConfigData{
			Name:     strings.TrimSuffix(file.Name(), ".ovpn"),
			FullName: file.Name(),
			File:     fmt.Sprintf("/ovpn/download/%s", file.Name()),
			Date:     finfo.ModTime().Local().Format("2006-01-02 15:04:05"),
		})
	}

	sort.Slice(clients, func(i, j int) bool {
		if clients[i].Date == clients[j].Date {
			return clients[i].FullName < clients[j].FullName
		}
		return clients[i].Date < clients[j].Date
	})

	defaultConfig := viper.GetString("system.base.default_ovpn_config")
	defaultIndex := -1
	for i := range clients {
		if clients[i].FullName == defaultConfig {
			defaultIndex = i
			break
		}
	}
	if defaultIndex == -1 && len(clients) > 0 {
		defaultIndex = 0
	}
	if defaultIndex >= 0 {
		clients[defaultIndex].IsDefault = true
	}

	return clients, nil
}

func genRandomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func IsLocalRequest(c *gin.Context) bool {
	ip, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return parsedIP.IsLoopback()
}

func AuthMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")

		if c.GetHeader("O-Token") == viper.GetString("system.base.token") {
			if c.Request.URL.Path == "/ovpn/login" || c.Request.URL.Path == "/ovpn/history" || c.Request.URL.Path == "/ovpn/firewall" {
				if IsLocalRequest(c) {
					c.Next()
					return
				}
			}
		}

		if user == nil {
			if isAPIRequest(c.Request.URL.Path) {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "登录已过期，请重新登录"})
			} else {
				c.Redirect(http.StatusFound, "/login")
			}
			c.Abort()
			return
		}

		if user, ok := user.(string); ok {
			if isAPIRequest(c.Request.URL.Path) && !strings.HasPrefix(c.Request.URL.Path, "/client") && c.Request.URL.Path != "/session" && user != adminUsername {
				c.JSON(http.StatusForbidden, gin.H{"message": "没有管理员权限"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

func isAPIRequest(path string) bool {
	return path == "/session" || path == "/settings" || strings.HasPrefix(path, "/ovpn/") ||
		strings.HasPrefix(path, "/client/") || strings.HasPrefix(path, "/email/") || strings.HasPrefix(path, "/user/")
}

func init() {
	if strings.HasSuffix(os.Args[0], ".test") {
		return
	}
	initConfig()
	loadConfig()
}

func main() {
	ov := ovpn{
		address: ovManage,
	}

	var err error
	db, err = gorm.Open(sqlite.Open(filepath.Join(ovData, "ovpn.db")+"?_pragma=foreign_keys(1)"), &gorm.Config{
		Logger: logger,
	})

	if err != nil {
		panic(err)
	}

	c := cron.New()
	c.AddFunc("@daily", func() {
		err := History{}.Clear()
		if err != nil {
			logger.Error(context.Background(), err.Error())
		}
	})
	c.Start()

	store := gormsessions.NewStore(db, true, []byte(secretKey))

	db.AutoMigrate(&Group{})
	db.FirstOrCreate(&Group{Name: "Default", ParentID: nil})
	db.AutoMigrate(&User{}, &History{}, &Firewall{})

	r := gin.New()
	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {

		var statusColor, methodColor, resetColor string
		if param.IsOutputColor() {
			statusColor = param.StatusCodeColor()
			methodColor = param.MethodColor()
			resetColor = param.ResetColor()
		}

		if param.Latency > time.Minute {
			param.Latency = param.Latency.Truncate(time.Second)
		}
		return fmt.Sprintf("[OPENVPN-WEB] %v GIN |%s %3d %s| %13v | %15s |%s %-7s %s %#v\n%s",
			param.TimeStamp.Format("2006-01-02 15:04:05.000"),
			statusColor, param.StatusCode, resetColor,
			param.Latency,
			param.ClientIP,
			methodColor, param.Method, resetColor,
			param.Path,
			param.ErrorMessage,
		)
	}))

	r.Use(sessions.Sessions("user_session", store))

	// r.Use(gin.Recovery())

	r.GET("/login", func(c *gin.Context) {
		serveSPAIndex(c)
	})

	r.POST("/login", func(c *gin.Context) {
		var err error

		cip := c.ClientIP()
		key := c.PostForm("c_key")
		dots := c.PostForm("c_dots")
		passcode := c.PostForm("passcode")

		n := getLoginFail(cip)
		if passcode == "" && n >= loginCaptchaThreshold {
			if key == "" && dots == "" {
				c.JSON(401, gin.H{"message": "需要进行人机验证", "needCaptcha": true})
				return
			}

			if !checkCaptcha(key, dots) {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "验证码错误"})
				return
			}
		}

		session := sessions.Default(c)
		remember7d := c.PostForm("remember7d")

		if remember7d == "on" {
			session.Options(sessions.Options{
				HttpOnly: true,
				Secure:   c.Request.TLS != nil,
				SameSite: http.SameSiteLaxMode,
				Path:     "/",
				MaxAge:   3600 * 24 * 7,
			})
		} else {
			session.Options(sessions.Options{
				HttpOnly: true,
				Secure:   c.Request.TLS != nil,
				SameSite: http.SameSiteLaxMode,
				Path:     "/",
				MaxAge:   3600 * 1,
			})
		}

		var u User
		c.ShouldBind(&u)

		if u.Username == adminUsername {
			if dp, err := aes.AesDecrypt(adminPassword, secretKey); err == nil {
				if subtle.ConstantTimeCompare([]byte(dp), []byte(u.Password)) == 1 {
					passwd, _ := bcrypt.GenerateFromPassword([]byte("admin"), 12)
					viper.Set("system.base.admin_password", string(passwd))
					viper.WriteConfig()

					c.JSON(401, gin.H{"message": "检测到旧的密码加密格式已重置为默认密码，请使用默认密码admin登录后进行修改"})
					return
				}
			}

			if bcrypt.CompareHashAndPassword([]byte(adminPassword), []byte(u.Password)) == nil {
				session.Set("user", u.Username)
				session.Save()

				resetLoginFail(cip)
				c.JSON(200, gin.H{"message": "登录成功", "redirect": "/admin"})
				return
			} else {
				err = fmt.Errorf("密码错误")
			}
		} else {
			if passcode != "" {
				if validUser, ok := cc.Get("valid_user"); ok {
					if u.Username == validUser.(string) {
						if ValidateMfa(passcode, u.Info().MfaSecret) {
							cc.Delete("valid_user")
							session.Set("user", u.Username)
							session.Save()
							resetLoginFail(cip)
							c.JSON(200, gin.H{"message": "登录成功", "redirect": "/"})
						} else {
							c.JSON(401, gin.H{"message": "MFA验证失败"})
						}

						return
					}
				}

				c.JSON(401, gin.H{"message": "登录超时", "redirect": "/login"})
				return
			}

			if err = u.Login(false); err == nil {
				user := u.Info()
				if user.MfaSecret != "" {
					cc.Set("valid_user", u.Username, 1*time.Minute)
					c.JSON(200, gin.H{"message": "需要MFA验证"})
					return
				}

				session.Set("user", u.Username)
				session.Save()

				resetLoginFail(cip)

				c.JSON(200, gin.H{"message": "登录成功", "redirect": "/", "user": gin.H{"id": user.ID, "isFirstLogin": *user.IsFirstLogin}})
				return
			}
		}

		setLoginFail(cip)

		c.JSON(401, gin.H{"message": err.Error()})
	})

	r.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Clear()
		session.Options(sessions.Options{MaxAge: -1})
		session.Save()
		c.Redirect(302, "/login")
	})

	r.GET("/captcha", func(c *gin.Context) {
		key, mBase64, tBase64, err := getCaptcha()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"key": key, "master": mBase64, "thumb": tBase64})
	})

	// 新版 SPA 静态资源与前端路由回退,必须在 AuthMiddleWare 之前注册
	registerWebUI(r)

	r.Use(AuthMiddleWare())

	r.GET("/session", func(c *gin.Context) {
		session := sessions.Default(c)
		username, _ := session.Get("user").(string)
		role := "user"
		if username == adminUsername {
			role = "admin"
		}
		c.JSON(http.StatusOK, gin.H{"username": username, "role": role})
	})

	r.GET("/", func(c *gin.Context) {
		serveSPAIndex(c)
	})

	r.GET("/admin", func(c *gin.Context) {
		session := sessions.Default(c)
		if user, ok := session.Get("user").(string); ok {
			if user != adminUsername {
				c.Redirect(302, "/")
				return
			}
		}

		serveSPAIndex(c)
	})

	r.GET("/settings", func(c *gin.Context) {
		var conf config
		viper.Unmarshal(&conf)
		tlsStatus := getTLSCertificateStatus()
		conf.System.Base.HTTPSCertConfigured = tlsStatus.Configured
		conf.System.Base.HTTPSCertSubject = tlsStatus.Subject
		if !tlsStatus.NotAfter.IsZero() {
			conf.System.Base.HTTPSCertNotAfter = tlsStatus.NotAfter.Format(time.RFC3339)
		}

		c.JSON(http.StatusOK, conf)
	})

	r.POST("/settings", func(c *gin.Context) {
		if err := c.Request.ParseForm(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "解析设置失败"})
			return
		}

		httpsEnabled := viper.GetBool("system.base.https_enabled")
		if values, ok := c.Request.PostForm["system.base.https_enabled"]; ok && len(values) > 0 {
			httpsEnabled = values[0] == "true"
		}
		certPEM := strings.TrimSpace(c.PostForm("https_certificate"))
		keyPEM := strings.TrimSpace(c.PostForm("https_private_key"))
		if (certPEM == "") != (keyPEM == "") {
			c.JSON(http.StatusBadRequest, gin.H{"message": "HTTPS 证书链和私钥必须同时填写"})
			return
		}
		tlsMaterialChanged := certPEM != "" && keyPEM != ""
		if tlsMaterialChanged {
			if err := writeTLSMaterial([]byte(certPEM+"\n"), []byte(keyPEM+"\n")); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
				return
			}
		}
		if httpsEnabled && !getTLSCertificateStatus().Configured {
			c.JSON(http.StatusBadRequest, gin.H{"message": "启用 HTTPS 前必须填写有效且匹配的证书链和私钥"})
			return
		}

		previousHTTPSEnabled := viper.GetBool("system.base.https_enabled")
		for k, vs := range c.Request.PostForm {
			if k == "https_certificate" || k == "https_private_key" {
				continue
			}
			val := vs[0]

			switch k {
			case "system.base.admin_password":
				ep, _ := bcrypt.GenerateFromPassword([]byte(val), 12)
				val = string(ep)
			case "system.email.password":
				val, _ = aes.AesEncrypt(val, secretKey)
			case "system.base.max_duplicate_login":
				n, err := strconv.Atoi(val)
				if err != nil {
					n = 0
				}

				if n > 0 {
					cfg, err := initOvpnConfig()
					if err != nil {
						logger.Error(context.Background(), err.Error())
						return
					}

					statusLogPath := filepath.Join(ovData, "openvpn-status.log")
					if cfg.Get("status-version") != "3" || cfg.Get("status") != statusLogPath+" 1" {
						cfg.Set("status", statusLogPath+" 1")
						cfg.Set("status-version", "3")
						cfg.Save()

						ov.sendCommand("signal SIGHUP")
					}
				}
			case "openvpn.ovpn_subnet", "openvpn.ovpn_subnet6":
				_, _, err := net.ParseCIDR(val)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
					return
				}
			case "openvpn.ovpn_push_dns1", "openvpn.ovpn_push_dns2":
				if net.ParseIP(val) == nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "invalid IP address: " + val})
					return
				}
			}

			switch val {
			case "true":
				viper.Set(k, true)
			case "false":
				viper.Set(k, false)
			default:
				viper.Set(k, val)
			}
		}
		if err := viper.WriteConfig(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			return
		}
		if httpsEnabled && (tlsMaterialChanged || httpsEnabled != previousHTTPSEnabled) {
			if err := updateInternalAPIEndpoints(); err != nil {
				logger.Error(context.Background(), "failed to update internal API endpoints: %s", err)
				c.JSON(http.StatusInternalServerError, gin.H{"message": "HTTPS 设置已保存，但更新 OpenVPN 内部认证地址失败: " + err.Error()})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"message":         "更新成功",
			"restartRequired": tlsMaterialChanged || httpsEnabled != previousHTTPSEnabled,
		})
	})

	r.POST("/email/send", func(c *gin.Context) {
		email := c.PostForm("email")
		subject := c.PostForm("subject")
		content := c.PostForm("content")

		err := sendEmail(email, subject, content)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "发送成功"})
		}
	})

	ovpn := r.Group("/ovpn")
	{
		// 使用 FileAttachment 强制触发浏览器下载(StaticFS 会被浏览器当文本打开)
		ovpn.GET("/download/:file", func(c *gin.Context) {
			file := filepath.Base(c.Param("file"))
			p := filepath.Join(ovData, "clients", file)
			if _, err := os.Stat(p); err != nil {
				c.Status(http.StatusNotFound)
				return
			}
			c.FileAttachment(p, file)
		})

		ovpn.POST("/server", func(c *gin.Context) {
			a := c.PostForm("action")

			switch a {
			case "settings":
				k := c.PostForm("key")
				v := c.PostForm("value")

				if k == "auth-user" {
					msg := "停用"
					if v == "true" {
						msg = "启用"
					}
					cmd := exec.Command("docker-entrypoint.sh", "auth", v)
					if out, err := cmd.CombinedOutput(); err != nil {
						if len(out) == 0 {
							out = []byte(err.Error())
						}
						logger.Error(context.Background(), string(out))
						c.JSON(http.StatusInternalServerError, gin.H{"message": fmt.Sprintf("%s用户认证失败", msg)})
					} else {
						ov.sendCommand("signal SIGHUP")
						c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("%s用户认证成功", msg)})
					}
				}
			case "renewCert":
				day := c.PostForm("day")

				cmd := exec.Command("docker-entrypoint.sh", "renewcert", day)
				if out, err := cmd.CombinedOutput(); err != nil {
					if len(out) == 0 {
						out = []byte(err.Error())
					}
					logger.Error(context.Background(), string(out))
					c.JSON(http.StatusInternalServerError, gin.H{"message": "更新证书失败"})
					return
				}

				if err := syncInlinePKIFromDisk(); err != nil {
					logger.Error(context.Background(), err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"message": "证书已续期，但同步客户端 CA 失败: " + err.Error()})
					return
				}

				ov.sendCommand("signal SIGHUP")
				c.JSON(http.StatusOK, gin.H{"message": "更新证书成功"})
			case "restartSrv":
				_, err := ov.sendCommand("signal SIGHUP")
				if err != nil {
					logger.Error(context.Background(), err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"message": "重启服务失败"})
					return
				}

				c.JSON(http.StatusOK, gin.H{"message": "重启服务成功"})
			case "getConfig":
				data, err := os.ReadFile(filepath.Join(ovData, "server.conf"))
				if err != nil {
					logger.Error(context.Background(), err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"content": string(data)})
			case "updateConfig":
				content := c.PostForm("content")
				if strings.TrimSpace(content) == "" {
					c.JSON(http.StatusBadRequest, gin.H{"message": "server.conf 不能为空"})
					return
				}
				if len(content) > 2*1024*1024 || strings.ContainsRune(content, '\x00') {
					c.JSON(http.StatusBadRequest, gin.H{"message": "server.conf 内容非法或超过 2 MiB"})
					return
				}
				if !strings.HasSuffix(content, "\n") {
					content += "\n"
				}

				configPath := filepath.Join(ovData, "server.conf")
				if err := applyFileUpdates([]fileUpdate{{path: configPath, data: []byte(content), mode: 0644}}); err != nil {
					logger.Error(context.Background(), err.Error())
					c.JSON(http.StatusInternalServerError, gin.H{"message": "保存 server.conf 失败: " + err.Error()})
					return
				}

				c.JSON(http.StatusOK, gin.H{"message": "配置已保存并创建备份，请重启 OpenVPN 生效"})
			default:
				c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "未知操作"})
			}

		})

		ovpn.POST("/kill", func(c *gin.Context) {
			cid := c.PostForm("cid")
			ov.killClient(cid)
			c.JSON(http.StatusOK, gin.H{"code": http.StatusOK})
		})

		ovpn.GET("/firewall", FirewallHandler)
		ovpn.POST("/firewall", FirewallHandler)
		ovpn.PATCH("/firewall", FirewallHandler)
		ovpn.DELETE("/firewall/:id", FirewallHandler)

		ovpn.POST("/login", func(c *gin.Context) {
			var u User
			c.ShouldBind(&u)
			u.OvpnConfig = c.PostForm("common_name")

			err := u.Login(true)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "登录成功"})
			}
		})

		ovpn.GET("/online-client", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"server": ov.getServer(), "clients": ov.getClient()})
		})

		ovpn.GET("/group", func(c *gin.Context) {
			var g Group
			c.JSON(http.StatusOK, g.All())
		})

		ovpn.GET("/group/:id", func(c *gin.Context) {
			var g Group
			c.JSON(http.StatusOK, g.Get(c.Param("id")))
		})

		ovpn.GET("/group/:id/users", func(c *gin.Context) {
			var auth bool
			var g Group

			gid := c.Param("id")

			cmd := exec.Command("egrep", "^auth-user-pass-verify", filepath.Join(ovData, "server.conf"))
			if err := cmd.Run(); err != nil {
				auth = false
			} else {
				auth = true
			}

			c.JSON(http.StatusOK, gin.H{"users": g.GetUsers(gid), "authUser": auth})
		})

		ovpn.POST("/group", func(c *gin.Context) {
			var g Group
			c.ShouldBind(&g)

			err := g.Create()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "添加成功"})
		})

		ovpn.PATCH("/group", func(c *gin.Context) {
			var g Group
			c.ShouldBind(&g)

			if config, ok := c.Request.PostForm["config"]; ok {
				if config[0] == "" {
					db.Model(&g).Update("config", nil)
				}
			}

			err := g.Update()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
		})

		ovpn.DELETE("/group/:id", func(c *gin.Context) {
			var g Group
			c.ShouldBind(&g)

			err := g.Delete(c.Param("id"))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
		})

		ovpn.GET("/user", func(c *gin.Context) {
			var u User

			username := c.Query("username")
			if username != "" {
				u.Username = username
			}

			c.JSON(http.StatusOK, u.Info())
		})

		ovpn.GET("/user/:id", func(c *gin.Context) {
			var u User
			c.JSON(http.StatusOK, u.Get(c.Param("id")))
		})

		r.GET("/user/template", func(c *gin.Context) {
			c.Header("Content-Type", "text/csv")
			c.Header("Content-Disposition", "attachment; filename=user_template.csv")

			c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})

			writer := csv.NewWriter(c.Writer)
			defer writer.Flush()

			writer.Write([]string{"username", "password", "name", "email", "is_enable", "expire_date", "ip_addr", "ovpn_config"})
			writer.Write([]string{"zhangsan", "Vpn@2026Secure", "张三", "zhangsan@example.com", "1", "2027-12-01/00:00:00", "10.8.0.222", "tt-gz.ovpn"})
			writer.Write([]string{"lisi", "Vpn@2026Secure", "李四", "lisi@example.com", "0", "", "", "tt-sh.ovpn"})
		})

		ovpn.GET("/user/export", func(c *gin.Context) {
			gid := c.Query("gid")

			fileName := fmt.Sprintf("user_%s.csv", time.Now().Format("20060102150405"))

			c.Header("Content-Type", "text/csv; charset=utf-8")
			c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
			c.Header("Cache-Control", "no-cache")

			c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})

			writer := csv.NewWriter(c.Writer)
			header := []string{"ID", "用户名", "密码", "姓名", "节点", "启用", "过期时间", "IP地址", "配置文件", "MFA", "创建时间"}
			if err := writer.Write(header); err != nil {
				logger.Error(context.Background(), err.Error())
				return
			}
			writer.Flush()

			gQuery := db.Model(&Group{}).
				Select("id").
				Where(`
				parent_id = ?
				OR EXISTS (
					SELECT 1 FROM `+"`group`"+`
					WHERE id = ? AND parent_id IS NULL
				)
				`, gid, gid)

			rows, err := db.Model(&User{}).Where("gid = ? OR gid IN (?)", gid, gQuery).Rows()
			if err != nil {
				return
			}
			defer rows.Close()

			for rows.Next() {
				var u User
				var g Group

				db.ScanRows(rows, &u)

				enable := "0"
				if *u.IsEnable {
					enable = "1"
				}

				dp, _ := aes.AesDecrypt(u.Password, secretKey)
				record := []string{
					strconv.Itoa(int(u.ID)),
					u.Username,
					dp,
					u.Name,
					g.Get(strconv.Itoa(int(u.Gid))).Name,
					enable,
					u.ExpireDate,
					u.IpAddr,
					u.OvpnConfig,
					u.MfaSecret,
					u.CreatedAt.Format("2006-01-02 15:04:05"),
				}

				if err := writer.Write(record); err != nil {
					logger.Error(context.Background(), err.Error())
					return
				}
			}
			writer.Flush()

			if err := writer.Error(); err != nil {
				logger.Error(context.Background(), err.Error())
			}
		})

		ovpn.POST("/user", func(c *gin.Context) {
			var u User
			c.ShouldBind(&u)

			file, err := c.FormFile("file")
			if err != nil {
				if strings.Contains(err.Error(), "no such file") {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "没有上传文件"})
					return
				}
			} else {
				gid := c.PostForm("gid")
				f, _ := file.Open()

				defer f.Close()

				reader := csv.NewReader(f)

				header, err := reader.Read()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
					return
				}

				if len(header) != 8 {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "导入文件格式错误"})
					return
				}

				for {
					record, err := reader.Read()
					if err == io.EOF {
						break
					}

					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
						return
					}

					enable := record[4] == "1"
					gid64, err := strconv.ParseUint(gid, 10, 64)
					u := User{
						Username:   record[0],
						Password:   record[1],
						Name:       record[2],
						Email:      record[3],
						IsEnable:   &enable,
						ExpireDate: strings.Replace(record[5], "/", " ", 1),
						IpAddr:     record[6],
						OvpnConfig: record[7],
						Gid:        uint(gid64),
					}

					err = u.Create()
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
						return
					}
				}

				c.JSON(http.StatusOK, gin.H{"message": "导入用户成功"})
				return
			}

			if isFirstLogin, ok := c.Request.PostForm["isFirstLogin"]; ok {
				val := isFirstLogin[0] == "true"
				u.IsFirstLogin = &val
			}

			err = u.Create()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			} else {
				sendNotifyEmail := c.PostForm("sendNotifyEmail")
				if sendNotifyEmail == "true" {
					go func() {
						var tpl *template.Template
						var buf bytes.Buffer

						tpl, err = template.ParseFS(FS, "templates/email.html")
						if err == nil {
							err = tpl.Execute(&buf, struct {
								Type     string
								Name     string
								Username string
								Password string
								SiteUrl  string
							}{
								Type:     "addUser",
								Name:     u.Name,
								Username: u.Username,
								Password: c.PostForm("password"),
								SiteUrl:  viper.GetString("system.base.site_url"),
							})
						}

						if err != nil {
							logger.Error(context.Background(), err.Error())
							return
						}

						sendEmail(u.Email, "用户开通通知", buf.String())
					}()
				}

				c.JSON(http.StatusOK, gin.H{"message": "添加用户成功"})
			}
		})

		ovpn.PATCH("/user", func(c *gin.Context) {
			var u User
			c.ShouldBind(&u)

			if ipAddr, ok := c.Request.PostForm["ipAddr"]; ok {
				if ipAddr[0] == "" {
					db.Model(&u).Update("ip_addr", nil)
				}
			}

			if expireDate, ok := c.Request.PostForm["expireDate"]; ok {
				if expireDate[0] == "" {
					db.Model(&u).Update("expire_date", nil)
				}
			}

			err := u.Update()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			} else {
				sendNotifyEmail := c.PostForm("sendNotifyEmail")
				if sendNotifyEmail == "true" {
					go func() {
						var cu User
						db.First(&cu, u.ID)

						if cu.Email != "" {
							var tpl *template.Template
							var buf bytes.Buffer

							tpl, err = template.ParseFS(FS, "templates/email.html")
							if err == nil {
								err = tpl.Execute(&buf, struct {
									Type     string
									Name     string
									Username string
									Password string
									SiteUrl  string
								}{
									Type:     "resetPass",
									Name:     cu.Name,
									Username: cu.Username,
									Password: c.PostForm("password"),
									SiteUrl:  viper.GetString("system.base.site_url"),
								})
							}

							if err != nil {
								logger.Error(context.Background(), err.Error())
								return
							}

							sendEmail(cu.Email, "用户密码重置通知", buf.String())
						} else {
							logger.Error(context.Background(), "发送邮件通知失败，用户没有配置邮箱地址")
						}
					}()
				}

				c.JSON(http.StatusOK, gin.H{"message": "用户更新成功"})
			}
		})

		ovpn.DELETE("/user/:id", func(c *gin.Context) {
			var u User
			id := c.Param("id")

			err := u.Delete(id)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "删除用户成功"})
			}
		})

		ovpn.GET("/client", func(c *gin.Context) {
			clients, err := listClientConfigs(filepath.Join(ovData, "clients"))
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "读取客户端配置失败"})
				return
			}
			c.JSON(http.StatusOK, clients)
		})

		ovpn.PUT("/client/:name/default", func(c *gin.Context) {
			name := c.Param("name")
			if filepath.Base(name) != name || !strings.HasSuffix(name, ".ovpn") {
				c.JSON(http.StatusBadRequest, gin.H{"message": "非法客户端配置名称"})
				return
			}
			if _, err := os.Stat(filepath.Join(ovData, "clients", name)); err != nil {
				c.JSON(http.StatusNotFound, gin.H{"message": "客户端配置不存在"})
				return
			}

			viper.Set("system.base.default_ovpn_config", name)
			if err := viper.WriteConfig(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "默认客户端设置成功"})
		})

		ovpn.GET("/client/:name/ccd", func(c *gin.Context) {
			name := c.Param("name")
			ccdDir := filepath.Join(ovData, "ccd")

			os.MkdirAll(ccdDir, 0755)

			ccdRoot, err := os.OpenRoot(ccdDir)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			defer ccdRoot.Close()

			data, err := ccdRoot.ReadFile(name)
			if err != nil {
				if os.IsNotExist(err) {
					c.JSON(http.StatusOK, gin.H{"content": ""})
				} else {
					c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				}
				return
			}

			c.JSON(http.StatusOK, gin.H{"content": string(data)})
		})

		ovpn.GET("/client/:name/config", func(c *gin.Context) {
			name := c.Param("name")
			clientsDir := filepath.Join(ovData, "clients")

			clientsRoot, err := os.OpenRoot(clientsDir)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			defer clientsRoot.Close()

			data, err := clientsRoot.ReadFile(name + ".ovpn")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"content": string(data)})
		})

		ovpn.PUT("/client/:name/ccd", func(c *gin.Context) {
			name := c.Param("name")
			content := c.PostForm("content")
			msg := "客户端更新成功"
			ccdDir := filepath.Join(ovData, "ccd")

			os.MkdirAll(ccdDir, 0755)

			cfg, err := initOvpnConfig()
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			if cfg.Get("client-config-dir") == "" {
				cfg.Set("client-config-dir", ccdDir)
				cfg.Save()

				msg += "（未启用CCD需要重启服务生效）"
			}

			ccdRoot, err := os.OpenRoot(ccdDir)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			defer ccdRoot.Close()

			err = ccdRoot.WriteFile(name, []byte(content), 0644)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": msg})
		})

		ovpn.PUT("/client/:name/config", func(c *gin.Context) {
			name := c.Param("name")
			content := c.PostForm("content")
			clientsDir := filepath.Join(ovData, "clients")

			clientsRoot, err := os.OpenRoot(clientsDir)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			defer clientsRoot.Close()

			err = clientsRoot.WriteFile(name+".ovpn", []byte(content), 0644)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "客户端配置更新成功"})
			}
		})

		ovpn.POST("/client", func(c *gin.Context) {
			name := c.PostForm("name")
			serverAddr := c.PostForm("serverAddr")
			serverPort := c.PostForm("serverPort")
			config := c.PostForm("config")
			ccdConfig := c.PostForm("ccdConfig")
			mfa := c.PostForm("mfa")

			clientsDir := filepath.Join(ovData, "clients")

			os.MkdirAll(clientsDir, 0755)

			clientsRoot, err := os.OpenRoot(clientsDir)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			defer clientsRoot.Close()

			_, err = clientsRoot.Stat(name + ".ovpn")
			if err != nil {
				if os.IsNotExist(err) {
					cmd := exec.Command("docker-entrypoint.sh", "genclient", name, serverAddr, serverPort, config, ccdConfig, mfa)
					if out, err := cmd.CombinedOutput(); err != nil {
						if len(out) == 0 {
							out = []byte(err.Error())
						}
						logger.Error(context.Background(), string(out))
						c.JSON(http.StatusInternalServerError, gin.H{"message": "客户端添加失败"})
						return
					}
					if viper.GetString("system.base.default_ovpn_config") == "" {
						clients, listErr := listClientConfigs(clientsDir)
						if listErr == nil && len(clients) > 0 {
							for _, client := range clients {
								if client.IsDefault {
									viper.Set("system.base.default_ovpn_config", client.FullName)
									break
								}
							}
							if err := viper.WriteConfig(); err != nil {
								logger.Error(context.Background(), err.Error())
							}
						} else if listErr != nil {
							logger.Error(context.Background(), listErr.Error())
						}
					}

					c.JSON(http.StatusOK, gin.H{"message": "客户端添加成功"})
					return
				}

				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "非法客户端名称"})
				return
			}

			c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "客户端已存在"})
		})

		ovpn.DELETE("/client/:name", func(c *gin.Context) {
			name := c.Param("name")

			cmd := exec.Command("easyrsa", "--batch", "revoke", name)
			out, err := cmd.CombinedOutput()
			if err == nil {
				cmd = exec.Command("easyrsa", "gen-crl")
				if out, err = cmd.CombinedOutput(); err != nil {
					logger.Error(context.Background(), string(out))
					c.JSON(http.StatusInternalServerError, gin.H{"message": "更新CRL证书失败"})
				}
			} else {
				if len(out) == 0 {
					out = []byte(err.Error())
				}
				logger.Error(context.Background(), string(out))
				c.JSON(http.StatusInternalServerError, gin.H{"message": "删除客户端失败"})
				return
			}

			dataRoot, err := os.OpenRoot(ovData)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			defer dataRoot.Close()

			dataRoot.Remove(filepath.Join("clients", fmt.Sprintf("%s.ovpn", name)))
			dataRoot.Remove(filepath.Join("ccd", name))
			if viper.GetString("system.base.default_ovpn_config") == name+".ovpn" {
				viper.Set("system.base.default_ovpn_config", "")
				if err := viper.WriteConfig(); err != nil {
					logger.Error(context.Background(), err.Error())
				}
			}

			c.JSON(http.StatusOK, gin.H{"message": "删除客户端成功"})
		})

		ovpn.GET("/history", func(c *gin.Context) {
			var h History
			var p Params

			c.ShouldBindQuery(&p)

			c.JSON(http.StatusOK, h.Query(p))
		})

		ovpn.POST("/history", func(c *gin.Context) {
			var h History
			c.ShouldBind(&h)

			err := h.Create()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "添加记录成功"})
			}
		})

		ovpn.GET("/history/export", func(c *gin.Context) {
			var p Params
			c.ShouldBindQuery(&p)

			fileName := fmt.Sprintf("history_%s.csv", time.Now().Format("20060102150405"))

			c.Header("Content-Type", "text/csv; charset=utf-8")
			c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
			c.Header("Cache-Control", "no-cache")

			c.Writer.Write([]byte{0xEF, 0xBB, 0xBF})

			writer := csv.NewWriter(c.Writer)
			header := []string{"ID", "用户名", "客户端", "VPN IP", "用户 IP", "下载流量", "上传流量", "上线时间", "在线时长", "创建时间"}
			if err := writer.Write(header); err != nil {
				logger.Error(context.Background(), err.Error())
				return
			}
			writer.Flush()

			query := db.Model(&History{})
			if p.Qt != "" {
				qt := strings.Split(p.Qt, ",")
				if len(qt) == 2 {
					query = query.Where("time_unix BETWEEN ? AND ?", qt[0], qt[1])
				}
			}

			rows, err := query.Rows()
			if err != nil {
				return
			}
			defer rows.Close()

			for rows.Next() {
				var h History

				db.ScanRows(rows, &h)
				record := []string{
					strconv.Itoa(int(h.ID)),
					h.Username,
					h.CommonName,
					h.Vip,
					h.Rip,
					tools.FormatBytes(h.BytesReceived),
					tools.FormatBytes(h.BytesSent),
					time.Unix(h.TimeUnix, 0).Format("2006-01-02 15:04:05"),
					(time.Duration(h.TimeDuration) * time.Second).String(),
					h.CreatedAt.Format("2006-01-02 15:04:05"),
				}

				if err := writer.Write(record); err != nil {
					logger.Error(context.Background(), err.Error())
					return
				}
			}
			writer.Flush()

			if err := writer.Error(); err != nil {
				logger.Error(context.Background(), err.Error())
			}
		})

		ovpn.GET("/certs", func(c *gin.Context) {
			c.JSON(http.StatusOK, getCerts(ovData))
		})

		ovpn.GET("/certs/material", getCertificateMaterial)
		ovpn.PUT("/certs/material", replaceCertificateMaterial)
	}

	client := r.Group("/client")
	{
		client.GET("/password-policy", func(c *gin.Context) {
			enforced := viper.GetBool("system.base.enforce_password_policy")
			minLength := 6
			if enforced {
				minLength = 12
			}
			c.JSON(http.StatusOK, gin.H{
				"enforced":  enforced,
				"minLength": minLength,
			})
		})

		client.GET("/userinfo", func(c *gin.Context) {
			var u User

			session := sessions.Default(c)
			if user, ok := session.Get("user").(string); ok {
				u.Username = user
			}

			if ldapAuth {
				l, err := InitLdap()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
					return
				}

				lu, err := l.Get(u.Username)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
					return
				}

				c.JSON(http.StatusOK, lu)
				return
			}

			c.JSON(http.StatusOK, u.Info())
		})

		client.POST("/modifyPass", func(c *gin.Context) {
			var u User
			c.ShouldBind(&u)

			session := sessions.Default(c)
			if user, ok := session.Get("user").(string); ok {
				cu := User{Username: user}.Info()
				if u.ID != cu.ID {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "非法请求"})
					return
				}
			}

			if !isValidPassword(u.Password) {
				c.JSON(http.StatusBadRequest, gin.H{"message": passwordPolicyMessage()})
				return
			}

			if currentPass, ok := c.Request.PostForm["currentPass"]; ok {
				if u.Info().Password != currentPass[0] {
					c.JSON(http.StatusUnauthorized, gin.H{"message": "当前密码错误"})
					return
				}
			}

			encryptedPassword, err := encryptUserPassword(u.Password)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "加密密码失败"})
				return
			}

			err = db.Transaction(func(tx *gorm.DB) error {
				data := User{
					Password: encryptedPassword,
				}

				if isFirstLogin, ok := c.Request.PostForm["isFirstLogin"]; ok {
					val := isFirstLogin[0] == "true"
					data.IsFirstLogin = &val
				}

				if err := tx.Model(&User{}).Where("id = ?", u.ID).Updates(data).Error; err != nil {
					return err
				}

				return nil
			})

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
			} else {
				c.JSON(http.StatusOK, gin.H{"message": "密码修改成功"})
			}
		})

		client.GET("/userConfig", func(c *gin.Context) {
			var u User
			session := sessions.Default(c)
			if user, ok := session.Get("user").(string); ok {
				u.Username = user
			}

			u = u.Info()
			configName := u.OvpnConfig

			if ldapAuth {
				l, err := InitLdap()
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
					return
				}

				lu, err := l.Get(u.Username)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
					return
				}

				configName = lu.OvpnConfig
			}

			if configName == "" {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "该账号未指定配置文件，请联系管理员"})
				return
			}

			clientsDir := filepath.Join(ovData, "clients")

			clientsRoot, err := os.OpenRoot(clientsDir)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}
			defer clientsRoot.Close()

			data, err := clientsRoot.ReadFile(configName)
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": "读取配置文件失败"})
				return
			}

			challengeLine := `static-challenge "Enter MFA code" 1`
			content := string(data)

			if u.MfaSecret != "" {
				if !strings.Contains(content, challengeLine) {
					if !strings.HasSuffix(content, "\n") {
						content += "\n"
					}
					content += challengeLine + "\n"
				}
			} else {
				content = strings.ReplaceAll(content, challengeLine+"\n", "")
			}

			cfg, err := initOvpnConfig()
			if err != nil {
				logger.Error(context.Background(), err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
				return
			}

			if cfg.Get("auth-user-pass-verify") != "" {
				if strings.Contains(content, "#auth-user-pass") {
					content = strings.ReplaceAll(content, "#auth-user-pass", "auth-user-pass")
				}
			} else {
				if !strings.Contains(content, "#auth-user-pass") {
					content = strings.ReplaceAll(content, "auth-user-pass", "#auth-user-pass")
				}
			}

			c.JSON(http.StatusOK, gin.H{"filename": configName, "content": content})
		})

		client.GET("/mfa", func(c *gin.Context) {
			if ldapAuth {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "LDAP用户不支持设置MFA"})
				return
			}

			var u User

			session := sessions.Default(c)
			if user, ok := session.Get("user").(string); ok {
				u.Username = user
			}

			u = u.Info()
			if u.MfaSecret == "" {
				secret, uri, qrCode, err := GenMfa(u.Username)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": fmt.Errorf("MFA: %w", err).Error()})
				} else {
					u.MfaSecret = secret
					c.JSON(http.StatusOK, gin.H{"mfaEnable": false, "user": u, "otpauthUri": uri, "qrCode": qrCode})
				}
			} else {
				c.JSON(http.StatusOK, gin.H{"mfaEnable": true, "user": u})
			}
		})

		client.POST("/mfa", func(c *gin.Context) {
			var u User
			c.ShouldBind(&u)

			session := sessions.Default(c)
			if user, ok := session.Get("user").(string); ok {
				cu := User{Username: user}.Info()
				if u.ID != cu.ID {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "非法请求"})
					return
				}
			}

			passcode := c.PostForm("passcode")

			vaild := ValidateMfa(passcode, u.MfaSecret)
			if !vaild {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "验证码错误"})
			} else {
				db.Model(&User{}).Where("id = ?", u.ID).Update("mfa_secret", u.MfaSecret)
				c.JSON(http.StatusOK, gin.H{"message": "MFA已启用"})
			}
		})

		client.DELETE("/mfa/:id", func(c *gin.Context) {
			var u User
			c.ShouldBindUri(&u)

			session := sessions.Default(c)
			if user, ok := session.Get("user").(string); ok {
				cu := User{Username: user}.Info()
				if !(u.ID == cu.ID || cu.Username == adminUsername) {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "非法请求"})
					return
				}
			}

			db.Model(&User{}).Where("id = ?", u.ID).Update("mfa_secret", nil)

			c.JSON(http.StatusOK, gin.H{"message": "MFA已停用"})
		})
	}

	if webPort == webInternalPort {
		log.Fatalf("public web port and internal web port must be different: %s", webPort)
	}

	internalServer := newWebServer("127.0.0.1:"+webInternalPort, r)
	go func() {
		logger.Info(context.Background(), "internal HTTP API listening on 127.0.0.1:%s", webInternalPort)
		if err := internalServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("internal HTTP API failed: %v", err)
		}
	}()

	publicServer := newWebServer(":"+webPort, r)
	var serveErr error
	if conf.System.Base.HTTPSEnabled {
		certPath, keyPath := tlsMaterialPaths()
		if !getTLSCertificateStatus().Configured {
			log.Fatal("HTTPS is enabled but the certificate or private key is missing, invalid, expired, or mismatched")
		}
		logger.Info(context.Background(), "public HTTPS server listening on :%s", webPort)
		serveErr = publicServer.ListenAndServeTLS(certPath, keyPath)
	} else {
		logger.Info(context.Background(), "public HTTP server listening on :%s", webPort)
		serveErr = publicServer.ListenAndServe()
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		log.Fatal(serveErr)
	}
}

func newWebServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}
