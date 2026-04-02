// dns-detector — 权威 DNS 服务器 + Web 后端
//
// 工作原理：
//   1. 前端生成随机 token，触发对 <token>.dns.yourdomain.com 的 DNS 查询
//   2. 用户的 DNS 解析器（递归解析器）将请求转发至本服务器（权威 DNS）
//   3. 本服务器在 UDP/TCP 53 端口接收查询，记录 token → 解析器IP 的映射
//   4. 前端轮询 /api/info?token=xxx，后端返回客户端IP + DNS解析器IP + 归属地信息

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// ══════════════════════════════════════════════════════════
//  日志系统
// ══════════════════════════════════════════════════════════

// LogLevel 定义日志等级，数值越大越详细。
// 生产环境建议设为 LevelInfo，调试时设为 LevelDebug。
type LogLevel int

const (
	LevelDebug LogLevel = iota // 0 — 详细调试信息（每条 DNS 查询、缓存命中等）
	LevelInfo                  // 1 — 关键流程信息（启动、token 捕获、清理统计）
	LevelWarn                  // 2 — 非致命异常（速率限制触发、geo 查询失败）
	LevelError                 // 3 — 致命错误（监听失败等）
)

// levelName 用于日志前缀显示。
var levelName = map[LogLevel]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO ",
	LevelWarn:  "WARN ",
	LevelError: "ERROR",
}

// Logger 是全局带等级的日志器。
// 只有 level >= minLevel 的日志才会输出。
type Logger struct {
	minLevel LogLevel
	inner    *log.Logger // 底层使用标准库 log，保留时间戳前缀
}

// newLogger 创建 Logger。
//
//	minLevel — 最低输出等级
//	out      — 输出目标（通常为 os.Stdout 或文件）
func newLogger(minLevel LogLevel, out io.Writer) *Logger {
	return &Logger{
		minLevel: minLevel,
		inner:    log.New(out, "", log.LstdFlags|log.Lmicroseconds),
	}
}

func (l *Logger) log(level LogLevel, format string, args ...any) {
	if level < l.minLevel {
		return // 低于最小等级，直接丢弃，零 I/O 开销
	}
	prefix := "[" + levelName[level] + "] "
	l.inner.Printf(prefix+format, args...)
}

// Debug 记录调试信息（例如每条 DNS 查询细节）。
// 生产环境 minLevel=Info 时此方法零开销（条件在入口即返回）。
func (l *Logger) Debug(format string, args ...any) { l.log(LevelDebug, format, args...) }

// Info 记录关键流程节点。
func (l *Logger) Info(format string, args ...any) { l.log(LevelInfo, format, args...) }

// Warn 记录非致命异常，需要关注但不影响主流程。
func (l *Logger) Warn(format string, args ...any) { l.log(LevelWarn, format, args...) }

// Error 记录需要立即处理的错误。
func (l *Logger) Error(format string, args ...any) { l.log(LevelError, format, args...) }

// parseLogLevel 将环境变量字符串转为 LogLevel。
// 未识别的字符串默认返回 LevelInfo。
func parseLogLevel(s string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// 全局 logger，在 main() 中初始化后供各模块使用。
var logger *Logger

// ══════════════════════════════════════════════════════════
//  配置
// ══════════════════════════════════════════════════════════

// Config 保存服务器运行所需的全部配置，通过环境变量注入。
type Config struct {
	Domain    string   // 权威 DNS 区域，例如 "dns.example.com"
	NSIP      string   // 本服务器的公网 IP
	WebPort   string   // HTTP 监听端口，例如 ":8080"
	DNSPort   string   // DNS 监听端口，通常为 ":53"
	LogLevel  LogLevel // 日志输出等级
	GeoDBPath string   // MaxMind GeoLite2 数据库文件路径

	// AllowedZones 是 DNS 查询的域名白名单。
	// 只有 qname 属于这些区域的查询才会被处理，其他返回 REFUSED。
	// 始终包含 Config.Domain 本身，可通过 DNS_ALLOW_ZONES 追加额外区域。
	AllowedZones []string
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// buildConfig 从环境变量构建 Config，同时做规范化处理。
func buildConfig() *Config {
	domain := strings.ToLower(strings.TrimSuffix(
		getEnv("DNS_DOMAIN", "dns.example.com"), "."))

	cfg := &Config{
		Domain:    domain,
		NSIP:      getEnv("NS_IP", "1.2.3.4"),
		WebPort:   getEnv("WEB_PORT", ":8080"),
		DNSPort:   getEnv("DNS_PORT", ":53"),
		LogLevel:  parseLogLevel(getEnv("LOG_LEVEL", "info")),
		GeoDBPath: getEnv("GEODB_PATH", "GeoLite2-City.mmdb"),
	}

	// 白名单始终包含主域名本身
	zoneSet := map[string]struct{}{domain: {}}

	// DNS_ALLOW_ZONES 允许追加额外区域，逗号分隔
	// 例如：DNS_ALLOW_ZONES=dns.example.com,probe.another.com
	if extra := getEnv("DNS_ALLOW_ZONES", ""); extra != "" {
		for _, z := range strings.Split(extra, ",") {
			z = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(z, ".")))
			if z != "" {
				zoneSet[z] = struct{}{}
			}
		}
	}

	for z := range zoneSet {
		cfg.AllowedZones = append(cfg.AllowedZones, z)
	}
	return cfg
}

// isAllowedZone 判断 qname 是否属于白名单中某个区域。
// 规则：qname == zone 本身，或者 qname 以 "."+zone 结尾（子域名）。
func (c *Config) isAllowedZone(qname string) bool {
	for _, zone := range c.AllowedZones {
		if qname == zone || strings.HasSuffix(qname, "."+zone) {
			return true
		}
	}
	return false
}

// ══════════════════════════════════════════════════════════
//  Token Store
// ══════════════════════════════════════════════════════════

type tokenEntry struct {
	resolverIP string
	createdAt  time.Time
}

// TokenStore 存储 token → DNS解析器IP 的映射。
//
// 设计要点：
//  1. sync.RWMutex 保证并发安全
//  2. token 被 HTTP 端读取后立即删除（一次性消费）
//  3. 后台定时清理兜底：未被消费的过期 token 也会被清除
//  4. 写入速率限制：防止攻击者用随机 DNS 查询打爆内存
type TokenStore struct {
	mu      sync.RWMutex
	entries map[string]tokenEntry

	rateMu    sync.Mutex
	rateCount map[string]int // resolverIP → 当前窗口内写入次数
	rateReset time.Time      // 当前速率窗口的结束时间
}

const (
	rateWindowDur = time.Minute
	rateMaxPerIP  = 60 // 每个解析器 IP 每分钟最多写入 60 个 token
	tokenTTL      = 5 * time.Minute
)

func NewTokenStore() *TokenStore {
	s := &TokenStore{
		entries:   make(map[string]tokenEntry),
		rateCount: make(map[string]int),
		rateReset: time.Now().Add(rateWindowDur),
	}
	go func() {
		for range time.NewTicker(time.Minute).C {
			s.mu.Lock()
			cutoff := time.Now().Add(-tokenTTL)
			cleaned := 0
			for k, v := range s.entries {
				if v.createdAt.Before(cutoff) {
					delete(s.entries, k)
					cleaned++
				}
			}
			size := len(s.entries)
			s.mu.Unlock()
			if cleaned > 0 {
				logger.Info("TokenStore 清理过期 token: cleaned=%d remaining=%d", cleaned, size)
			} else {
				logger.Debug("TokenStore 定时扫描: no expired tokens, size=%d", size)
			}
		}
	}()
	return s
}

// Set 写入 token → resolverIP。若触发速率限制返回 false。
func (s *TokenStore) Set(token, resolverIP string) bool {
	s.rateMu.Lock()
	now := time.Now()
	if now.After(s.rateReset) {
		s.rateCount = make(map[string]int)
		s.rateReset = now.Add(rateWindowDur)
	}
	s.rateCount[resolverIP]++
	count := s.rateCount[resolverIP]
	s.rateMu.Unlock()

	if count > rateMaxPerIP {
		logger.Warn("速率限制: resolverIP=%s 本分钟写入 %d 次，丢弃 token=%s", resolverIP, count, token)
		return false
	}

	s.mu.Lock()
	s.entries[token] = tokenEntry{resolverIP: resolverIP, createdAt: now}
	s.mu.Unlock()
	return true
}

// Get 查询并一次性消费 token（读取即删除，double-check 防竞态）。
func (s *TokenStore) Get(token string) (string, bool) {
	// 第一次检查（读锁，性能优先）
	s.mu.RLock()
	_, ok := s.entries[token]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}

	// 升级为写锁，二次确认并删除（防止两个并发请求都消费同一 token）
	s.mu.Lock()
	e, ok := s.entries[token]
	if ok {
		delete(s.entries, token)
	}
	s.mu.Unlock()

	if !ok {
		return "", false
	}
	return e.resolverIP, true
}

func (s *TokenStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// ══════════════════════════════════════════════════════════
//  MaxMind GeoLite2 数据库
// ══════════════════════════════════════════════════════════

type geoDBReader struct {
	db *maxminddb.Reader
}

type maxmindRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
		Names   struct {
			ZhCN string `maxminddb:"zh-CN"`
		} `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names struct {
			ZhCN string `maxminddb:"zh-CN"`
		} `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names struct {
			ZhCN string `maxminddb:"zh-CN"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

var geoDB *geoDBReader

func initGeoDB(path string) error {
	db, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("打开 MaxMind 数据库失败: %v", err)
	}
	geoDB = &geoDBReader{db: db}
	logger.Info("MaxMind GeoLite2 数据库已加载: %s", path)
	return nil
}

func closeGeoDB() {
	if geoDB != nil && geoDB.db != nil {
		geoDB.db.Close()
	}
}

// ══════════════════════════════════════════════════════════
//  Geo 缓存
// ══════════════════════════════════════════════════════════

// specialRegionCodes 将特殊地区代码映射到正确的国家中文名
var specialRegionCodes = map[string]string{
	"HK": "中国香港",
	"TW": "中国台湾",
	"MO": "中国澳门",
}

type geoEntry struct {
	info     *GeoInfo
	cachedAt time.Time
}

const geoCacheTTL = 10 * time.Minute

type GeoCache struct {
	mu    sync.RWMutex
	cache map[string]geoEntry
}

func NewGeoCache() *GeoCache {
	g := &GeoCache{cache: make(map[string]geoEntry)}
	go func() {
		for range time.NewTicker(5 * time.Minute).C {
			g.mu.Lock()
			cutoff := time.Now().Add(-geoCacheTTL)
			cleaned := 0
			for k, v := range g.cache {
				if v.cachedAt.Before(cutoff) {
					delete(g.cache, k)
					cleaned++
				}
			}
			g.mu.Unlock()
			if cleaned > 0 {
				logger.Info("GeoCache 清理过期条目: cleaned=%d", cleaned)
			}
		}
	}()
	return g
}

func (g *GeoCache) Get(ip string) (*GeoInfo, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	e, ok := g.cache[ip]
	if !ok || time.Since(e.cachedAt) > geoCacheTTL {
		return nil, false
	}
	return e.info, true
}

func (g *GeoCache) Set(ip string, info *GeoInfo) {
	g.mu.Lock()
	g.cache[ip] = geoEntry{info: info, cachedAt: time.Now()}
	g.mu.Unlock()
}

// ══════════════════════════════════════════════════════════
//  DNS 协议实现（RFC 1035）
// ══════════════════════════════════════════════════════════

// parseQuery 解析 DNS 请求报文，提取事务ID、QNAME、QTYPE。
func parseQuery(buf []byte) (id uint16, qname string, qtype uint16, ok bool) {
	if len(buf) < 12 {
		return
	}
	id = binary.BigEndian.Uint16(buf[0:2])
	qdcount := binary.BigEndian.Uint16(buf[4:6])
	if qdcount == 0 {
		ok = true
		return
	}
	pos := 12
	var labels []string
	for pos < len(buf) {
		length := int(buf[pos])
		if length == 0 {
			pos++
			break
		}
		if length&0xC0 == 0xC0 {
			pos += 2
			break
		}
		pos++
		if pos+length > len(buf) {
			return
		}
		labels = append(labels, string(buf[pos:pos+length]))
		pos += length
	}
	if pos+4 > len(buf) {
		return
	}
	qname = strings.ToLower(strings.Join(labels, "."))
	qtype = binary.BigEndian.Uint16(buf[pos:])
	ok = true
	return
}

// encodeName 将点分域名编码为 DNS wire-format 标签序列。
func encodeName(name string) []byte {
	var b []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, []byte(label)...)
	}
	b = append(b, 0x00)
	return b
}

// buildReply 构造标准 DNS 响应报文（FLAGS: QR=1 AA=1 RCODE=0）。
func buildReply(id uint16, qname string, qtype uint16, aRecords []net.IP, nsNames []string) []byte {
	var h [12]byte
	binary.BigEndian.PutUint16(h[0:], id)
	binary.BigEndian.PutUint16(h[2:], 0x8400) // QR=1 AA=1
	binary.BigEndian.PutUint16(h[4:], 1)
	binary.BigEndian.PutUint16(h[6:], uint16(len(aRecords)+len(nsNames)))

	qnw := encodeName(qname)
	var qt [4]byte
	binary.BigEndian.PutUint16(qt[0:], qtype)
	binary.BigEndian.PutUint16(qt[2:], 1)

	buf := make([]byte, 0, 512)
	buf = append(buf, h[:]...)
	buf = append(buf, qnw...)
	buf = append(buf, qt[:]...)

	for _, ip := range aRecords {
		buf = append(buf, encodeName(qname)...)
		buf = append(buf, 0x00, 0x01, 0x00, 0x01)
		buf = append(buf, 0x00, 0x00, 0x00, 0x01) // TTL=1s，防解析器缓存
		buf = append(buf, 0x00, 0x04)
		buf = append(buf, ip.To4()...)
	}
	for _, ns := range nsNames {
		nw := encodeName(ns)
		buf = append(buf, encodeName(qname)...)
		buf = append(buf, 0x00, 0x02, 0x00, 0x01)
		buf = append(buf, 0x00, 0x00, 0x0E, 0x10) // TTL=3600s
		buf = append(buf, 0x00, byte(len(nw)))
		buf = append(buf, nw...)
	}
	return buf
}

// buildRefused 构造 REFUSED 响应（RCODE=5）。
// 用于拒绝非白名单域名的查询，告知对方"我没有权限回答这个问题"。
// 相比直接丢弃，REFUSED 能让对方解析器快速得知结果，而不是等到超时。
func buildRefused(id uint16, qname string, qtype uint16) []byte {
	var h [12]byte
	binary.BigEndian.PutUint16(h[0:], id)
	// FLAGS: QR=1(响应) AA=0(非权威，因为我们不负责此域) RCODE=5(REFUSED)
	binary.BigEndian.PutUint16(h[2:], 0x8005)
	binary.BigEndian.PutUint16(h[4:], 1) // QDCOUNT=1，回填问题节

	// 回填 Question 节（标准要求响应中包含原始问题）
	qnw := encodeName(qname)
	var qt [4]byte
	binary.BigEndian.PutUint16(qt[0:], qtype)
	binary.BigEndian.PutUint16(qt[2:], 1)

	buf := make([]byte, 0, 32)
	buf = append(buf, h[:]...)
	buf = append(buf, qnw...)
	buf = append(buf, qt[:]...)
	return buf
}

// ══════════════════════════════════════════════════════════
//  DNS 服务器
// ══════════════════════════════════════════════════════════

type DNSServer struct {
	cfg   *Config
	store *TokenStore
}

// handle 是 DNS 请求的核心路由。
//
// 处理顺序：
//  1. 解析报文，提取 qname / qtype
//  2. 白名单检查：qname 不属于任何允许区域 → REFUSED（并记录 Warn 日志）
//  3. 路由到具体记录类型处理
func (d *DNSServer) handle(data []byte, remoteAddr net.Addr) []byte {
	id, qname, qtype, ok := parseQuery(data)
	if !ok {
		logger.Warn("DNS 报文解析失败，来自 %s，丢弃", remoteAddr)
		return nil
	}
	if qname == "" {
		// 无问题节的合法报文，忽略即可
		logger.Debug("DNS 无问题节报文，来自 %s，忽略", remoteAddr)
		return nil
	}

	// ── 白名单检查 ────────────────────────────────────────────
	// 只处理属于已配置区域的查询，其他一律 REFUSED。
	// 防止：
	//   a. 本服务器被用作"开放解析器"转发任意查询
	//   b. 探测扫描/DDoS 利用本端口
	if !d.cfg.isAllowedZone(qname) {
		logger.Warn("域名白名单拒绝: qname=%s qtype=%d from=%s (allowed=%v)",
			qname, qtype, remoteAddr, d.cfg.AllowedZones)
		return buildRefused(id, qname, qtype)
	}

	// 白名单通过后的处理逻辑记录为 Debug（生产环境高频，不需要 Info）
	logger.Debug("DNS 查询: qname=%s qtype=%d from=%s", qname, qtype, remoteAddr)

	fqDomain := d.cfg.Domain
	suffix := "." + fqDomain
	serverIP := net.ParseIP(d.cfg.NSIP)

	switch {
	case qtype == 2 && qname == fqDomain:
		// NS 查询：返回权威名字服务器
		logger.Debug("DNS NS 响应: %s", qname)
		return buildReply(id, qname, qtype, nil,
			[]string{"ns1." + fqDomain, "ns2." + fqDomain})

	case qtype == 1 && (qname == "ns1."+fqDomain ||
		qname == "ns2."+fqDomain ||
		qname == fqDomain):
		// A 查询：NS 胶水记录或顶点域名
		logger.Debug("DNS A 响应 (glue/apex): %s -> %s", qname, d.cfg.NSIP)
		return buildReply(id, qname, qtype, []net.IP{serverIP}, nil)

	case qtype == 1 && strings.HasSuffix(qname, suffix):
		// A 查询：token 子域名 —— 核心探测路径
		token := strings.TrimSuffix(qname, suffix)

		resolverIP := remoteAddr.String()
		if h, _, err := net.SplitHostPort(resolverIP); err == nil {
			resolverIP = h
		}

		accepted := d.store.Set(token, resolverIP)
		if accepted {
			// token 成功捕获，用 Info 级别记录（有价值的业务事件）
			logger.Info("DNS 探测捕获: token=%s resolverIP=%s", token, resolverIP)
		}
		return buildReply(id, qname, qtype, []net.IP{serverIP}, nil)

	default:
		// 属于白名单区域但不认识的查询类型（如 AAAA、MX 等）→ NXDOMAIN
		logger.Debug("DNS NXDOMAIN: qname=%s qtype=%d", qname, qtype)
		var h [12]byte
		binary.BigEndian.PutUint16(h[0:], id)
		binary.BigEndian.PutUint16(h[2:], 0x8403) // QR=1 AA=1 RCODE=3
		return h[:]
	}
}

// ServeUDP 在 UDP 上监听 DNS 查询，每个请求独立 goroutine 处理。
func (d *DNSServer) ServeUDP() {
	pc, err := net.ListenPacket("udp", d.cfg.DNSPort)
	if err != nil {
		logger.Error("DNS-UDP 监听失败: %v", err)
		os.Exit(1)
	}
	defer pc.Close()
	logger.Info("DNS-UDP 监听 %s", d.cfg.DNSPort)

	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			logger.Warn("DNS-UDP 读取错误: %v", err)
			continue
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		go func(data []byte, a net.Addr) {
			if reply := d.handle(data, a); reply != nil {
				pc.WriteTo(reply, a)
			}
		}(msg, addr)
	}
}

// ServeTCP 在 TCP 上监听 DNS 查询（RFC 1035 §4.2.2，报文前 2 字节为长度前缀）。
func (d *DNSServer) ServeTCP() {
	ln, err := net.Listen("tcp", d.cfg.DNSPort)
	if err != nil {
		logger.Warn("DNS-TCP 监听失败: %v（仅 UDP 模式）", err)
		return
	}
	defer ln.Close()
	logger.Info("DNS-TCP 监听 %s", d.cfg.DNSPort)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go d.handleTCPConn(conn)
	}
}

func (d *DNSServer) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var lb [2]byte
	if _, err := conn.Read(lb[:]); err != nil {
		return
	}
	buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := conn.Read(buf); err != nil {
		return
	}
	reply := d.handle(buf, conn.RemoteAddr())
	if reply == nil {
		return
	}
	var rl [2]byte
	binary.BigEndian.PutUint16(rl[:], uint16(len(reply)))
	conn.Write(rl[:])
	conn.Write(reply)
}

// ══════════════════════════════════════════════════════════
//  IP 地理归属查询（ip-api.com，带本地缓存）
// ══════════════════════════════════════════════════════════

type GeoInfo struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	Query       string  `json:"query"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

// getGeoInfoCached 查询 IP 地理归属，优先命中本地缓存。
func getGeoInfoCached(ip string, cache *GeoCache) (*GeoInfo, error) {
	host := ip
	if h, _, err := net.SplitHostPort(ip); err == nil {
		host = h
	}
	if isPrivateIP(host) {
		return &GeoInfo{Query: host, Status: "success", Country: "本地", City: "私有网络"}, nil
	}

	if cached, ok := cache.Get(host); ok {
		logger.Debug("GeoCache 命中: ip=%s", host)
		return cached, nil
	}

	if geoDB == nil || geoDB.db == nil {
		logger.Warn("MaxMind 数据库未初始化: ip=%s", host)
		return nil, fmt.Errorf("MaxMind 数据库未初始化")
	}

	var record maxmindRecord
	err := geoDB.db.Lookup(net.ParseIP(host), &record)
	if err != nil {
		logger.Warn("MaxMind 查询失败: ip=%s err=%v", host, err)
		return nil, err
	}

	info := &GeoInfo{
		Query:       host,
		Status:      "success",
		CountryCode: record.Country.ISOCode,
		City:        record.City.Names.ZhCN,
		Lat:         record.Location.Latitude,
		Lon:         record.Location.Longitude,
	}

	// 处理特殊地区代码（香港、台湾、澳门）
	if mappedCountry, ok := specialRegionCodes[record.Country.ISOCode]; ok {
		info.Country = mappedCountry
	} else {
		info.Country = record.Country.Names.ZhCN
	}

	if len(record.Subdivisions) > 0 {
		info.RegionName = record.Subdivisions[0].Names.ZhCN
	}
	if info.Country == "" {
		info.Country = "未知"
	}
	if info.CountryCode == "" {
		info.CountryCode = "--"
	}
	if info.City == "" {
		info.City = "未知"
	}

	logger.Debug("GeoInfo 查询成功: ip=%s country=%s city=%s", host, info.Country, info.City)
	cache.Set(host, info)
	return info, nil
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
	} {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ══════════════════════════════════════════════════════════
//  HTTP 服务器
// ══════════════════════════════════════════════════════════

type InfoResponse struct {
	ClientIP    string   `json:"client_ip"`
	ClientGeo   *GeoInfo `json:"client_geo"`
	ResolverIP  string   `json:"resolver_ip,omitempty"`
	ResolverGeo *GeoInfo `json:"resolver_geo,omitempty"`
	Token       string   `json:"token"`
	Found       bool     `json:"found"`
}

type WebServer struct {
	cfg      *Config
	store    *TokenStore
	geoCache *GeoCache
}

// handleInfo 处理 /api/info?token=xxx。
// token 首次命中后立即从 Store 删除，防止重复消费。
func (w *WebServer) handleInfo(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Set("Content-Type", "application/json")

	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
		clientIP = xri
	} else if h, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = h
	}

	token := r.URL.Query().Get("token")
	resp := InfoResponse{ClientIP: clientIP, Token: token}

	if geo, err := getGeoInfoCached(clientIP, w.geoCache); err == nil {
		resp.ClientGeo = geo
	}

	if token != "" {
		if resolverIP, ok := w.store.Get(token); ok {
			resp.Found = true
			resp.ResolverIP = resolverIP
			logger.Info("HTTP 探测结果下发: token=%s clientIP=%s resolverIP=%s",
				token, clientIP, resolverIP)
			if geo, err := getGeoInfoCached(resolverIP, w.geoCache); err == nil {
				resp.ResolverGeo = geo
			}
		} else {
			logger.Debug("HTTP 轮询未命中: token=%s clientIP=%s", token, clientIP)
		}
	}

	json.NewEncoder(rw).Encode(resp)
}

func (w *WebServer) handleIndex(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(rw, r)
		return
	}
	data, err := os.ReadFile("index.html")
	if err != nil {
		logger.Error("读取 index.html 失败: %v", err)
		http.Error(rw, "index.html not found", 500)
		return
	}
	html := strings.ReplaceAll(string(data), "{{.Domain}}", w.cfg.Domain)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Write([]byte(html))
}

// handleProbe 返回 1×1 透明 PNG，触发浏览器发起 DNS 查询。
func (w *WebServer) handleProbe(rw http.ResponseWriter, r *http.Request) {
	png := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
		0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,
		0x54, 0x78, 0x9C, 0x62, 0x00, 0x01, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
		0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
		0x42, 0x60, 0x82,
	}
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Set("Content-Type", "image/png")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Write(png)
}

// handleStats 返回运行状态（建议生产环境加 IP 鉴权）。
func (w *WebServer) handleStats(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]any{
		"token_store_size": w.store.Len(),
		"allowed_zones":    w.cfg.AllowedZones,
		"log_level":        levelName[w.cfg.LogLevel],
		"time":             time.Now().Format(time.RFC3339),
	})
}

// ══════════════════════════════════════════════════════════
//  程序入口
// ══════════════════════════════════════════════════════════

func main() {
	cfg := buildConfig()

	// 初始化全局 logger（所有模块共享）
	logger = newLogger(cfg.LogLevel, os.Stdout)

	logger.Info("=== DNS Detector 启动 ===")
	logger.Info("域名        : %s", cfg.Domain)
	logger.Info("服务IP      : %s", cfg.NSIP)
	logger.Info("Web 端口    : %s", cfg.WebPort)
	logger.Info("DNS 端口    : %s", cfg.DNSPort)
	logger.Info("日志等级    : %s", levelName[cfg.LogLevel])
	logger.Info("DNS 白名单  : %v", cfg.AllowedZones)
	logger.Info("Token TTL   : %v", tokenTTL)
	logger.Info("速率限制    : %d token/min/resolverIP", rateMaxPerIP)
	logger.Info("Geo 缓存TTL : %v", geoCacheTTL)
	logger.Info("Geo 数据库  : %s", cfg.GeoDBPath)

	// 初始化 MaxMind GeoLite2 数据库
	if err := initGeoDB(cfg.GeoDBPath); err != nil {
		logger.Error("MaxMind 数据库初始化失败: %v", err)
		os.Exit(1)
	}
	defer closeGeoDB()

	store := NewTokenStore()
	geoCache := NewGeoCache()

	dnsServer := &DNSServer{cfg: cfg, store: store}
	go dnsServer.ServeUDP()
	go dnsServer.ServeTCP()

	webServer := &WebServer{cfg: cfg, store: store, geoCache: geoCache}
	mux := http.NewServeMux()
	mux.HandleFunc("/", webServer.handleIndex)
	mux.HandleFunc("/api/info", webServer.handleInfo)
	mux.HandleFunc("/probe.png", webServer.handleProbe)
	mux.HandleFunc("/api/stats", webServer.handleStats)

	logger.Info("HTTP 开始监听 %s", cfg.WebPort)
	if err := http.ListenAndServe(cfg.WebPort, mux); err != nil {
		logger.Error("HTTP 启动失败: %v", err)
		os.Exit(1)
	}
}
