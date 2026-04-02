# DNS 检测器 

根据代码梳理完整的功能列表：

---

## 核心功能

- **权威 DNS 服务器**：同时监听 UDP/TCP 53 端口，实现 RFC 1035 标准的权威应答（支持 A、NS、SOA、NXDOMAIN、REFUSED 响应类型）
- **DNS 探测机制**：前端生成随机 token，通过加载 `<token>.domain` 下的 1×1 透明 PNG 触发浏览器 DNS 查询，从权威 DNS 层捕获用户的递归解析器 IP
- **客户端 IP 获取**：HTTP 层获取用户真实出口 IP，兼容 Nginx/CDN 反代（优先读取 `X-Forwarded-For`、`X-Real-IP`）
- **IP 地理归属查询**：接入 ip-api.com 免费接口，返回国家、省份、城市、运营商、经纬度信息，支持中文
- **Web 前端**：内置单页应用，实时展示客户端 IP 与 DNS 解析器 IP 及归属地，含原理说明、流程图、探测进度条

---

## Token 机制

- **唯一性**：每次检测生成 12 位随机字母数字 token，碰撞概率极低
- **一次性消费**：token 被 HTTP 端读取后立即从内存删除，不可重复消费（double-check 锁防并发竞态）
- **自动过期**：未被消费的 token 存活上限为 **5 分钟**，后台每 1 分钟扫描清理一次
- **存储位置**：纯进程内存（`map[string]tokenEntry`），重启后丢失，不依赖外部存储

---

## 并发与安全

- **并发模型**：HTTP 每请求独立 goroutine，DNS UDP 每包独立 goroutine，DNS TCP 每连接独立 goroutine，理论支持数万级并发
- **并发安全**：TokenStore 使用 `sync.RWMutex` 读写锁，多读单写互不干扰，不存在 map 并发写 panic 风险
- **DNS 写入速率限制**：每个解析器 IP 每分钟最多写入 **60 个 token**，超出后丢弃并记录 Warn 日志，防止恶意构造随机查询打爆内存
- **域名白名单**：只响应属于配置区域的 DNS 查询，其他域名返回 REFUSED（RCODE=5），防止本服务器被用作开放解析器或 DDoS 反射

---

## 日志系统

- **四个等级**：DEBUG / INFO / WARN / ERROR，通过环境变量 `LOG_LEVEL` 配置
- **分级策略**：
    - DEBUG — 每条 DNS 查询详情、缓存命中、HTTP 轮询未命中
    - INFO — 启动参数、token 捕获、结果下发、定时清理统计
    - WARN — 速率限制触发、白名单拒绝、geo 查询失败
    - ERROR — 监听失败、文件读取失败等致命错误
- **底层实现**：基于标准库 `log.Logger`，带微秒级时间戳，输出到 stdout

---

## 地理信息缓存

- **目的**：ip-api.com 免费版限速 45 次/分钟，同一 IP（尤其是 8.8.8.8 等公共 DNS）会被多用户触发，缓存避免重复请求
- **缓存有效期**：**10 分钟**，过期后下次查询重新请求外部接口
- **后台清理**：每 5 分钟扫描一次，删除过期条目

---

## 配置（全部通过环境变量）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DNS_DOMAIN` | `dns.example.com` | 权威 DNS 区域（必填） |
| `NS_IP` | `1.2.3.4` | 服务器公网 IP（必填） |
| `WEB_PORT` | `:8080` | HTTP 监听端口 |
| `DNS_PORT` | `:53` | DNS 监听端口 |
| `LOG_LEVEL` | `info` | 日志等级（debug/info/warn/error） |
| `DNS_ALLOW_ZONES` | 空 | 追加白名单区域，逗号分隔 |

---

## 已知局限

- **不支持多实例**：TokenStore 在进程内存，水平扩展需替换为 Redis
- **重启丢失**：进行中的探测 token 随进程重启消失
- **DoH 场景**：用户开启 DNS over HTTPS 时，DNS 查询走加密通道，本工具只能捕获 DoH 提供商的出口 IP，无法得知用户真实配置的 DNS 服务器
- **ip-api.com 依赖**：地理归属依赖第三方免费接口，免费版 45 次/分钟，高并发生产环境建议替换为本地 MaxMind GeoLite2 数据库


## 项目结构

```
dns-detector/
├── main.go       # Go 后端（DNS 服务器 + Web 服务器）
├── index.html    # 前端页面
├── go.mod
├── Dockerfile
└── README.md
```

---

## 工作原理

```
用户浏览器
    │
    ├─① HTTP 请求 → 服务器:8080
    │   生成随机 token，页面加载
    │
    ├─② 浏览器加载图片: http://<token>.dns.yourdomain.com/probe.png
    │   这会触发 DNS 查询
    │
    ③ 用户的 DNS 解析器查询 <token>.dns.yourdomain.com
    │   → 到达 权威DNS服务器:53
    │   → 记录解析器 IP + token
    │
    └─④ 浏览器轮询 /api/info?token=<token>
        → 返回用户IP + DNS解析器IP + 地理信息
```

---

## 第一步：域名配置（必须）

需要一个自己的域名，假设是 `example.com`，用子域名 `dns.example.com` 作为权威区。

### 在域名注册商/DNS面板添加以下记录：

| 类型 | 名称 | 值 | 说明 |
|------|------|-----|------|
| A    | ns1.dns | `服务器的IP` | NS1 解析 |
| A    | ns2.dns | `服务器的IP` | NS2 解析（可同IP）|
| NS   | dns    | ns1.dns.example.com | 委派权威DNS |
| NS   | dns    | ns2.dns.example.com | 委派权威DNS |

> ⚠️ 这里关键是 **NS 记录**，让 `dns.example.com` 这个子域名的权威服务器
> 指向自己的服务器。这样当有人查询 `xxx.dns.example.com` 时，
> 查询就会打到服务器上。

---

## 第二步：服务器配置

服务器需要开放端口：
- `53/UDP`（DNS）
- `53/TCP`（DNS）
- `8080/TCP`（Web，或用 Nginx 反代到 80/443）

### 方式一：Docker 部署（推荐）

```bash
# 构建镜像
docker build -t dns-detector .

# 运行（替换为实际值）
docker run -d \
  --name dns-detector \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8080:8080 \
  -e DNS_DOMAIN=dns.example.com \
  -e LOG_LEVEL=debug \
  -e NS_IP=1.2.3.4 \
  -e WEB_PORT=:8080 \
  -e DNS_PORT=:53 \
  --restart unless-stopped \
  dns-detector
```

### 方式二：直接运行

```bash
# 安装 Go 1.21+
go mod tidy
go build -o dns-detector .

# 运行（需要 root 权限绑定 53 端口）
DNS_DOMAIN=dns.example.com NS_IP=1.2.3.4 WEB_PORT=:8080 DNS_PORT=:53 \
  sudo ./dns-detector
```

---

## 第三步：Nginx 反代（可选，推荐）

如果想用 80/443 端口：

```nginx
server {
    listen 80;
    server_name dns.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

---

## 验证是否成功

```bash
# 测试 DNS 是否正常工作
dig @服务器IP test123.dns.example.com A

# 期望看到返回服务器IP
```

访问 `http://dns.example.com:8080` 查看效果。

---

## 常见问题

**Q: 53 端口被占用？**
```bash
# Ubuntu 禁用 systemd-resolved
sudo systemctl disable --now systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
```

**Q: DNS 解析器未能捕获？**
- 部分浏览器（如 Chrome）使用 DNS over HTTPS，不走传统 DNS
- 可以让用户关闭 "使用安全DNS" 设置
- 或者在说明中告知这是正常现象

**Q: ip-api.com 限速？**
- 免费版每分钟 45 次请求
- 可自行接入其他地理IP库（MaxMind GeoLite2 等）
