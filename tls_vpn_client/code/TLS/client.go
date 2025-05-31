package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/songgao/water"
)

// 日志级别常量
const (
	LogLevelNone    = 0
	LogLevelError   = 1
	LogLevelInfo    = 2
	LogLevelVerbose = 3
)

type VPNClient struct {
	serverAddr string
	status     string
	iface      *water.Interface
	conn       *tls.Conn
	logs       []string

	// 日志控制
	logMutex   sync.Mutex
	logEnabled bool
	logLevel   int // 0: 无日志, 1: 错误, 2: 信息, 3: 详细

	// 日志采样控制
	logSampleRate int // 日志采样率，数值越大记录越少（如10表示每10个包记录1个）

	// 数据统计
	statsMutex         sync.RWMutex
	bytesReceived      uint64    // 接收的总字节数
	bytesSent          uint64    // 发送的总字节数
	packetsReceived    uint64    // 接收的数据包数
	packetsSent        uint64    // 发送的数据包数
	lastStatsUpdate    time.Time // 上次更新统计信息的时间
	rxSpeed            float64   // 接收速度 (Mbps)
	txSpeed            float64   // 发送速度 (Mbps)
	totalRxBytes       uint64    // 累计接收字节数（不重置）
	totalTxBytes       uint64    // 累计发送字节数（不重置）
	statsUpdateCounter uint64    // 统计更新计数器，用于控制日志频率

	// 当前会话信息
	sessionStart time.Time
	isActive     bool

	// 统计定期更新控制
	statsUpdateInterval time.Duration

	// 缓冲区重用池
	bufferPool sync.Pool

	// 流量控制
	maxRxSpeed float64 // 最大接收速度限制（Mbps，0表示不限制）
	maxTxSpeed float64 // 最大发送速度限制（Mbps，0表示不限制）
}

func NewVPNClient() *VPNClient {
	client := &VPNClient{
		serverAddr:          "10.37.129.4:443",
		status:              "未连接",
		logs:                make([]string, 0, 100), // 预分配容量
		logLevel:            LogLevelInfo,           // 默认信息级别，方便观察性能
		logEnabled:          true,
		logSampleRate:       50,                        // 增加采样率，减少日志记录
		statsUpdateInterval: 1 * time.Second,          // 1秒更新一次统计
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 1500) // 标准MTU大小
			},
		},
	}

	return client
}

// 改进的日志函数，支持日志级别
func (v *VPNClient) log(level int, message string) {
	if !v.logEnabled || level > v.logLevel {
		return
	}

	v.logMutex.Lock()
	defer v.logMutex.Unlock()

	logEntry := time.Now().Format("2006/01/02 15:04:05") + " " + message
	v.logs = append(v.logs, logEntry)

	// 直接输出到控制台
	fmt.Println(logEntry)

	// 限制日志长度，防止内存无限增长
	if len(v.logs) > 100 {
		v.logs = v.logs[len(v.logs)-100:]
	}
}

func (v *VPNClient) Connect() error {
	v.status = "连接中..."
	v.log(LogLevelInfo, "正在连接到服务器: "+v.serverAddr)

	// 重置所有计数器
	atomic.StoreUint64(&v.bytesSent, 0)
	atomic.StoreUint64(&v.bytesReceived, 0)
	atomic.StoreUint64(&v.packetsSent, 0)
	atomic.StoreUint64(&v.packetsReceived, 0)
	atomic.StoreUint64(&v.totalTxBytes, 0)
	atomic.StoreUint64(&v.totalRxBytes, 0)
	v.statsUpdateCounter = 0

	v.statsMutex.Lock()
	v.rxSpeed = 0
	v.txSpeed = 0
	v.statsMutex.Unlock()

	config := water.Config{DeviceType: water.TUN}
	iface, err := water.New(config)
	if err != nil {
		v.log(LogLevelError, "创建TUN接口失败: "+err.Error())
		v.status = "连接失败"
		return err
	}
	v.iface = iface
	v.log(LogLevelInfo, "TUN接口创建成功: "+iface.Name())

	// 配置TUN接口
	exec.Command("ip", "addr", "add", "10.0.0.2/24", "dev", iface.Name()).Run()
	exec.Command("ip", "link", "set", "dev", iface.Name(), "up").Run()
	exec.Command("ip", "route", "add", "default", "via", "10.0.0.1", "dev", iface.Name()).Run()
	v.log(LogLevelInfo, "TUN接口配置完成")

	// 加载CA证书
	rootCA, err := os.ReadFile("../../cert/ca.crt")
	if err != nil {
		v.log(LogLevelError, "读取CA证书失败: "+err.Error())
		v.status = "连接失败"
		return err
	}

	// 创建CA证书池
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(rootCA) {
		v.log(LogLevelError, "解析CA证书失败")
		v.status = "连接失败"
		return fmt.Errorf("解析CA证书失败")
	}

	// 加载客户端证书
	clientCert, err := tls.LoadX509KeyPair("../../cert/client.crt", "../../cert/client.key")
	if err != nil {
		v.log(LogLevelError, "加载客户端证书失败: "+err.Error())
		v.status = "连接失败"
		return err
	}

	// 建立TLS连接
	tlsConfig := &tls.Config{
		RootCAs:            certPool,                    // 用于验证服务器证书的CA
		Certificates:       []tls.Certificate{clientCert}, // 客户端证书
		InsecureSkipVerify: false,                       // 启用证书验证
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
	conn, err := tls.Dial("tcp", v.serverAddr, tlsConfig)
	if err != nil {
		v.log(LogLevelError, "连接服务器失败: "+err.Error())
		v.status = "连接失败"
		return err
	}
	v.conn = conn
	v.log(LogLevelInfo, "成功连接到VPN服务器")

	// 初始化统计信息
	v.sessionStart = time.Now()
	v.lastStatsUpdate = time.Now()
	v.isActive = true

	// 开始定期更新统计信息
	go func() {
		ticker := time.NewTicker(v.statsUpdateInterval)
		defer ticker.Stop()

		for v.isActive {
			select {
			case <-ticker.C:
				v.updateStats()
			}
		}
	}()

	// 启动数据转发
	go v.forwardData()

	v.status = "已连接"
	v.log(LogLevelInfo, "VPN连接建立成功，开始数据转发")
	return nil
}

func (v *VPNClient) Disconnect() {
	v.status = "断开中..."
	v.log(LogLevelInfo, "正在断开VPN连接")

	// 停止统计更新
	v.isActive = false

	if v.conn != nil {
		v.conn.Close()
		v.conn = nil
		v.log(LogLevelInfo, "已关闭服务器连接")
	}

	if v.iface != nil {
		v.iface.Close()
		v.iface = nil
		v.log(LogLevelInfo, "已关闭TUN接口")
	}

	v.status = "已断开"
	v.log(LogLevelInfo, "VPN连接已断开")
}

func (v *VPNClient) forwardData() {
	// 从TUN读取并发送到服务器
	go func() {
		// 使用对象池获取缓冲区
		buf := v.bufferPool.Get().([]byte)
		// 确保函数退出时将缓冲区放回池中
		defer v.bufferPool.Put(buf)

		// 数据包计数器，用于日志采样
		var packetCounter uint64

		for v.conn != nil && v.isActive {
			n, err := v.iface.Read(buf)
			if err != nil {
				v.log(LogLevelError, "从TUN读取失败: "+err.Error())
				continue
			}

			// 流量控制（如果启用）
			if v.maxTxSpeed > 0 {
				v.statsMutex.RLock()
				currentSpeed := v.txSpeed
				v.statsMutex.RUnlock()

				if currentSpeed > v.maxTxSpeed {
					// 简单延迟，降低发送速率
					time.Sleep(10 * time.Millisecond)
				}
			}

			_, err = v.conn.Write(buf[:n])
			if err != nil {
				v.log(LogLevelError, "发送到服务器失败: "+err.Error())
				continue
			}

			// 记录数据包但不生成详细日志
			v.recordSent(n)

			// 使用采样率控制日志生成
			packetCounter++
			if v.logLevel >= LogLevelVerbose && packetCounter%uint64(v.logSampleRate) == 0 {
				v.log(LogLevelVerbose, "发送 "+strconv.Itoa(n)+" 字节到服务器")
			}
		}
	}()

	// 从服务器读取并写回TUN
	// 使用对象池获取缓冲区
	buf := v.bufferPool.Get().([]byte)
	// 确保函数退出时将缓冲区放回池中
	defer v.bufferPool.Put(buf)

	// 数据包计数器，用于日志采样
	var packetCounter uint64

	for v.conn != nil && v.isActive {
		n, err := v.conn.Read(buf)
		if err != nil {
			v.log(LogLevelError, "从服务器读取失败: "+err.Error())
			continue
		}

		// 流量控制（如果启用）
		if v.maxRxSpeed > 0 {
			v.statsMutex.RLock()
			currentSpeed := v.rxSpeed
			v.statsMutex.RUnlock()

			if currentSpeed > v.maxRxSpeed {
				// 简单延迟，降低接收处理速率
				time.Sleep(10 * time.Millisecond)
			}
		}

		_, err = v.iface.Write(buf[:n])
		if err != nil {
			v.log(LogLevelError, "写回TUN失败: "+err.Error())
			continue
		}

		// 记录数据包但不生成详细日志
		v.recordReceived(n)

		// 使用采样率控制日志生成
		packetCounter++
		if v.logLevel >= LogLevelVerbose && packetCounter%uint64(v.logSampleRate) == 0 {
			v.log(LogLevelVerbose, "写回 "+strconv.Itoa(n)+" 字节到TUN")
		}
	}
}

// 更新统计信息
func (v *VPNClient) updateStats() {
	v.statsMutex.Lock()
	defer v.statsMutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(v.lastStatsUpdate).Seconds()

	if elapsed > 0 && v.lastStatsUpdate.Unix() > 0 {
		// 计算传输速度 (Mbps)
		sentSinceLastUpdate := float64(atomic.LoadUint64(&v.bytesSent))
		receivedSinceLastUpdate := float64(atomic.LoadUint64(&v.bytesReceived))

		v.txSpeed = (sentSinceLastUpdate * 8) / (elapsed * 1000000)
		v.rxSpeed = (receivedSinceLastUpdate * 8) / (elapsed * 1000000)

		// 生成统计信息日志
		if v.isActive && v.logLevel >= LogLevelInfo {
			// 更新计数器并取模判断是否需要记录日志
			v.statsUpdateCounter++

			totalSpeed := v.txSpeed + v.rxSpeed
			if totalSpeed > 0.1 || v.statsUpdateCounter%5 == 0 { // 降低日志频率
				fmt.Printf("\r[统计] 速度: ↑%.2f Mbps ↓%.2f Mbps | 总计: ↑%s ↓%s | 连接时长: %s",
					v.txSpeed, v.rxSpeed,
					formatBytes(atomic.LoadUint64(&v.totalTxBytes)),
					formatBytes(atomic.LoadUint64(&v.totalRxBytes)),
					formatDuration(time.Since(v.sessionStart)))
			}
		}
	}

	v.lastStatsUpdate = now

	// 重置计数器用于下次计算速度
	atomic.StoreUint64(&v.bytesSent, 0)
	atomic.StoreUint64(&v.bytesReceived, 0)
}

// 格式化字节数为可读形式
func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// 添加速度跟踪函数
func (v *VPNClient) recordSent(bytes int) {
	atomic.AddUint64(&v.bytesSent, uint64(bytes))
	atomic.AddUint64(&v.packetsSent, 1)
	atomic.AddUint64(&v.totalTxBytes, uint64(bytes)) // 累计总字节数
}

func (v *VPNClient) recordReceived(bytes int) {
	atomic.AddUint64(&v.bytesReceived, uint64(bytes))
	atomic.AddUint64(&v.packetsReceived, 1)
	atomic.AddUint64(&v.totalRxBytes, uint64(bytes)) // 累计总字节数
}

// 格式化持续时间为可读形式
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%d时%d分%d秒", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%d分%d秒", m, s)
	}
	return fmt.Sprintf("%d秒", s)
}

// 设置日志级别
func (v *VPNClient) SetLogLevel(level int) {
	v.logLevel = level
}

// 获取当前状态
func (v *VPNClient) GetStatus() string {
	return v.status
}

func main() {
	fmt.Println("VPN客户端 - 无UI版本")
	fmt.Println("使用 Ctrl+C 退出程序")
	fmt.Println("========================")

	vpnClient := NewVPNClient()

	// 设置信号处理
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// 连接VPN
	if err := vpnClient.Connect(); err != nil {
		fmt.Printf("连接失败: %v\n", err)
		os.Exit(1)
	}

	// 等待中断信号
	<-c
	fmt.Println("\n\n收到退出信号，正在断开连接...")

	// 断开连接
	vpnClient.Disconnect()

	fmt.Println("程序已退出")
}
