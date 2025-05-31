package main

import (
        "crypto/tls"
        "crypto/x509"
        "fmt"
        "os"
        "os/exec"
        "strconv"
        "strings"
        "sync"
        "sync/atomic"
        "time"
        "math"

        "image/color"

        "fyne.io/fyne/v2"
        "fyne.io/fyne/v2/app"
        "fyne.io/fyne/v2/canvas"
        "fyne.io/fyne/v2/container"
        "fyne.io/fyne/v2/widget"
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
        logSampleRate  int // 日志采样率，数值越大记录越少（如10表示每10个包记录1个）
        
        // 数据统计
        statsMutex       sync.RWMutex
        bytesReceived    uint64 // 接收的总字节数
        bytesSent        uint64 // 发送的总字节数
        packetsReceived  uint64 // 接收的数据包数
        packetsSent      uint64 // 发送的数据包数
        lastStatsUpdate  time.Time // 上次更新统计信息的时间
        rxSpeed          float64 // 接收速度 (Mbps)
        txSpeed          float64 // 发送速度 (Mbps)
        totalRxBytes     uint64 // 累计接收字节数（不重置）
        totalTxBytes     uint64 // 累计发送字节数（不重置）
        statsUpdateCounter uint64 // 统计更新计数器，用于控制日志频率
        
        // 当前会话信息
        sessionStart time.Time
        isActive     bool
        
        // 统计定期更新控制
        statsUpdateInterval time.Duration
        
        // UI更新控制
        uiUpdateLock      sync.Mutex
        uiUpdateThreshold float64 // UI更新阈值（Mbps），流量低于此值时降低UI更新频率
        
        // 缓冲区重用池
        bufferPool        sync.Pool
        
        // 流量控制
        maxRxSpeed        float64 // 最大接收速度限制（Mbps，0表示不限制）
        maxTxSpeed        float64 // 最大发送速度限制（Mbps，0表示不限制）
        
        // TLS握手测试相关
        tlsHandshakeTimes []time.Duration // 记录每次TLS握手的时间
        tlsTestRunning    bool            // 测试是否正在运行
        tlsTestProgress   int             // 当前测试进度
        tlsTestTotal      int             // 总测试次数
        tlsTestResults    struct {        // 测试结果统计
            avgTime   time.Duration       // 平均时间
            minTime   time.Duration       // 最小时间
            maxTime   time.Duration       // 最大时间
            stdDev    time.Duration       // 标准差
        }
        tlsTestMutex      sync.Mutex      // 测试数据访问互斥锁
}

func NewVPNClient() *VPNClient {
        client := &VPNClient{
                serverAddr: "10.37.129.4:443",
                status:     "未连接",
                logs:       make([]string, 0, 100), // 预分配容量
                logLevel:   LogLevelError,          // 默认只记录错误，降低CPU使用
                logEnabled: true,
                logSampleRate: 20,                  // 每20个包采样一次日志
                statsUpdateInterval: 2 * time.Second, // 降低统计更新频率
                uiUpdateThreshold: 0.5,             // 低于0.5Mbps时降低UI更新频率
                bufferPool: sync.Pool{
                        New: func() interface{} {
                                return make([]byte, 1500) // 标准MTU大小
                        },
                },
                // 初始化TLS握手测试相关字段
                tlsHandshakeTimes: make([]time.Duration, 0),
                tlsTestRunning: false,
                tlsTestProgress: 0,
                tlsTestTotal: 0,
        }
        
        // 初始化测试结果字段
        client.tlsTestResults.minTime = 0
        client.tlsTestResults.maxTime = 0
        client.tlsTestResults.avgTime = 0
        client.tlsTestResults.stdDev = 0
        
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
    
    // 限制日志长度，防止内存无限增长
    if len(v.logs) > 100 {
        v.logs = v.logs[len(v.logs)-100:]
    }
}

func (v *VPNClient) Connect() {
        v.status = "连接中..."
        v.log(LogLevelInfo, "正在连接到服务器: " + v.serverAddr)
        
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
                v.log(LogLevelError, "创建TUN接口失败: " + err.Error())
                v.status = "连接失败"
                return
        }
        v.iface = iface
        v.log(LogLevelInfo, "TUN接口创建成功: " + iface.Name())

        // 配置TUN接口
        exec.Command("ip", "addr", "add", "10.0.0.2/24", "dev", iface.Name()).Run()
        exec.Command("ip", "link", "set", "dev", iface.Name(), "up").Run()
        exec.Command("ip", "route", "add", "default", "via", "10.0.0.1", "dev", iface.Name()).Run()
        v.log(LogLevelInfo, "TUN接口配置完成")

        // 加载CA证书
        rootCA, err := os.ReadFile("../../cert/ca.crt")
        if err != nil {
            v.log(LogLevelError, "读取CA证书失败: " + err.Error())
            v.status = "连接失败"
            return
        }

        // 创建CA证书池
        certPool := x509.NewCertPool()
        if !certPool.AppendCertsFromPEM(rootCA) {
            v.log(LogLevelError, "解析CA证书失败")
            v.status = "连接失败"
            return
        }

        // 加载客户端证书
        clientCert, err := tls.LoadX509KeyPair("../../cert/client.crt", "../../cert/client.key")
        if err != nil {
            v.log(LogLevelError, "加载客户端证书失败: " + err.Error())
            v.status = "连接失败"
            return
        }

        // 建立TLS连接
        tlsConfig := &tls.Config{
            RootCAs:            certPool,            // 用于验证服务器证书的CA
            Certificates:       []tls.Certificate{clientCert}, // 客户端证书
            InsecureSkipVerify: false,               // 启用证书验证
            MinVersion:         tls.VersionTLS13,
            MaxVersion:         tls.VersionTLS13,
            CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
        }
        conn, err := tls.Dial("tcp", v.serverAddr, tlsConfig)
        if err != nil {
                v.log(LogLevelError, "连接服务器失败: " + err.Error())
                v.status = "连接失败"
                return
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
                                v.log(LogLevelError, "从TUN读取失败: " + err.Error())
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
                                v.log(LogLevelError, "发送到服务器失败: " + err.Error())
                                continue
                        }
                        
                        // 记录数据包但不生成详细日志
                        v.recordSent(n)
                        
                        // 使用采样率控制日志生成
                        packetCounter++
                        if v.logLevel >= LogLevelVerbose && packetCounter % uint64(v.logSampleRate) == 0 {
                            v.log(LogLevelVerbose, "发送 " + strconv.Itoa(n) + " 字节到服务器")
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
                        v.log(LogLevelError, "从服务器读取失败: " + err.Error())
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
                        v.log(LogLevelError, "写回TUN失败: " + err.Error())
                        continue
                }
                
                // 记录数据包但不生成详细日志
                v.recordReceived(n)
                
                // 使用采样率控制日志生成
                packetCounter++
                if v.logLevel >= LogLevelVerbose && packetCounter % uint64(v.logSampleRate) == 0 {
                    v.log(LogLevelVerbose, "写回 " + strconv.Itoa(n) + " 字节到TUN")
                }
        }
}

// 自定义文本小部件
type ColoredTextWidget struct {
        widget.Entry
        textColor color.Color
}

func NewColoredTextWidget() *ColoredTextWidget {
        w := &ColoredTextWidget{}
        w.ExtendBaseWidget(w)
        w.MultiLine = true
        w.Wrapping = fyne.TextWrapWord
        return w
}

func (w *ColoredTextWidget) SetTextColor(c color.Color) {
        w.textColor = c
        w.Refresh()
}

func (w *ColoredTextWidget) CreateRenderer() fyne.WidgetRenderer {
        r := w.Entry.CreateRenderer()
        return &coloredTextRenderer{WidgetRenderer: r, ctw: w}
}

type coloredTextRenderer struct {
        fyne.WidgetRenderer
        ctw *ColoredTextWidget
}

func (r *coloredTextRenderer) Refresh() {
        r.WidgetRenderer.Refresh()
        if text, ok := r.WidgetRenderer.Objects()[0].(*canvas.Text); ok {
                text.Color = r.ctw.textColor
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
        
        // 低流量时减少日志记录频率，节省资源
        totalSpeed := v.txSpeed + v.rxSpeed
        
        // 生成统计信息日志 - 根据流量大小和日志级别决定是否记录
        if v.isActive && v.logLevel >= LogLevelInfo {
            // 更新计数器并取模判断是否需要记录日志
            v.statsUpdateCounter++
            
            if totalSpeed > 1.0 || v.statsUpdateCounter % 10 == 0 {
                v.log(LogLevelInfo, fmt.Sprintf("统计: ↑%.2f Mbps ↓%.2f Mbps, 总计: ↑%s ↓%s",
                    v.txSpeed, v.rxSpeed,
                    formatBytes(atomic.LoadUint64(&v.totalTxBytes)),
                    formatBytes(atomic.LoadUint64(&v.totalRxBytes))))
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

func main() {
        myApp := app.New()
        myWindow := myApp.NewWindow("VPN客户端")

        vpnClient := NewVPNClient()

        serverEntry := widget.NewEntry()
        serverEntry.SetText(vpnClient.serverAddr)

        statusLabel := widget.NewLabel(vpnClient.status)
        
        // 统计信息标签
        statsLabel := widget.NewLabel("未连接")
        
        // 日志级别选择器
        logLevelSelect := widget.NewSelect(
            []string{"无日志", "仅错误", "一般信息", "详细信息"}, 
            func(level string) {
                switch level {
                case "无日志":
                    vpnClient.logLevel = LogLevelNone
                case "仅错误":
                    vpnClient.logLevel = LogLevelError
                case "一般信息":
                    vpnClient.logLevel = LogLevelInfo
                case "详细信息":
                    vpnClient.logLevel = LogLevelVerbose
                }
            })
        logLevelSelect.SetSelected("一般信息") // 默认选择
        
        connectBtn := widget.NewButton("连接", func() {
                vpnClient.serverAddr = serverEntry.Text
                vpnClient.Connect()
                statusLabel.SetText(vpnClient.status)
        })

        disconnectBtn := widget.NewButton("断开", func() {
                vpnClient.Disconnect()
                statusLabel.SetText(vpnClient.status)
                statsLabel.SetText("未连接")
        })
        
        // TLS握手测试相关UI
        testTimesEntry := widget.NewEntry()
        testTimesEntry.SetText("10") // 默认测试10次
        testTimesEntry.SetPlaceHolder("输入测试次数")
        
        testResultLabel := widget.NewLabel("未进行测试")
        
        // 先声明按钮变量，不附加处理函数
        testBtn := widget.NewButton("测试TLS握手", nil)
        
        // 然后单独设置按钮的处理函数
        testBtn.OnTapped = func() {
            // 获取测试次数
            times, err := strconv.Atoi(testTimesEntry.Text)
            if err != nil || times <= 0 {
                testResultLabel.SetText("请输入有效的测试次数")
                return
            }
            
            // 检查是否正在测试中
            vpnClient.tlsTestMutex.Lock()
            isRunning := vpnClient.tlsTestRunning
            vpnClient.tlsTestMutex.Unlock()
            
            if isRunning {
                testResultLabel.SetText("测试已在进行中，请等待当前测试完成")
                return
            }
            
            // 更新服务器地址
            vpnClient.serverAddr = serverEntry.Text
            
            // 开始测试
            vpnClient.TestTLSHandshake(times, testResultLabel)
            
            // 禁用测试按钮，直到测试完成
            testBtn.Disable()
            
            // 启动一个goroutine等待测试完成并重新启用按钮
            go func() {
                for {
                    vpnClient.tlsTestMutex.Lock()
                    running := vpnClient.tlsTestRunning
                    vpnClient.tlsTestMutex.Unlock()
                    
                    if !running {
                        testBtn.Enable()
                        break
                    }
                    
                    time.Sleep(500 * time.Millisecond)
                }
            }()
        }

        logText := NewColoredTextWidget()
        logText.SetText("VPN客户端日志:\n")
        logText.TextStyle = fyne.TextStyle{Monospace: true}
        logText.SetTextColor(color.NRGBA{R: 0, G: 0, B: 255, A: 255}) // 蓝色文本
        logScroll := container.NewScroll(logText)
        logScroll.SetMinSize(fyne.NewSize(380, 150))

        // 定时更新UI
        go func() {
            // 日志更新计时器 - 降低默认更新频率
            logUpdateTicker := time.NewTicker(1 * time.Second)
            defer logUpdateTicker.Stop()
            
            // 统计信息更新计时器 - 降低默认更新频率
            statsUpdateTicker := time.NewTicker(2 * time.Second)
            defer statsUpdateTicker.Stop()
            
            // 自适应UI更新计时器控制
            var lowTrafficMode bool
            var lastLogCount int
            var lastUIUpdate time.Time = time.Now()
            
            for {
                select {
                case <-logUpdateTicker.C:
                    // 只在有新日志时更新UI，减少不必要的重绘
                    vpnClient.logMutex.Lock()
                    currentLogCount := len(vpnClient.logs)
                    hasNewLogs := currentLogCount > 0 && currentLogCount != lastLogCount
                    logContent := ""
                    
                    if hasNewLogs {
                        logContent = "VPN客户端日志:\n" + strings.Join(vpnClient.logs, "\n")
                        lastLogCount = currentLogCount
                    }
                    vpnClient.logMutex.Unlock()
                    
                    // 只在有新日志时才更新UI
                    if hasNewLogs {
                        logText.SetText(logContent)
                    }
                    
                case <-statsUpdateTicker.C:
                    // 更新统计信息 - 根据流量情况调整更新频率
                    if vpnClient.isActive {
                        vpnClient.statsMutex.RLock()
                        currentSpeed := vpnClient.rxSpeed + vpnClient.txSpeed
                        stats := fmt.Sprintf("速度: ↑%.2f Mbps ↓%.2f Mbps | 总计: ↑%s ↓%s | 已连接: %s",
                            vpnClient.txSpeed, 
                            vpnClient.rxSpeed,
                            formatBytes(atomic.LoadUint64(&vpnClient.totalTxBytes)),
                            formatBytes(atomic.LoadUint64(&vpnClient.totalRxBytes)),
                            formatDuration(time.Since(vpnClient.sessionStart)))
                        vpnClient.statsMutex.RUnlock()
                        
                        // 自适应UI更新：低流量时降低更新频率
                        updateUI := true
                        
                        // 检查流量情况
                        if currentSpeed < vpnClient.uiUpdateThreshold {
                            // 低流量模式，减少UI更新频率
                            if !lowTrafficMode {
                                // 切换到低流量模式
                                lowTrafficMode = true
                                // 调整ticker频率
                                statsUpdateTicker.Reset(5 * time.Second)
                            }
                            
                            // 在低流量模式下，只有当距离上次更新至少3秒才更新UI
                            if time.Since(lastUIUpdate) < 3*time.Second {
                                updateUI = false
                            }
                        } else {
                            // 高流量模式
                            if lowTrafficMode {
                                // 切换回正常模式
                                lowTrafficMode = false
                                // 恢复正常更新频率
                                statsUpdateTicker.Reset(2 * time.Second)
                            }
                        }
                        
                        // 只在需要时更新UI
                        if updateUI {
                            statsLabel.SetText(stats)
                            lastUIUpdate = time.Now()
                        }
                    }
                }
            }
        }()
        
        // 创建TLS握手测试区域
        testArea := container.NewVBox(
            widget.NewLabel("TLS握手测试:"),
            container.NewHBox(
                widget.NewLabel("测试次数:"),
                testTimesEntry,
                testBtn,
            ),
            testResultLabel,
        )

        content := container.NewVBox(
                widget.NewLabel("服务器地址:"),
                serverEntry,
                container.NewHBox(connectBtn, disconnectBtn),
                statusLabel,
                widget.NewLabel("统计信息:"),
                statsLabel,
                widget.NewLabel("日志级别:"),
                logLevelSelect,
                widget.NewLabel("日志输出:"),
                logScroll,
                testArea, // 添加TLS握手测试区域
        )

        myWindow.SetContent(content)
        myWindow.Resize(fyne.NewSize(400, 550)) // 略微增加窗口高度以适应新控件
        myWindow.ShowAndRun()
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

// 格式化毫秒级持续时间为可读形式
func formatMilliseconds(d time.Duration) string {
    return fmt.Sprintf("%.2f毫秒", float64(d.Microseconds()) / 1000.0)
}

// 测量单次TLS握手时间
func (v *VPNClient) measureTLSHandshake() (time.Duration, error) {
    // 加载CA证书
    rootCA, err := os.ReadFile("../../cert/ca.crt")
    if err != nil {
        v.log(LogLevelError, "读取CA证书失败: " + err.Error())
        return 0, err
    }

    // 创建CA证书池
    certPool := x509.NewCertPool()
    if !certPool.AppendCertsFromPEM(rootCA) {
        v.log(LogLevelError, "解析CA证书失败")
        return 0, fmt.Errorf("解析CA证书失败")
    }

    // 加载客户端证书
    clientCert, err := tls.LoadX509KeyPair("../../cert/client.crt", "../../cert/client.key")
    if err != nil {
        v.log(LogLevelError, "加载客户端证书失败: " + err.Error())
        return 0, err
    }

    // 配置TLS
    tlsConfig := &tls.Config{
        RootCAs:            certPool,                 // 用于验证服务器证书的CA
        Certificates:       []tls.Certificate{clientCert}, // 客户端证书
        InsecureSkipVerify: false,                    // 启用证书验证
        MinVersion:         tls.VersionTLS13,
        MaxVersion:         tls.VersionTLS13,
    }
    
    // 记录开始时间
    startTime := time.Now()
    
    // 执行TLS握手
    conn, err := tls.Dial("tcp", v.serverAddr, tlsConfig)
    if err != nil {
        v.log(LogLevelError, "TLS握手失败: " + err.Error())
        return 0, err
    }
    
    // 计算握手时间
    handshakeTime := time.Since(startTime)
    
    // 关闭连接
    conn.Close()
    
    return handshakeTime, nil
}

// 执行多次TLS握手测试并计算统计数据
func (v *VPNClient) TestTLSHandshake(times int, resultLabel *widget.Label) {
    // 防止并发测试
    v.tlsTestMutex.Lock()
    if v.tlsTestRunning {
        v.tlsTestMutex.Unlock()
        return
    }
    
    // 初始化测试状态
    v.tlsTestRunning = true
    v.tlsTestTotal = times
    v.tlsTestProgress = 0
    v.tlsHandshakeTimes = make([]time.Duration, 0, times)
    v.tlsTestMutex.Unlock()
    
    // 记录整体测试开始时间
    testStartTime := time.Now()
    
    // 更新UI提示测试开始
    resultLabel.SetText("TLS握手测试进行中: 0/" + strconv.Itoa(times))
    
    // 在后台执行测试
    go func() {
        // 确保在函数退出时更新状态
        defer func() {
            v.tlsTestMutex.Lock()
            v.tlsTestRunning = false
            v.tlsTestMutex.Unlock()
        }()
        
        // 执行多次测试
        for i := 0; i < times; i++ {
            // 更新进度
            v.tlsTestMutex.Lock()
            v.tlsTestProgress = i + 1
            v.tlsTestMutex.Unlock()
            
            // 更新UI显示进度
            resultLabel.SetText(fmt.Sprintf("TLS握手测试进行中: %d/%d", i+1, times))
            
            // 测量单次握手时间
            handshakeTime, err := v.measureTLSHandshake()
            if err != nil {
                // 处理错误
                resultLabel.SetText("测试失败: " + err.Error())
                return
            }
            
            // 记录本次测量结果
            v.tlsTestMutex.Lock()
            v.tlsHandshakeTimes = append(v.tlsHandshakeTimes, handshakeTime)
            v.tlsTestMutex.Unlock()
            
            // 每次测试后短暂等待，避免服务器过载
            time.Sleep(100 * time.Millisecond)
        }
        
        // 计算统计数据
        v.tlsTestMutex.Lock()
        
        // 计算总时间
        var totalTime time.Duration
        for _, t := range v.tlsHandshakeTimes {
            totalTime += t
        }
        
        // 计算平均时间
        v.tlsTestResults.avgTime = totalTime / time.Duration(len(v.tlsHandshakeTimes))
        
        // 计算最小和最大时间
        v.tlsTestResults.minTime = v.tlsHandshakeTimes[0]
        v.tlsTestResults.maxTime = v.tlsHandshakeTimes[0]
        for _, t := range v.tlsHandshakeTimes {
            if t < v.tlsTestResults.minTime {
                v.tlsTestResults.minTime = t
            }
            if t > v.tlsTestResults.maxTime {
                v.tlsTestResults.maxTime = t
            }
        }
        
        // 计算标准差
        var variance float64
        for _, t := range v.tlsHandshakeTimes {
            diff := float64(t - v.tlsTestResults.avgTime)
            variance += diff * diff
        }
        variance /= float64(len(v.tlsHandshakeTimes))
        stdDev := time.Duration(math.Sqrt(variance))
        v.tlsTestResults.stdDev = stdDev
        
        v.tlsTestMutex.Unlock()
        
        // 更新UI显示结果
        totalTestTime := time.Since(testStartTime)
        resultLabel.SetText(fmt.Sprintf(
            "测试完成 (%d次):\n平均: %s\n最小: %s\n最大: %s\n标准差: %s\n总耗时: %s",
            times,
            formatMilliseconds(v.tlsTestResults.avgTime),
            formatMilliseconds(v.tlsTestResults.minTime),
            formatMilliseconds(v.tlsTestResults.maxTime),
            formatMilliseconds(v.tlsTestResults.stdDev),
            formatDuration(totalTestTime),
        ))
    }()
}

