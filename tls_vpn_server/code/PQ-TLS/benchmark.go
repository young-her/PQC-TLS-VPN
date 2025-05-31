package main

import (
    "crypto/tls"
    "fmt"
    "net"
    "os"
    "os/exec"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"
)

// HandshakeMetrics TLS握手指标
type HandshakeMetrics struct {
    StartTime     time.Time
    EndTime       time.Time
    Duration      time.Duration
    Success       bool
    ClientAddr    string
    ErrorMsg      string
    CPUBefore     float64
    CPUAfter      float64
    MemBefore     float64
    MemAfter      float64
}

// ResourceSnapshot 资源快照
type ResourceSnapshot struct {
    CPUUsage    float64
    MemoryUsage float64
    Timestamp   time.Time
}

// HandshakeMonitor 握手监控器
type HandshakeMonitor struct {
    handshakes     []HandshakeMetrics
    mu             sync.RWMutex
    totalCount     int64
    successCount   int64
    failureCount   int64
    samplingActive int32
    resourceChan   chan ResourceSnapshot
    resourceData   []ResourceSnapshot
    startTime      time.Time
}

// NewHandshakeMonitor 创建握手监控器
func NewHandshakeMonitor() *HandshakeMonitor {
    monitor := &HandshakeMonitor{
        handshakes:   make([]HandshakeMetrics, 0, 200), // 预分配空间
        resourceChan: make(chan ResourceSnapshot, 1000),
        resourceData: make([]ResourceSnapshot, 0, 10000),
        startTime:    time.Now(),
    }
    
    // 启动高频资源采样
    go monitor.startResourceSampling()
    
    return monitor
}

// startResourceSampling 启动资源采样
func (hm *HandshakeMonitor) startResourceSampling() {
    ticker := time.NewTicker(5 * time.Millisecond) // 5ms高频采样
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            if atomic.LoadInt32(&hm.samplingActive) == 1 {
                snapshot := ResourceSnapshot{
                    CPUUsage:    hm.getCPUUsage(),
                    MemoryUsage: hm.getMemoryUsage(),
                    Timestamp:   time.Now(),
                }
                
                select {
                case hm.resourceChan <- snapshot:
                default: // 如果通道满了就丢弃
                }
            }
        }
    }
}

// StartSampling 开始采样
func (hm *HandshakeMonitor) StartSampling() {
    atomic.StoreInt32(&hm.samplingActive, 1)
    
    // 清空之前的数据并开始收集
    go func() {
        hm.mu.Lock()
        hm.resourceData = hm.resourceData[:0] // 清空但保留容量
        hm.mu.Unlock()
        
        for atomic.LoadInt32(&hm.samplingActive) == 1 {
            select {
            case snapshot := <-hm.resourceChan:
                hm.mu.Lock()
                hm.resourceData = append(hm.resourceData, snapshot)
                hm.mu.Unlock()
            case <-time.After(100 * time.Millisecond):
                // 超时继续
            }
        }
    }()
}

// StopSampling 停止采样
func (hm *HandshakeMonitor) StopSampling() {
    atomic.StoreInt32(&hm.samplingActive, 0)
}

// getCPUUsage 获取CPU使用率
func (hm *HandshakeMonitor) getCPUUsage() float64 {
    pid := os.Getpid()
    
    // 使用ps命令获取瞬时CPU使用率
    cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "%cpu", "--no-headers")
    if output, err := cmd.Output(); err == nil {
        cpuStr := strings.TrimSpace(string(output))
        if cpu, err := strconv.ParseFloat(cpuStr, 64); err == nil {
            return cpu
        }
    }
    
    return 0
}

// getMemoryUsage 获取内存使用量
func (hm *HandshakeMonitor) getMemoryUsage() float64 {
    var mem runtime.MemStats
    runtime.ReadMemStats(&mem)
    return float64(mem.Alloc) / (1024 * 1024) // 转换为MB
}

// RecordHandshake 记录握手信息
func (hm *HandshakeMonitor) RecordHandshake(metrics HandshakeMetrics) {
    hm.mu.Lock()
    defer hm.mu.Unlock()
    
    hm.handshakes = append(hm.handshakes, metrics)
    atomic.AddInt64(&hm.totalCount, 1)
    
    if metrics.Success {
        atomic.AddInt64(&hm.successCount, 1)
    } else {
        atomic.AddInt64(&hm.failureCount, 1)
    }
}

// GetStats 获取统计信息
func (hm *HandshakeMonitor) GetStats() {
    hm.mu.RLock()
    defer hm.mu.RUnlock()
    
    totalCount := atomic.LoadInt64(&hm.totalCount)
    successCount := atomic.LoadInt64(&hm.successCount)
    failureCount := atomic.LoadInt64(&hm.failureCount)
    
    if totalCount == 0 {
        fmt.Printf("暂无握手数据\n")
        return
    }
    
    // 计算握手时间统计
    var durations []float64
    var cpuDiffs []float64
    var memDiffs []float64
    
    for _, h := range hm.handshakes {
        if h.Success {
            durations = append(durations, h.Duration.Seconds()*1000) // 转换为毫秒
            if h.CPUAfter > h.CPUBefore {
                cpuDiffs = append(cpuDiffs, h.CPUAfter-h.CPUBefore)
            }
            if h.MemAfter > h.MemBefore {
                memDiffs = append(memDiffs, h.MemAfter-h.MemBefore)
            }
        }
    }
    
    // 计算资源使用统计
    var cpuValues, memValues []float64
    for _, snapshot := range hm.resourceData {
        cpuValues = append(cpuValues, snapshot.CPUUsage)
        memValues = append(memValues, snapshot.MemoryUsage)
    }
    
    fmt.Printf("\n=== TLS握手性能测试结果 ===\n")
    fmt.Printf("测试时间: %.2f秒\n", time.Since(hm.startTime).Seconds())
    fmt.Printf("总握手次数: %d\n", totalCount)
    fmt.Printf("成功次数: %d (%.1f%%)\n", successCount, float64(successCount)/float64(totalCount)*100)
    fmt.Printf("失败次数: %d (%.1f%%)\n", failureCount, float64(failureCount)/float64(totalCount)*100)
    
    if len(durations) > 0 {
        durationStats := calculateDetailedStats(durations)
        fmt.Printf("\n握手时间统计 (ms):\n")
        fmt.Printf("  平均: %.2f, 最小: %.2f, 最大: %.2f\n", durationStats.Avg, durationStats.Min, durationStats.Max)
        fmt.Printf("  P50: %.2f, P95: %.2f, P99: %.2f\n", durationStats.P50, durationStats.P95, durationStats.P99)
    }
    
    if len(cpuValues) > 0 {
        cpuStats := calculateDetailedStats(cpuValues)
        fmt.Printf("\nCPU使用率统计 (%d个样本):\n", len(cpuValues))
        fmt.Printf("  平均: %.2f%%, 最小: %.2f%%, 最大: %.2f%%\n", cpuStats.Avg, cpuStats.Min, cpuStats.Max)
        fmt.Printf("  P50: %.2f%%, P95: %.2f%%, P99: %.2f%%\n", cpuStats.P50, cpuStats.P95, cpuStats.P99)
    }
    
    if len(memValues) > 0 {
        memStats := calculateDetailedStats(memValues)
        fmt.Printf("\n内存使用统计 (MB):\n")
        fmt.Printf("  平均: %.2f, 最小: %.2f, 最大: %.2f\n", memStats.Avg, memStats.Min, memStats.Max)
        fmt.Printf("  P50: %.2f, P95: %.2f, P99: %.2f\n", memStats.P50, memStats.P95, memStats.P99)
    }
    
    // 显示最近的握手详情
    fmt.Printf("\n最近10次握手详情:\n")
    start := len(hm.handshakes) - 10
    if start < 0 {
        start = 0
    }
    
    for i := start; i < len(hm.handshakes); i++ {
        h := hm.handshakes[i]
        status := "成功"
        if !h.Success {
            status = fmt.Sprintf("失败(%s)", h.ErrorMsg)
        }
        fmt.Printf("  #%d: %s, 耗时: %.2fms, CPU变化: %.2f%%, 内存变化: %.2fMB\n",
            i+1, status, h.Duration.Seconds()*1000,
            h.CPUAfter-h.CPUBefore, h.MemAfter-h.MemBefore)
    }
    
    fmt.Printf("=============================\n")
}

// Stats 统计结构
type Stats struct {
    Avg, Min, Max, P50, P95, P99 float64
    Count                        int
}

// calculateDetailedStats 计算详细统计
func calculateDetailedStats(values []float64) Stats {
    if len(values) == 0 {
        return Stats{}
    }
    
    // 复制并排序
    sorted := make([]float64, len(values))
    copy(sorted, values)
    
    // 简单排序
    for i := 0; i < len(sorted); i++ {
        for j := i + 1; j < len(sorted); j++ {
            if sorted[i] > sorted[j] {
                sorted[i], sorted[j] = sorted[j], sorted[i]
            }
        }
    }
    
    var sum float64
    for _, v := range values {
        sum += v
    }
    
    avg := sum / float64(len(values))
    min := sorted[0]
    max := sorted[len(sorted)-1]
    
    getPercentile := func(p int) float64 {
        index := len(sorted) * p / 100
        if index >= len(sorted) {
            index = len(sorted) - 1
        }
        return sorted[index]
    }
    
    return Stats{
        Avg:   avg,
        Min:   min,
        Max:   max,
        P50:   getPercentile(50),
        P95:   getPercentile(95),
        P99:   getPercentile(99),
        Count: len(values),
    }
}

// handleConnection 处理单个连接（专注于握手）
func handleConnection(rawConn net.Conn, monitor *HandshakeMonitor) {
    clientAddr := rawConn.RemoteAddr().String()
    fmt.Printf("新连接来自: %s\n", clientAddr)
    
    // 记录握手开始
    metrics := HandshakeMetrics{
        StartTime:  time.Now(),
        ClientAddr: clientAddr,
        CPUBefore:  monitor.getCPUUsage(),
        MemBefore:  monitor.getMemoryUsage(),
    }
    
    // 执行TLS握手
    tlsConn := rawConn.(*tls.Conn)
    err := tlsConn.Handshake()
    
    // 记录握手结束
    metrics.EndTime = time.Now()
    metrics.Duration = metrics.EndTime.Sub(metrics.StartTime)
    metrics.CPUAfter = monitor.getCPUUsage()
    metrics.MemAfter = monitor.getMemoryUsage()
    
    if err != nil {
        metrics.Success = false
        metrics.ErrorMsg = err.Error()
        fmt.Printf("握手失败 %s: %v (耗时: %.2fms)\n", 
            clientAddr, err, metrics.Duration.Seconds()*1000)
    } else {
        metrics.Success = true
        fmt.Printf("握手成功 %s (耗时: %.2fms)\n", 
            clientAddr, metrics.Duration.Seconds()*1000)
        
        // 握手成功后，读取少量数据然后关闭（模拟快速断开）
        tlsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
        buffer := make([]byte, 1024)
        _, readErr := tlsConn.Read(buffer)
        if readErr != nil {
            fmt.Printf("读取数据: %s\n", clientAddr)
        }
    }
    
    // 记录指标
    monitor.RecordHandshake(metrics)
    
    // 关闭连接
    rawConn.Close()
}

// simulateLoad 模拟计算负载以增加CPU使用率
func simulateLoad() {
    go func() {
        for {
            // CPU密集型计算
            sum := 0.0
            for i := 0; i < 100000; i++ {
                sum += float64(i) * 3.14159
            }
            
            // 内存分配
            data := make([]byte, 1024*100) // 100KB
            _ = data
            
            runtime.Gosched()
            time.Sleep(10 * time.Millisecond)
        }
    }()
}

func main() {
    // 服务器配置
    config := struct {
        ListenAddr string
        CertPath   string
        KeyPath    string
    }{
        ListenAddr: ":443",
        CertPath:   "../../cert/server.crt",
        KeyPath:    "../../cert/server.key",
    }
    
    // 创建握手监控器
    monitor := NewHandshakeMonitor()
    
    // 启动资源采样
    monitor.StartSampling()
    defer monitor.StopSampling()
    
    // 启动模拟负载
    simulateLoad()
    
    // 定期输出统计信息
    go func() {
        ticker := time.NewTicker(10 * time.Second)
        defer ticker.Stop()
        
        for {
            <-ticker.C
            monitor.GetStats()
        }
    }()
    
    // 加载TLS证书
    cert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
    if err != nil {
        fmt.Printf("加载服务器证书失败: %v\n", err)
        return
    }
    
    // TLS配置 - 优化用于频繁握手
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS13,
        MaxVersion:   tls.VersionTLS13,
        // 为了增加握手成本，可以启用客户端证书验证
        // ClientAuth: tls.RequireAnyClientCert,
    }
    
    // 创建监听器
    listener, err := tls.Listen("tcp", config.ListenAddr, tlsConfig)
    if err != nil {
        fmt.Printf("创建监听器失败: %v\n", err)
        return
    }
    defer listener.Close()
    
    fmt.Printf("TLS握手测试服务器启动，监听地址: %s\n", config.ListenAddr)
    fmt.Printf("准备接收握手测试...\n")
    fmt.Printf("\n客户端测试命令示例:\n")
    fmt.Printf("for i in {1..100}; do echo \"test\" | timeout 2 openssl s_client -connect localhost:443 -quiet; done\n")
    fmt.Printf("\n或使用Go客户端进行100次连接测试\n")
    
    // 接受连接循环
    for {
        conn, err := listener.Accept()
        if err != nil {
            fmt.Printf("接受连接失败: %v\n", err)
            continue
        }
        
        // 每个连接都在独立的goroutine中处理
        go handleConnection(conn, monitor)
    }
}
