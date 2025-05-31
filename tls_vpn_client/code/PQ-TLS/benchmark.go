package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// 测试配置
type TestConfig struct {
	ServerAddr string
	TestCount  int
	CAPath     string
	CertPath   string
	KeyPath    string
	
	// 数据传输测试参数
	TestTransfer bool   // 是否测试数据传输
	TransferSize int64  // 传输数据大小(MB)
	TransferTime int    // 每次传输测试时间(秒)
}

// 测试结果
type TestResult struct {
	Type       string // "Standard TLS" 或 "PQ-TLS"
	Times      []time.Duration
	AvgTime    time.Duration
	MinTime    time.Duration
	MaxTime    time.Duration
	StdDev     time.Duration
	FailCount  int
	
	// CPU使用情况（百分比）
	CPUUsages  []float64
	AvgCPU     float64
	MinCPU     float64
	MaxCPU     float64
	
	// 内存使用情况（MB）
	MemUsages  []float64
	AvgMem     float64
	MinMem     float64
	MaxMem     float64
	
	// 吞吐量相关(Mbps)
	Throughputs    []float64  // 每次测试的吞吐量
	AvgThroughput  float64    // 平均吞吐量
	MinThroughput  float64    // 最小吞吐量
	MaxThroughput  float64    // 最大吞吐量
	
	// 传输测试期间的CPU使用率
	TransferCPUs   []float64  // 每次传输测试的CPU使用率
	AvgTransferCPU float64    // 平均传输CPU使用率
	MinTransferCPU float64    // 最小传输CPU使用率
	MaxTransferCPU float64    // 最大传输CPU使用率
	
	// 传输测试期间的内存使用情况
	TransferMems   []float64  // 每次传输测试的内存使用
	AvgTransferMem float64    // 平均传输内存使用
	MinTransferMem float64    // 最小传输内存使用
	MaxTransferMem float64    // 最大传输内存使用
}

// ResourceUsage 保存资源使用情况
type ResourceUsage struct {
	CPUUsage    float64 // CPU使用百分比
	MemoryUsage float64 // 内存使用MB
}

// 测量资源使用情况
func measureResources() ResourceUsage {
	var r ResourceUsage
	
	// 获取内存使用情况
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	r.MemoryUsage = float64(mem.Alloc) / (1024 * 1024) // 转换为MB
	
	// 获取当前进程的PID
	pid := os.Getpid()
	
	// 使用ps命令获取CPU使用百分比
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "%cpu")
	output, err := cmd.Output()
	if err == nil {
		// 解析输出
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			// 第二行是CPU百分比
			cpuStr := strings.TrimSpace(lines[1])
			cpu, err := strconv.ParseFloat(cpuStr, 64)
			if err == nil {
				r.CPUUsage = cpu
			}
		}
	}
	
	return r
}

// 格式化CPU百分比
func formatCPUPercentage(cpu float64) string {
	return fmt.Sprintf("%.2f%%", cpu)
}

// 格式化内存使用量（MB）
func formatMemoryMB(mem float64) string {
	return fmt.Sprintf("%.2f MB", mem)
}

// 格式化毫秒级持续时间为可读形式
func formatMilliseconds(d time.Duration) string {
	return fmt.Sprintf("%.2f毫秒", float64(d.Microseconds())/1000.0)
}

// 格式化吞吐量(Mbps)为可读形式
func formatThroughput(mbps float64) string {
	return fmt.Sprintf("%.2f Mbps", mbps)
}

// 计算吞吐量统计数据和传输期间资源使用统计数据
func calculateTransferStats(throughputs, cpus, mems []float64) (
	avgThroughput, minThroughput, maxThroughput,
	avgCPU, minCPU, maxCPU,
	avgMem, minMem, maxMem float64) {
	
	if len(throughputs) == 0 {
		return 0, 0, 0, 0, 0, 0, 0, 0, 0
	}
	
	// 初始化最小、最大值
	minThroughput = throughputs[0]
	maxThroughput = throughputs[0]
	var totalThroughput float64
	
	minCPU = cpus[0]
	maxCPU = cpus[0]
	var totalCPU float64
	
	minMem = mems[0]
	maxMem = mems[0]
	var totalMem float64
	
	// 计算总和、最小值和最大值
	for _, tp := range throughputs {
		totalThroughput += tp
		if tp < minThroughput {
			minThroughput = tp
		}
		if tp > maxThroughput {
			maxThroughput = tp
		}
	}
	
	for _, cpu := range cpus {
		totalCPU += cpu
		if cpu < minCPU {
			minCPU = cpu
		}
		if cpu > maxCPU {
			maxCPU = cpu
		}
	}
	
	for _, mem := range mems {
		totalMem += mem
		if mem < minMem {
			minMem = mem
		}
		if mem > maxMem {
			maxMem = mem
		}
	}
	
	// 计算平均值
	avgThroughput = totalThroughput / float64(len(throughputs))
	avgCPU = totalCPU / float64(len(cpus))
	avgMem = totalMem / float64(len(mems))
	
	return avgThroughput, minThroughput, maxThroughput, avgCPU, minCPU, maxCPU, avgMem, minMem, maxMem
}

// 测试标准TLS握手时间
func testStandardTLS(config TestConfig, progressCh chan<- int) TestResult {
	result := TestResult{
		Type:          "Standard TLS",
		Times:         make([]time.Duration, 0, config.TestCount),
		CPUUsages:     make([]float64, 0, config.TestCount),
		MemUsages:     make([]float64, 0, config.TestCount),
		Throughputs:   make([]float64, 0, config.TestCount),
		TransferCPUs:  make([]float64, 0, config.TestCount),
		TransferMems:  make([]float64, 0, config.TestCount),
		FailCount:     0,
	}

	// 加载CA证书
	rootCA, err := os.ReadFile(config.CAPath)
	if err != nil {
		fmt.Printf("读取CA证书失败: %v\n", err)
		result.FailCount = config.TestCount
		return result
	}

	// 创建CA证书池
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(rootCA) {
		fmt.Printf("解析CA证书失败\n")
		result.FailCount = config.TestCount
		return result
	}

	// 加载客户端证书
	clientCert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		fmt.Printf("加载客户端证书失败: %v\n", err)
		result.FailCount = config.TestCount
		return result
	}

	// 标准TLS配置
	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	// 执行多次测试
	for i := 0; i < config.TestCount; i++ {
		// 测量握手前的资源使用情况
		beforeResource := measureResources()
		
		// 记录开始时间
		startTime := time.Now()

		// 执行TLS握手
		conn, err := tls.Dial("tcp", config.ServerAddr, tlsConfig)
		if err != nil {
			fmt.Printf("标准TLS握手失败: %v\n", err)
			result.FailCount++
			progressCh <- 1 // 通知进度更新
			continue
		}

		// 计算握手时间
		handshakeTime := time.Since(startTime)
		result.Times = append(result.Times, handshakeTime)
		
		// 测量握手后的资源使用情况
		afterResource := measureResources()
		
		// 计算资源使用差异
		cpuDiff := afterResource.CPUUsage - beforeResource.CPUUsage
		if cpuDiff < 0 {
			cpuDiff = afterResource.CPUUsage // 如果差异为负，就使用握手后的值
		}
		memDiff := afterResource.MemoryUsage - beforeResource.MemoryUsage
		if memDiff < 0 {
			memDiff = 0 // 如果差异为负，可能是因为GC，设为0
		}
		
		// 记录资源使用情况
		result.CPUUsages = append(result.CPUUsages, cpuDiff)
		result.MemUsages = append(result.MemUsages, memDiff)

		// 如果需要进行数据传输测试
		if config.TestTransfer {
			// 执行数据传输测试
			throughput, transferCPU, transferMem, err := testTLSTransfer(conn, config, time.Duration(config.TransferTime)*time.Second)
			if err != nil {
				fmt.Printf("标准TLS数据传输测试失败: %v\n", err)
			} else {
				// 记录测试结果
				result.Throughputs = append(result.Throughputs, throughput)
				result.TransferCPUs = append(result.TransferCPUs, transferCPU)
				result.TransferMems = append(result.TransferMems, transferMem)
			}
		}

		// 关闭连接
		conn.Close()

		// 通知进度更新
		progressCh <- 1

		// 每次测试后短暂等待，避免服务器过载
		time.Sleep(100 * time.Millisecond)
	}

	// 计算统计数据
	if len(result.Times) > 0 {
		result.AvgTime, result.MinTime, result.MaxTime, result.StdDev = calculateStats(result.Times)
		result.AvgCPU, result.MinCPU, result.MaxCPU, result.AvgMem, result.MinMem, result.MaxMem = calculateResourceStats(result.CPUUsages, result.MemUsages)
		
		// 如果有传输测试数据，计算传输相关统计
		if len(result.Throughputs) > 0 {
			result.AvgThroughput, result.MinThroughput, result.MaxThroughput,
			result.AvgTransferCPU, result.MinTransferCPU, result.MaxTransferCPU,
			result.AvgTransferMem, result.MinTransferMem, result.MaxTransferMem = calculateTransferStats(
				result.Throughputs, result.TransferCPUs, result.TransferMems)
		}
	}

	return result
}

// 测试后量子TLS握手时间
func testPQTLS(config TestConfig, progressCh chan<- int) TestResult {
	result := TestResult{
		Type:          "PQ-TLS",
		Times:         make([]time.Duration, 0, config.TestCount),
		CPUUsages:     make([]float64, 0, config.TestCount),
		MemUsages:     make([]float64, 0, config.TestCount),
		Throughputs:   make([]float64, 0, config.TestCount),
		TransferCPUs:  make([]float64, 0, config.TestCount),
		TransferMems:  make([]float64, 0, config.TestCount),
		FailCount:     0,
	}

	// 加载CA证书
	rootCA, err := os.ReadFile(config.CAPath)
	if err != nil {
		fmt.Printf("读取CA证书失败: %v\n", err)
		result.FailCount = config.TestCount
		return result
	}

	// 创建CA证书池
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(rootCA) {
		fmt.Printf("解析CA证书失败\n")
		result.FailCount = config.TestCount
		return result
	}

	// 加载客户端证书
	clientCert, err := tls.LoadX509KeyPair(config.CertPath, config.KeyPath)
	if err != nil {
		fmt.Printf("加载客户端证书失败: %v\n", err)
		result.FailCount = config.TestCount
		return result
	}

	// 后量子TLS配置
	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768}, // 使用后量子密钥交换
	}

	// 执行多次测试
	for i := 0; i < config.TestCount; i++ {
		// 测量握手前的资源使用情况
		beforeResource := measureResources()
		
		// 记录开始时间
		startTime := time.Now()

		// 执行TLS握手
		conn, err := tls.Dial("tcp", config.ServerAddr, tlsConfig)
		if err != nil {
			fmt.Printf("后量子TLS握手失败: %v\n", err)
			result.FailCount++
			progressCh <- 1 // 通知进度更新
			continue
		}

		// 计算握手时间
		handshakeTime := time.Since(startTime)
		result.Times = append(result.Times, handshakeTime)
		
		// 测量握手后的资源使用情况
		afterResource := measureResources()
		
		// 计算资源使用差异
		cpuDiff := afterResource.CPUUsage - beforeResource.CPUUsage
		if cpuDiff < 0 {
			cpuDiff = afterResource.CPUUsage // 如果差异为负，就使用握手后的值
		}
		memDiff := afterResource.MemoryUsage - beforeResource.MemoryUsage
		if memDiff < 0 {
			memDiff = 0 // 如果差异为负，可能是因为GC，设为0
		}
		
		// 记录资源使用情况
		result.CPUUsages = append(result.CPUUsages, cpuDiff)
		result.MemUsages = append(result.MemUsages, memDiff)

		// 如果需要进行数据传输测试
		if config.TestTransfer {
			// 执行数据传输测试
			throughput, transferCPU, transferMem, err := testTLSTransfer(conn, config, time.Duration(config.TransferTime)*time.Second)
			if err != nil {
				fmt.Printf("后量子TLS数据传输测试失败: %v\n", err)
			} else {
				// 记录测试结果
				result.Throughputs = append(result.Throughputs, throughput)
				result.TransferCPUs = append(result.TransferCPUs, transferCPU)
				result.TransferMems = append(result.TransferMems, transferMem)
			}
		}

		// 关闭连接
		conn.Close()

		// 通知进度更新
		progressCh <- 1

		// 每次测试后短暂等待，避免服务器过载
		time.Sleep(100 * time.Millisecond)
	}

	// 计算统计数据
	if len(result.Times) > 0 {
		result.AvgTime, result.MinTime, result.MaxTime, result.StdDev = calculateStats(result.Times)
		result.AvgCPU, result.MinCPU, result.MaxCPU, result.AvgMem, result.MinMem, result.MaxMem = calculateResourceStats(result.CPUUsages, result.MemUsages)
		
		// 如果有传输测试数据，计算传输相关统计
		if len(result.Throughputs) > 0 {
			result.AvgThroughput, result.MinThroughput, result.MaxThroughput,
			result.AvgTransferCPU, result.MinTransferCPU, result.MaxTransferCPU,
			result.AvgTransferMem, result.MinTransferMem, result.MaxTransferMem = calculateTransferStats(
				result.Throughputs, result.TransferCPUs, result.TransferMems)
		}
	}

	return result
}

// 计算统计数据
func calculateStats(times []time.Duration) (avg, min, max, stdDev time.Duration) {
	if len(times) == 0 {
		return 0, 0, 0, 0
	}

	// 计算总时间
	var totalTime time.Duration
	min = times[0]
	max = times[0]

	for _, t := range times {
		totalTime += t
		if t < min {
			min = t
		}
		if t > max {
			max = t
		}
	}

	// 计算平均时间
	avg = totalTime / time.Duration(len(times))

	// 计算标准差
	var variance float64
	for _, t := range times {
		diff := float64(t - avg)
		variance += diff * diff
	}
	variance /= float64(len(times))
	stdDev = time.Duration(math.Sqrt(variance))

	return avg, min, max, stdDev
}

// 计算CPU和内存统计数据
func calculateResourceStats(cpuUsages, memUsages []float64) (avgCPU, minCPU, maxCPU, avgMem, minMem, maxMem float64) {
	if len(cpuUsages) == 0 || len(memUsages) == 0 {
		return 0, 0, 0, 0, 0, 0
	}

	// 初始化
	minCPU = cpuUsages[0]
	maxCPU = cpuUsages[0]
	var totalCPU float64
	
	minMem = memUsages[0]
	maxMem = memUsages[0]
	var totalMem float64

	// 计算总和、最小值和最大值
	for _, cpu := range cpuUsages {
		totalCPU += cpu
		if cpu < minCPU {
			minCPU = cpu
		}
		if cpu > maxCPU {
			maxCPU = cpu
		}
	}

	for _, mem := range memUsages {
		totalMem += mem
		if mem < minMem {
			minMem = mem
		}
		if mem > maxMem {
			maxMem = mem
		}
	}

	// 计算平均值
	avgCPU = totalCPU / float64(len(cpuUsages))
	avgMem = totalMem / float64(len(memUsages))

	return avgCPU, minCPU, maxCPU, avgMem, minMem, maxMem
}

// 测试TLS连接的数据传输性能
func testTLSTransfer(conn *tls.Conn, config TestConfig, testDuration time.Duration) (throughput, cpuUsage, memUsage float64, err error) {
	// 准备测试数据缓冲区
	bufferSize := 64 * 1024 // 64KB的缓冲区
	dataBuffer := make([]byte, bufferSize)
	// 填充随机数据
	for i := range dataBuffer {
		dataBuffer[i] = byte(i % 256)
	}
	
	// 设置测试时间
	endTime := time.Now().Add(testDuration)
	
	// 测量开始时的资源使用情况
	startResource := measureResources()
	
	// 设置写入超时
	conn.SetWriteDeadline(endTime.Add(5 * time.Second)) // 额外5秒以确保所有数据都能发送
	
	// 开始测试，持续发送数据直到测试时间结束
	var totalBytesSent int64
	
	for time.Now().Before(endTime) {
		// 发送数据
		n, err := conn.Write(dataBuffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 写入超时，可能是服务器繁忙，继续尝试
				continue
			}
			return 0, 0, 0, fmt.Errorf("发送数据失败: %v", err)
		}
		totalBytesSent += int64(n)
		
		// 短暂休眠，避免占用过多CPU
		time.Sleep(1 * time.Millisecond)
	}
	
	// 测量结束时的资源使用情况
	endResource := measureResources()
	
	// 计算吞吐量(Mbps)
	totalBits := totalBytesSent * 8
	durationSeconds := testDuration.Seconds()
	throughput = float64(totalBits) / durationSeconds / 1_000_000 // 转换为Mbps
	
	// 计算资源使用差异
	cpuUsage = endResource.CPUUsage - startResource.CPUUsage
	if cpuUsage < 0 {
		cpuUsage = endResource.CPUUsage // 如果差异为负，就使用结束时的值
	}
	
	memUsage = endResource.MemoryUsage - startResource.MemoryUsage
	if memUsage < 0 {
		memUsage = 0 // 如果差异为负，可能是因为GC，设为0
	}
	
	return throughput, cpuUsage, memUsage, nil
}

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("TLS握手和数据传输性能比较测试")

	// 默认配置
	defaultConfig := TestConfig{
		ServerAddr:    "10.37.129.4:443",
		TestCount:     100,
		CAPath:        "../../cert/ca.crt",
		CertPath:      "../../cert/client.crt",
		KeyPath:       "../../cert/client.key",
		TestTransfer:  false,
		TransferSize:  100,
		TransferTime:  10,
	}

	// 服务器地址输入框
	serverEntry := widget.NewEntry()
	serverEntry.SetText(defaultConfig.ServerAddr)
	serverEntry.SetPlaceHolder("输入服务器地址和端口")

	// 测试次数输入框
	testCountEntry := widget.NewEntry()
	testCountEntry.SetText(strconv.Itoa(defaultConfig.TestCount))
	testCountEntry.SetPlaceHolder("输入测试次数")

	// CA证书路径输入框
	caPathEntry := widget.NewEntry()
	caPathEntry.SetText(defaultConfig.CAPath)
	caPathEntry.SetPlaceHolder("输入CA证书路径")

	// 客户端证书路径输入框
	certPathEntry := widget.NewEntry()
	certPathEntry.SetText(defaultConfig.CertPath)
	certPathEntry.SetPlaceHolder("输入客户端证书路径")

	// 客户端密钥路径输入框
	keyPathEntry := widget.NewEntry()
	keyPathEntry.SetText(defaultConfig.KeyPath)
	keyPathEntry.SetPlaceHolder("输入客户端密钥路径")
	
	// 传输测试开关
	transferTestCheck := widget.NewCheck("测试数据传输", nil)
	transferTestCheck.SetChecked(defaultConfig.TestTransfer)
	
	// 传输测试时间输入框
	transferTimeEntry := widget.NewEntry()
	transferTimeEntry.SetText(strconv.Itoa(defaultConfig.TransferTime))
	transferTimeEntry.SetPlaceHolder("输入每次传输测试时间(秒)")

	// 传输数据大小输入框
	transferSizeEntry := widget.NewEntry()
	transferSizeEntry.SetText(strconv.FormatInt(defaultConfig.TransferSize, 10))
	transferSizeEntry.SetPlaceHolder("输入传输数据大小(MB)")
	
	// 根据传输测试开关状态设置传输相关输入框的可用性
	transferTestCheck.OnChanged = func(checked bool) {
		if checked {
			transferTimeEntry.Enable()
			transferSizeEntry.Enable()
		} else {
			transferTimeEntry.Disable()
			transferSizeEntry.Disable()
		}
	}
	
	// 初始设置传输相关输入框的可用性
	if !defaultConfig.TestTransfer {
		transferTimeEntry.Disable()
		transferSizeEntry.Disable()
	}

	// 进度条
	progressBar := widget.NewProgressBar()
	progressBar.Hide()

	// 状态标签
	statusLabel := widget.NewLabel("")
	statusLabel.Alignment = fyne.TextAlignCenter
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	// 创建分组标题
	configTitle := widget.NewLabel("测试配置")
	configTitle.TextStyle = fyne.TextStyle{Bold: true}
	configTitle.Alignment = fyne.TextAlignCenter
	
	resultTitle := widget.NewLabel("测试结果")
	resultTitle.TextStyle = fyne.TextStyle{Bold: true}
	resultTitle.Alignment = fyne.TextAlignCenter

	// 使用多行富文本组件替代普通标签
	resultRichText := widget.NewRichTextFromMarkdown("点击'开始测试'按钮开始比较测试")
	resultRichText.Wrapping = fyne.TextWrapWord
	
	// 创建结果滚动容器，设置最小大小
	resultScroll := container.NewScroll(resultRichText)
	resultScroll.SetMinSize(fyne.NewSize(700, 400)) // 设置最小尺寸
	
	// 创建结果区域
	resultArea := container.NewVBox(
		resultTitle,
		widget.NewSeparator(),
		resultScroll, // 直接使用滚动容器，不再包装
	)

	// 开始测试按钮
	startBtn := widget.NewButton("开始测试", nil)
	startBtn.Importance = widget.HighImportance

	// 设置按钮点击处理函数
	startBtn.OnTapped = func() {
		// 获取配置
		testCount, err := strconv.Atoi(testCountEntry.Text)
		if err != nil || testCount <= 0 {
			resultRichText.ParseMarkdown("**错误**: 请输入有效的测试次数")
			return
		}
		
		// 获取传输测试相关配置
		transferTest := transferTestCheck.Checked
		var transferSize int64 = 100 // 默认值
		var transferTime int = 10    // 默认值
		
		if transferTest {
			// 解析传输大小
			size, err := strconv.ParseInt(transferSizeEntry.Text, 10, 64)
			if err == nil && size > 0 {
				transferSize = size
			} else {
				resultRichText.ParseMarkdown("**警告**: 传输数据大小无效，使用默认值(100MB)")
			}
			
			// 解析传输时间
			time, err := strconv.Atoi(transferTimeEntry.Text)
			if err == nil && time > 0 {
				transferTime = time
			} else {
				resultRichText.ParseMarkdown("**警告**: 传输测试时间无效，使用默认值(10秒)")
			}
		}

		config := TestConfig{
			ServerAddr:   serverEntry.Text,
			TestCount:    testCount,
			CAPath:       caPathEntry.Text,
			CertPath:     certPathEntry.Text,
			KeyPath:      keyPathEntry.Text,
			TestTransfer: transferTest,
			TransferSize: transferSize,
			TransferTime: transferTime,
		}

		// 禁用按钮，显示进度条
		startBtn.Disable()
		progressBar.Show()
		progressBar.SetValue(0)
		statusLabel.SetText("测试中...")
		
		testInfo := "**正在进行测试，请稍候...**\n\n测试将同时进行标准TLS和后量子TLS握手测试"
		if config.TestTransfer {
			testInfo += fmt.Sprintf("\n\n同时将进行数据发送测试，每次测试持续%d秒", config.TransferTime)
		}
		resultRichText.ParseMarkdown(testInfo)

		// 创建进度通道
		progressCh := make(chan int, testCount*2)
		totalTests := testCount * 2 // 标准TLS和后量子TLS各测试testCount次

		// 在后台执行测试
		go func() {
			var wg sync.WaitGroup
			wg.Add(2)

			var standardResult, pqResult TestResult

			// 测试标准TLS
			go func() {
				defer wg.Done()
				standardResult = testStandardTLS(config, progressCh)
			}()

			// 测试后量子TLS
			go func() {
				defer wg.Done()
				pqResult = testPQTLS(config, progressCh)
			}()

			// 更新进度条
			go func() {
				completed := 0
				for range progressCh {
					completed++
					progressBar.SetValue(float64(completed) / float64(totalTests))
				}
			}()

			// 等待两个测试完成
			wg.Wait()
			close(progressCh)

			// 计算对比结果并格式化为Markdown
			var resultMarkdown string
			if len(standardResult.Times) == 0 && len(pqResult.Times) == 0 {
				resultMarkdown = "# 测试失败\n\n**错误**: 两种TLS握手均未成功"
			} else {
				resultMarkdown = fmt.Sprintf("# 测试完成\n\n**测试次数**: 每种方法%d次\n\n", testCount)
				
				// 标准TLS结果
				resultMarkdown += "## 标准TLS握手结果\n\n"
				if len(standardResult.Times) > 0 {
					resultMarkdown += fmt.Sprintf("- **平均时间**: %s\n", formatMilliseconds(standardResult.AvgTime))
					resultMarkdown += fmt.Sprintf("- **最小时间**: %s\n", formatMilliseconds(standardResult.MinTime))
					resultMarkdown += fmt.Sprintf("- **最大时间**: %s\n", formatMilliseconds(standardResult.MaxTime))
					resultMarkdown += fmt.Sprintf("- **标准差**: %s\n", formatMilliseconds(standardResult.StdDev))
					resultMarkdown += fmt.Sprintf("- **成功次数**: %d次\n", len(standardResult.Times))
					resultMarkdown += fmt.Sprintf("- **平均CPU使用**: %s\n", formatCPUPercentage(standardResult.AvgCPU))
					resultMarkdown += fmt.Sprintf("- **最大CPU使用**: %s\n", formatCPUPercentage(standardResult.MaxCPU))
					resultMarkdown += fmt.Sprintf("- **平均内存增长**: %s\n", formatMemoryMB(standardResult.AvgMem))
					resultMarkdown += fmt.Sprintf("- **最大内存增长**: %s\n", formatMemoryMB(standardResult.MaxMem))
					
					// 显示数据传输测试结果（如果有）
					if len(standardResult.Throughputs) > 0 {
						resultMarkdown += "\n### 标准TLS数据传输结果\n\n"
						resultMarkdown += fmt.Sprintf("- **平均发送吞吐量**: %s\n", formatThroughput(standardResult.AvgThroughput))
						resultMarkdown += fmt.Sprintf("- **最小发送吞吐量**: %s\n", formatThroughput(standardResult.MinThroughput))
						resultMarkdown += fmt.Sprintf("- **最大发送吞吐量**: %s\n", formatThroughput(standardResult.MaxThroughput))
						resultMarkdown += fmt.Sprintf("- **传输期间平均CPU使用**: %s\n", formatCPUPercentage(standardResult.AvgTransferCPU))
						resultMarkdown += fmt.Sprintf("- **传输期间最大CPU使用**: %s\n", formatCPUPercentage(standardResult.MaxTransferCPU))
						resultMarkdown += fmt.Sprintf("- **传输期间平均内存使用**: %s\n", formatMemoryMB(standardResult.AvgTransferMem))
						resultMarkdown += fmt.Sprintf("- **传输期间最大内存使用**: %s\n", formatMemoryMB(standardResult.MaxTransferMem))
					}
				}
				if standardResult.FailCount > 0 {
					resultMarkdown += fmt.Sprintf("- **失败次数**: %d次\n", standardResult.FailCount)
				}
				
				resultMarkdown += "\n## 后量子TLS握手结果\n\n"
				if len(pqResult.Times) > 0 {
					resultMarkdown += fmt.Sprintf("- **平均时间**: %s\n", formatMilliseconds(pqResult.AvgTime))
					resultMarkdown += fmt.Sprintf("- **最小时间**: %s\n", formatMilliseconds(pqResult.MinTime))
					resultMarkdown += fmt.Sprintf("- **最大时间**: %s\n", formatMilliseconds(pqResult.MaxTime))
					resultMarkdown += fmt.Sprintf("- **标准差**: %s\n", formatMilliseconds(pqResult.StdDev))
					resultMarkdown += fmt.Sprintf("- **成功次数**: %d次\n", len(pqResult.Times))
					resultMarkdown += fmt.Sprintf("- **平均CPU使用**: %s\n", formatCPUPercentage(pqResult.AvgCPU))
					resultMarkdown += fmt.Sprintf("- **最大CPU使用**: %s\n", formatCPUPercentage(pqResult.MaxCPU))
					resultMarkdown += fmt.Sprintf("- **平均内存增长**: %s\n", formatMemoryMB(pqResult.AvgMem))
					resultMarkdown += fmt.Sprintf("- **最大内存增长**: %s\n", formatMemoryMB(pqResult.MaxMem))
					
					// 显示数据传输测试结果（如果有）
					if len(pqResult.Throughputs) > 0 {
						resultMarkdown += "\n### 后量子TLS数据传输结果\n\n"
						resultMarkdown += fmt.Sprintf("- **平均发送吞吐量**: %s\n", formatThroughput(pqResult.AvgThroughput))
						resultMarkdown += fmt.Sprintf("- **最小发送吞吐量**: %s\n", formatThroughput(pqResult.MinThroughput))
						resultMarkdown += fmt.Sprintf("- **最大发送吞吐量**: %s\n", formatThroughput(pqResult.MaxThroughput))
						resultMarkdown += fmt.Sprintf("- **传输期间平均CPU使用**: %s\n", formatCPUPercentage(pqResult.AvgTransferCPU))
						resultMarkdown += fmt.Sprintf("- **传输期间最大CPU使用**: %s\n", formatCPUPercentage(pqResult.MaxTransferCPU))
						resultMarkdown += fmt.Sprintf("- **传输期间平均内存使用**: %s\n", formatMemoryMB(pqResult.AvgTransferMem))
						resultMarkdown += fmt.Sprintf("- **传输期间最大内存使用**: %s\n", formatMemoryMB(pqResult.MaxTransferMem))
					}
				}
				if pqResult.FailCount > 0 {
					resultMarkdown += fmt.Sprintf("- **失败次数**: %d次\n", pqResult.FailCount)
				}
				
				// 比较结果
				if len(standardResult.Times) > 0 && len(pqResult.Times) > 0 {
					resultMarkdown += fmt.Sprintf("\n## 📊 性能比较\n\n")
					
					// 时间比较
					timeRatio := float64(pqResult.AvgTime) / float64(standardResult.AvgTime)
					resultMarkdown += fmt.Sprintf("### 时间性能\n\n")
					resultMarkdown += fmt.Sprintf("- **时间比率**: 后量子TLS是标准TLS的 **%.2f倍**\n", timeRatio)
					if timeRatio > 1 {
						resultMarkdown += fmt.Sprintf("- **性能差异**: 后量子TLS比标准TLS慢 **%.1f%%**\n", (timeRatio-1)*100)
					} else {
						resultMarkdown += fmt.Sprintf("- **性能差异**: 后量子TLS比标准TLS快 **%.1f%%**\n", (1-timeRatio)*100)
					}
					resultMarkdown += fmt.Sprintf("- **绝对差异**: %.2f毫秒\n", float64(pqResult.AvgTime-standardResult.AvgTime)/1000000.0)
					
					// CPU使用率比较
					cpuRatio := pqResult.AvgCPU / standardResult.AvgCPU
					resultMarkdown += fmt.Sprintf("\n### CPU使用率性能\n\n")
					resultMarkdown += fmt.Sprintf("- **CPU使用率比率**: 后量子TLS是标准TLS的 **%.2f倍**\n", cpuRatio)
					if cpuRatio > 1 {
						resultMarkdown += fmt.Sprintf("- **CPU使用率差异**: 后量子TLS比标准TLS高 **%.1f%%**\n", (cpuRatio-1)*100)
					} else {
						resultMarkdown += fmt.Sprintf("- **CPU使用率差异**: 后量子TLS比标准TLS低 **%.1f%%**\n", (1-cpuRatio)*100)
					}
					resultMarkdown += fmt.Sprintf("- **绝对差异**: %.2f%%\n", pqResult.AvgCPU-standardResult.AvgCPU)
					
					// 内存使用量比较
					memRatio := pqResult.AvgMem / standardResult.AvgMem
					resultMarkdown += fmt.Sprintf("\n### 内存使用量性能\n\n")
					resultMarkdown += fmt.Sprintf("- **内存使用量比率**: 后量子TLS是标准TLS的 **%.2f倍**\n", memRatio)
					if memRatio > 1 {
						resultMarkdown += fmt.Sprintf("- **内存使用量差异**: 后量子TLS比标准TLS高 **%.1f%%**\n", (memRatio-1)*100)
					} else {
						resultMarkdown += fmt.Sprintf("- **内存使用量差异**: 后量子TLS比标准TLS低 **%.1f%%**\n", (1-memRatio)*100)
					}
					resultMarkdown += fmt.Sprintf("- **绝对差异**: %.2f MB\n", pqResult.AvgMem-standardResult.AvgMem)
					
					// 数据传输测试结果比较（如果有）
					if len(standardResult.Throughputs) > 0 && len(pqResult.Throughputs) > 0 {
						// 吞吐量比较
						throughputRatio := pqResult.AvgThroughput / standardResult.AvgThroughput
						resultMarkdown += fmt.Sprintf("\n### 数据发送吞吐量性能\n\n")
						resultMarkdown += fmt.Sprintf("- **发送吞吐量比率**: 后量子TLS是标准TLS的 **%.2f倍**\n", throughputRatio)
						if throughputRatio > 1 {
							resultMarkdown += fmt.Sprintf("- **性能差异**: 后量子TLS比标准TLS快 **%.1f%%**\n", (throughputRatio-1)*100)
						} else {
							resultMarkdown += fmt.Sprintf("- **性能差异**: 后量子TLS比标准TLS慢 **%.1f%%**\n", (1-throughputRatio)*100)
						}
						resultMarkdown += fmt.Sprintf("- **绝对差异**: %.2f Mbps\n", pqResult.AvgThroughput-standardResult.AvgThroughput)
						
						// 传输期间CPU使用率比较
						transferCPURatio := pqResult.AvgTransferCPU / standardResult.AvgTransferCPU
						resultMarkdown += fmt.Sprintf("\n### 数据传输期间CPU使用率\n\n")
						resultMarkdown += fmt.Sprintf("- **CPU使用率比率**: 后量子TLS是标准TLS的 **%.2f倍**\n", transferCPURatio)
						if transferCPURatio > 1 {
							resultMarkdown += fmt.Sprintf("- **资源消耗差异**: 后量子TLS比标准TLS高 **%.1f%%**\n", (transferCPURatio-1)*100)
						} else {
							resultMarkdown += fmt.Sprintf("- **资源消耗差异**: 后量子TLS比标准TLS低 **%.1f%%**\n", (1-transferCPURatio)*100)
						}
						resultMarkdown += fmt.Sprintf("- **绝对差异**: %.2f%%\n", pqResult.AvgTransferCPU-standardResult.AvgTransferCPU)
						
						// 传输期间内存使用比较
						transferMemRatio := pqResult.AvgTransferMem / standardResult.AvgTransferMem
						resultMarkdown += fmt.Sprintf("\n### 数据传输期间内存使用\n\n")
						resultMarkdown += fmt.Sprintf("- **内存使用比率**: 后量子TLS是标准TLS的 **%.2f倍**\n", transferMemRatio)
						if transferMemRatio > 1 {
							resultMarkdown += fmt.Sprintf("- **资源消耗差异**: 后量子TLS比标准TLS高 **%.1f%%**\n", (transferMemRatio-1)*100)
						} else {
							resultMarkdown += fmt.Sprintf("- **资源消耗差异**: 后量子TLS比标准TLS低 **%.1f%%**\n", (1-transferMemRatio)*100)
						}
						resultMarkdown += fmt.Sprintf("- **绝对差异**: %.2f MB\n", pqResult.AvgTransferMem-standardResult.AvgTransferMem)
					}
				}
				
				resultMarkdown += "\n---\n\n**测试完成时间**: " + time.Now().Format("2006-01-02 15:04:05")
			}

			// 更新UI
			statusLabel.SetText("测试完成")
			resultRichText.ParseMarkdown(resultMarkdown)
			progressBar.Hide()
			startBtn.Enable()
		}()
	}

	// 创建输入框容器
	makeInputRow := func(label string, entry *widget.Entry) *fyne.Container {
		labelWidget := widget.NewLabel(label)
		labelWidget.TextStyle = fyne.TextStyle{Bold: true}
		return container.NewBorder(nil, nil, labelWidget, nil, entry)
	}
	
	// 创建复选框容器
	makeCheckRow := func(label string, check *widget.Check) *fyne.Container {
		labelWidget := widget.NewLabel(label)
		labelWidget.TextStyle = fyne.TextStyle{Bold: true}
		return container.NewBorder(nil, nil, labelWidget, nil, check)
	}

	// 创建配置区域 - 压缩高度
	configArea := container.NewVBox(
		configTitle,
		widget.NewSeparator(),
		container.NewVBox(
			makeInputRow("服务器地址:", serverEntry),
			makeInputRow("测试次数:  ", testCountEntry),
			makeInputRow("CA证书路径:", caPathEntry),
			makeInputRow("客户端证书:", certPathEntry),
			makeInputRow("客户端密钥:", keyPathEntry),
			makeCheckRow("传输测试开关:", transferTestCheck),
			makeInputRow("传输测试时间:", transferTimeEntry),
			makeInputRow("传输数据大小:", transferSizeEntry),
		),
		container.NewHBox(
			layout.NewSpacer(),
			startBtn,
			layout.NewSpacer(),
		),
		progressBar,
		statusLabel,
	)

	// 创建主布局 - 调整分割比例，给结果区域更多空间
	split := container.NewVSplit(
		configArea,
		resultArea,
	)
	// 给结果区域更多空间 - 20%配置，80%结果
	split.Offset = 0.2

	myWindow.SetContent(split)
	myWindow.Resize(fyne.NewSize(800, 1000)) // 增加窗口高度
	myWindow.ShowAndRun()
}
