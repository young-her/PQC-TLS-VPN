package main

import (
    "crypto/tls"
    "log"
    "net"
    "os/exec"
    "github.com/songgao/water"
    "os"
)

func createTLSConfig(cert tls.Certificate) *tls.Config {
    keyLogFile, err := os.OpenFile("tls_keys.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        log.Fatalf("error: %v", err)
    }

    return &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS13,
        MaxVersion:   tls.VersionTLS13,
        KeyLogWriter: keyLogFile, 
    }
}

func main() {
    config := water.Config{DeviceType: water.TUN}
    iface, err := water.New(config)
    if err != nil {
        log.Fatalf("创建 TUN 接口失败: %v", err)
    }
    log.Printf("TUN 接口名称: %s", iface.Name())

    // 配置 TUN 接口
    setupTUN(iface.Name())
    
    cert, err := tls.LoadX509KeyPair("../../cert/server.crt", "../../cert/server.key")
    if err != nil {
        log.Fatalf("加载密钥对失败: %v", err)
    }
    
    // 配置 TLS 以支持 X25519Kyber768Draft00
    tlsConfig := createTLSConfig(cert)

    listener, err := tls.Listen("tcp", ":443", tlsConfig)
    if err != nil {
        log.Fatalf("监听失败: %v", err)
    }
    defer listener.Close()

    log.Println("服务器监听在 :443")

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("接受连接失败: %v", err)
            continue
        }
        log.Println("客户端已连接")
        go handleClient(conn, iface)
    }
}

// 配置 TUN 接口和系统网络设置
func setupTUN(tunName string) {
    // 为 TUN 接口分配 IP 地址 (10.0.0.1/24)
    if err := exec.Command("ip", "addr", "add", "10.0.0.1/24", "dev", tunName).Run(); err != nil {
        log.Printf("配置TUN IP地址失败: %v", err)
    }
    
    // 启动 TUN 接口
    if err := exec.Command("ip", "link", "set", "dev", tunName, "up").Run(); err != nil {
        log.Printf("启动TUN接口失败: %v", err)
    }
    
    // 添加路由，使客户端流量通过 TUN 接口
    if err := exec.Command("ip", "route", "add", "10.0.0.0/24", "dev", tunName).Run(); err != nil {
        log.Printf("添加路由失败: %v", err)
    }
    
    // 启用 IP 转发功能
    if err := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run(); err != nil {
        log.Printf("启用IP转发失败: %v", err)
    }
    
    // 添加FORWARD规则，允许流量转发
    if err := exec.Command("iptables", "-A", "FORWARD", "-i", tunName, "-j", "ACCEPT").Run(); err != nil {
        log.Printf("添加FORWARD规则失败: %v", err)
    }
    if err := exec.Command("iptables", "-A", "FORWARD", "-o", tunName, "-j", "ACCEPT").Run(); err != nil {
        log.Printf("添加FORWARD规则失败: %v", err)
    }
    
    // 配置 NAT，使客户端可以访问互联网
    if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.0.0.0/24", "-j", "MASQUERADE").Run(); err != nil {
        log.Printf("配置NAT失败: %v", err)
    }
    
    log.Printf("TUN 接口 %s 配置完成", tunName)
}

func handleClient(conn net.Conn, iface *water.Interface) {
    defer conn.Close()

    // 从客户端读取并写入 TUN
    go func() {
        buf := make([]byte, 1500)
        for {
            n, err := conn.Read(buf)
            if err != nil {
                log.Printf("从客户端读取失败: %v", err)
                return
            }
            
            if n > 0 && n > 20 {  // 确保至少有IP头部
                srcIP := net.IP(buf[12:16]).String()
                dstIP := net.IP(buf[16:20]).String()
                log.Printf("从客户端收到数据包: %s -> %s, 大小: %d", srcIP, dstIP, n)
            }
            
            _, err = iface.Write(buf[:n])
            if err != nil {
                log.Printf("写入 TUN 失败: %v", err)
                continue
            }
            log.Printf("写入 %d 字节到 TUN", n)
        }
    }()

    // 从 TUN 读取并发送到客户端
    buf := make([]byte, 1500)
    for {
        n, err := iface.Read(buf)
        if err != nil {
            log.Printf("从 TUN 读取失败: %v", err)
            continue
        }
        
        if n > 0 && n > 20 {  // 确保至少有IP头部
            srcIP := net.IP(buf[12:16]).String()
            dstIP := net.IP(buf[16:20]).String()
            log.Printf("从TUN收到数据包: %s -> %s, 大小: %d", srcIP, dstIP, n)
        }
        
        _, err = conn.Write(buf[:n])
        if err != nil {
            log.Printf("发送到客户端失败: %v", err)
            return
        }
        log.Printf("发送 %d 字节到客户端", n)
    }
}

