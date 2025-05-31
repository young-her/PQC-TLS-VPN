package main

import (
    "crypto/tls"
    "log"
    "os/exec"
    "github.com/songgao/water"
)

func main() {
    config := water.Config{DeviceType: water.TUN}
    iface, err := water.New(config)
    if err != nil {
        log.Fatalf("创建 TUN 接口失败: %v", err)
    }
    log.Printf("TUN 接口名称: %s", iface.Name())
    
    // 添加TUN接口配置
    setupTUN(iface.Name())

    tlsConfig := &tls.Config{
        InsecureSkipVerify: true,
        MinVersion:         tls.VersionTLS13,
        MaxVersion:         tls.VersionTLS13,
    }
    conn, err := tls.Dial("tcp", "10.211.55.3:443", tlsConfig)
    if err != nil {
        log.Fatalf("连接服务器失败: %v", err)
    }
    defer conn.Close()

    // 从 TUN 读取并发送到服务器
    go func() {
        buf := make([]byte, 1500)
        for {
            n, err := iface.Read(buf)
            if err != nil {
                log.Printf("从 TUN 读取失败: %v", err)
                continue
            }
            _, err = conn.Write(buf[:n])
            if err != nil {
                log.Printf("发送到服务器失败: %v", err)
                continue
            }
            log.Printf("发送 %d 字节到服务器", n)
        }
    }()

    // 从服务器读取并写回 TUN
    buf := make([]byte, 1500)
    for {
        n, err := conn.Read(buf)
        if err != nil {
            log.Printf("从服务器读取失败: %v", err)
            continue
        }
        _, err = iface.Write(buf[:n])
        if err != nil {
            log.Printf("写回 TUN 失败: %v", err)
            continue
        }
        log.Printf("写回 %d 字节到 TUN", n)
    }
}
// 添加TUN接口配置函数
func setupTUN(tunName string) {
    // 为TUN接口分配IP地址(10.0.0.2/24)，需要与服务器端在同一子网
    exec.Command("ip", "addr", "add", "10.0.0.2/24", "dev", tunName).Run()
    
    // 启动TUN接口
    exec.Command("ip", "link", "set", "dev", tunName, "up").Run()
    
    // 添加路由，使目标为8.8.8.8的流量通过VPN
    exec.Command("ip", "route", "add", "default", "via", "10.0.0.1", "dev", tunName).Run()
    
    log.Printf("TUN 接口 %s 配置完成", tunName)
}