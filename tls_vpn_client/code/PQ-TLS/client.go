package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/songgao/water"
)

// 后量子密码学握手管理器
type PostQuantumHandshake struct {
	conn          net.Conn
	sharedKey     []byte
	encryptCipher cipher.AEAD
	decryptCipher cipher.AEAD

	// 客户端专用
	kyberSk kem.PrivateKey // 客户端的临时密钥封装密钥
}

// 创建新的后量子握手管理器
func NewPostQuantumHandshake(conn net.Conn) *PostQuantumHandshake {
	return &PostQuantumHandshake{
		conn: conn,
	}
}

// 客户端执行后量子握手
func (pq *PostQuantumHandshake) ClientHandshake() error {
	dilithiumScheme := mode2.Scheme()
	kyberScheme := kyber512.Scheme()

	// 1. 客户端生成Kyber密钥对
	kyberPk, kyberSk, err := kyberScheme.GenerateKeyPair()
	if err != nil {
		return err
	}
	pq.kyberSk = kyberSk

	// 2. 构造ClientHello消息，包含Kyber公钥
	kyberPkBytes, err := kyberPk.MarshalBinary()
	if err != nil {
		return err
	}
	fmt.Printf("Kyber公钥: %x\n", kyberPkBytes)
	fmt.Printf("Kyber公钥长度: %d\n", len(kyberPkBytes))

	// ClientHello = Kyber公钥长度(2字节) + Kyber公钥
	clientHelloSize := 2 + len(kyberPkBytes)
	clientHello := make([]byte, clientHelloSize)

	binary.BigEndian.PutUint16(clientHello[0:], uint16(len(kyberPkBytes)))
	copy(clientHello[2:], kyberPkBytes)
	fmt.Printf("ClientHello: %x\n", clientHello)

	// 3. 发送ClientHello
	binary.Write(pq.conn, binary.BigEndian, uint16(clientHelloSize))
	_, err = pq.conn.Write(clientHello)
	if err != nil {
		return err
	}

	// 4. 接收ServerHello
	var serverHelloSize uint16
	if err := binary.Read(pq.conn, binary.BigEndian, &serverHelloSize); err != nil {
		return err
	}
	fmt.Printf("ServerHello大小: %d\n", serverHelloSize)

	serverHello := make([]byte, serverHelloSize)
	if _, err := io.ReadFull(pq.conn, serverHello); err != nil {
		return err
	}
	fmt.Printf("ServerHello: %x\n", serverHello)

	// 5. 解析ServerHello
	r := 0 // 读取指针

	// 读取服务端Dilithium公钥
	var dilithiumPkSize uint16
	dilithiumPkSize = binary.BigEndian.Uint16(serverHello[r:])
	r += 2

	var serverDilithiumPk sign.PublicKey
	serverDilithiumPk, err = dilithiumScheme.UnmarshalBinaryPublicKey(serverHello[r : r+int(dilithiumPkSize)])
	if err != nil {
		return err
	}
	r += int(dilithiumPkSize)

	// 读取密文
	var ciphertextSize uint16
	ciphertextSize = binary.BigEndian.Uint16(serverHello[r:])
	r += 2
	ciphertext := serverHello[r : r+int(ciphertextSize)]
	r += int(ciphertextSize)

	// 读取签名
	var signatureSize uint16
	signatureSize = binary.BigEndian.Uint16(serverHello[r:])
	r += 2
	signature := serverHello[r : r+int(signatureSize)]

	// 6. 验证服务端签名
	if !dilithiumScheme.Verify(serverDilithiumPk, ciphertext, signature, nil) {
		return errors.New("服务端签名验证失败")
	}

	// 7. 使用客户端的Kyber私钥解密密文，获取共享密钥
	sharedSecret, err := kyberScheme.Decapsulate(pq.kyberSk, ciphertext)
	if err != nil {
		return err
	}

	// 8. 保存共享密钥并设置加密/解密器
	pq.sharedKey = sharedSecret
	return pq.setupCiphers()
}

// 从共享密钥派生加密/解密密钥
func (pq *PostQuantumHandshake) deriveKey(purpose string, length int) []byte {
	h := hmac.New(sha256.New, pq.sharedKey)
	h.Write([]byte(purpose))
	return h.Sum(nil)[:length]
}

// 设置 AES-GCM 加密/解密器
func (pq *PostQuantumHandshake) setupCiphers() error {
	// 客户端的加密/解密密钥与服务端相反
	encKey := pq.deriveKey("decryption", 32) // 注意这里交换了
	decKey := pq.deriveKey("encryption", 32) // 注意这里交换了

	// 创建加密器
	encBlock, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	pq.encryptCipher, err = cipher.NewGCM(encBlock)
	if err != nil {
		return err
	}

	// 创建解密器
	decBlock, err := aes.NewCipher(decKey)
	if err != nil {
		return err
	}
	pq.decryptCipher, err = cipher.NewGCM(decBlock)
	if err != nil {
		return err
	}

	return nil
}

// 加密和解密方法与服务端相同
func (pq *PostQuantumHandshake) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, pq.encryptCipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return pq.encryptCipher.Seal(nonce, nonce, plaintext, nil), nil
}

func (pq *PostQuantumHandshake) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := pq.decryptCipher.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("密文太短")
	}

	nonce := ciphertext[:nonceSize]
	return pq.decryptCipher.Open(nil, nonce, ciphertext[nonceSize:], nil)
}

func main() {
	// 创建并配置TUN接口
	config := water.Config{DeviceType: water.TUN}
	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("创建 TUN 接口失败: %v", err)
	}
	log.Printf("TUN 接口名称: %s", iface.Name())

	// 配置TUN接口
	setupTUN(iface.Name())

	// 设置TLS连接
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
	log.Println("已连接到服务器，开始后量子握手")

	// 执行后量子握手
	pq := NewPostQuantumHandshake(conn)
	if err := pq.ClientHandshake(); err != nil {
		log.Fatalf("后量子握手失败: %v", err)
	}
	log.Println("后量子握手成功完成")

	// 从 TUN 读取并发送到服务器
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err := iface.Read(buf)
			if err != nil {
				log.Printf("从 TUN 读取失败: %v", err)
				continue
			}

			// 为数据包添加日志记录（如果是IP包）
			if n > 20 {
				srcIP := net.IP(buf[12:16]).String()
				dstIP := net.IP(buf[16:20]).String()
				log.Printf("从TUN读取数据包: %s -> %s, 大小: %d", srcIP, dstIP, n)
			}

			// 加密数据
			encryptedData, err := pq.Encrypt(buf[:n])
			if err != nil {
				log.Printf("加密失败: %v", err)
				continue
			}

			_, err = conn.Write(encryptedData)
			if err != nil {
				log.Printf("发送到服务器失败: %v", err)
				continue
			}
			log.Printf("发送 %d 字节加密数据到服务器", len(encryptedData))
		}
	}()

	// 从服务器读取并写回 TUN
	buf := make([]byte, 2000) // 加密会增加数据长度
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("从服务器读取失败: %v", err)
			continue
		}

		// 解密数据
		decryptedData, err := pq.Decrypt(buf[:n])
		if err != nil {
			log.Printf("解密失败: %v", err)
			continue
		}

		// 为数据包添加日志记录（如果是IP包）
		if len(decryptedData) > 20 {
			srcIP := net.IP(decryptedData[12:16]).String()
			dstIP := net.IP(decryptedData[16:20]).String()
			log.Printf("从服务器收到数据包: %s -> %s, 大小: %d", srcIP, dstIP, len(decryptedData))
		}

		_, err = iface.Write(decryptedData)
		if err != nil {
			log.Printf("写回 TUN 失败: %v", err)
			continue
		}
		log.Printf("写回 %d 字节解密数据到 TUN", len(decryptedData))
	}
}

// 添加TUN接口配置函数
func setupTUN(tunName string) {
	// 为TUN接口分配IP地址(10.0.0.2/24)，需要与服务器端在同一子网
	if err := exec.Command("ip", "addr", "add", "10.0.0.2/24", "dev", tunName).Run(); err != nil {
		log.Printf("配置TUN IP地址失败: %v", err)
	}

	// 启动TUN接口
	if err := exec.Command("ip", "link", "set", "dev", tunName, "up").Run(); err != nil {
		log.Printf("启动TUN接口失败: %v", err)
	}

	// 添加路由，使目标为8.8.8.8的流量通过VPN
	if err := exec.Command("ip", "route", "add", "default", "via", "10.0.0.1", "dev", tunName).Run(); err != nil {
		log.Printf("添加路由失败: %v", err)
	}

	log.Printf("TUN 接口 %s 配置完成", tunName)
}
