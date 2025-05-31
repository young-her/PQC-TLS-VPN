# PQC-TLS-VPN: 探索基于 TLS 的 VPN 中的后量子密码学

本项目实现并基准测试了使用标准 TLS 1.3 以及使用后量子密码学 (PQC) 增强的 TLS 1.3 的 VPN 客户端和服务器，特别探索了 `X25519MLKEM768` (Kyber-768) 密钥交换机制。此外，项目还包含一个实验性的客户端，该客户端演示了在初始 TLS 连接之上隧道化的自定义 PQC 握手协议（Kyber KEM + Dilithium 签名）。

本项目提供：

* 标准 TLS 1.3 VPN 客户端和服务器。

* PQC 增强的 TLS 1.3 VPN 客户端（使用 `X25519MLKEM768`）和服务器。

* 部分客户端版本的图形用户界面 (GUI)，使用 Fyne 构建。

* 部分客户端版本的命令行界面 (CLI)。

* 基准测试工具，用于比较标准 TLS 和 PQC-TLS 之间的握手性能（时间、CPU、内存）和数据吞吐量。

* 一个实验性的 CLI 客户端，演示了使用 CIRCL 库中的 Kyber 和 Dilithium 的自定义 PQC 握手层，该握手层运行在标准 TLS 连接之上。

## 主要特性

* **VPN 功能：** 使用 TUN 接口安全地隧道化 IP 流量。

* **TLS 1.3 安全性：** 利用 TLS 1.3 实现强大的信道加密。

* **后量子密码学：**

  * 在 TLS 1.3 握手中集成 `X25519MLKEM768`（Kyber-768 的一种变体）进行密钥交换，提供抗量子密钥建立。

  * 包含一个实验性客户端，其具有使用 Kyber KEM 和 Dilithium 签名的自定义 PQC 协议层。

* **基准测试套件：**

  * 客户端工具，用于比较标准 TLS 与 PQC-TLS 的握手时间、握手期间的 CPU/内存使用情况以及数据传输性能。

  * 服务器端工具，用于监控和记录握手负载下的性能指标。

* **用户界面：**

  * 为 PQC-TLS 和标准 TLS VPN 客户端提供了易于使用的基于 Fyne 的 GUI。

  * 显示连接状态、实时统计信息（传输速度、数据量、连接时长）和系统日志。

  * 在 UI 客户端中包含 TLS 握手测试功能。

* **跨平台 (有条件)：**

  * Go 和 Fyne 是跨平台的。

  * TUN 设备设置和用于资源测量的 `ps` 命令特定于 Linux/macOS。Windows 用户可能需要调整这些部分。

* **证书管理：** 使用 X.509 证书进行身份验证（CA、服务器和客户端证书）。

* **密钥记录：** 支持 TLS 密钥记录 (`tls_keys.log`)，以便使用 Wireshark 等工具进行调试和流量分析。

## 项目结构

仓库结构如下：

```text
PQC-TLS-VPN/
├── cert/                       # (假设的) 证书目录
├── tls_vpn_client/
│   ├── code/
│   │   ├── PQ-TLS/
│   │   │   ├── benchmark.go    # 客户端 PQC/标准 TLS 握手和传输基准测试工具 (GUI)
│   │   │   ├── client.go       # CLI VPN 客户端，具有自定义 PQC 握手 (Kyber+Dilithium over TLS)
│   │   │   └── client_ui.go    # GUI VPN 客户端，使用 PQC 增强的 TLS 1.3 (X25519MLKEM768)
│   │   └── TLS/
│   │       ├── client.go       # CLI VPN 客户端，使用标准 TLS 1.3
│   │       └── client_ui.go    # GUI VPN 客户端，使用标准 TLS 1.3
│   └── ...
├── tls_vpn_server/
│   ├── code/
│   │   ├── PQ-TLS/
│   │   │   ├── benchmark.go    # 服务器端握手性能基准测试工具
│   │   │   └── server.go       # VPN 服务器 (如果客户端提议，则支持 PQC 增强的 TLS 1.3)
│   │   └── TLS/
│   │       └── server.go       # VPN 服务器 (标准 TLS 1.3)
│   └── ...
└── README.md                   # 本文档
```

* **`tls_vpn_client/code/PQ-TLS/`**: 包含与后量子密码学相关的客户端和工具。

  * `benchmark.go`: 一个 GUI 工具，用于运行和比较标准 TLS 与 PQC-TLS (使用 `X25519MLKEM768`) 的握手和数据传输性能。

  * `client.go`: 一个基于 CLI 的 VPN 客户端，首先建立标准 TLS 连接，然后执行额外的自定义 PQC 握手，使用 Kyber 进行密钥封装，使用 Dilithium 进行签名，以建立用于数据加密的独立共享密钥。这是一种实验性方法。

  * `client_ui.go`: 一个基于 GUI 的 VPN 客户端，使用标准 TLS 1.3，但如果服务器支持，则优先使用 `X25519MLKEM768` 进行密钥交换。

* **`tls_vpn_client/code/TLS/`**: 包含使用标准 TLS 1.3 且未进行 PQC 修改的客户端。

  * `client.go`: 一个基于 CLI 的 VPN 客户端，使用标准 TLS 1.3。

  * `client_ui.go`: 一个基于 GUI 的 VPN 客户端，使用标准 TLS 1.3。

* **`tls_vpn_server/code/PQ-TLS/`**:

  * `benchmark.go`: 一个服务器，设计用于处理大量握手尝试并记录性能统计信息（握手时间、CPU/内存使用情况）。

  * `server.go`: 一个 VPN 服务器。虽然位于 PQ-TLS 目录中，但其代码是一个标准的 TLS 1.3 服务器。如果客户端提议并且底层的 Go 加密库支持，它将协商 PQC 密码套件（如 `X25519MLKEM768`）。它会将 TLS 会话密钥保存到 `tls_keys.log`。

* **`tls_vpn_server/code/TLS/`**:

  * `server.go`: 一个标准的 TLS 1.3 VPN 服务器，功能上类似于 `PQ-TLS/` 中的服务器，但在概念上是分开的。它也会将 TLS 会话密钥保存到 `tls_keys.log`。

##核心技术

* **Go (Golang):** 用于客户端、服务器和基准测试工具的核心逻辑。

* **Fyne:** 用于部分 VPN 客户端的图形用户界面。

* **TLS 1.3:** 安全通信的标准。

* **`crypto/tls` (Go 标准库):** 用于 TLS 实现。PQC 支持依赖于所使用的 Go 版本的功能

* **`X25519MLKEM768` (Kyber):** 用于 TLS 1.3 中混合密钥交换的后量子密钥封装机制。

* **`github.com/songgao/water`:** 用于创建和管理 TUN 网络接口。

* **`ps` 命令:** 基准测试工具用于测量 CPU 使用率 (Linux/macOS)。

## 证书设置

本项目需要 X.509 证书来实现客户端和服务器之间的相互身份验证。您将需要：

1. 一个证书颁发机构 (CA) 证书 (`ca.crt`)。

2. 一个服务器证书 (`server.crt`) 和私钥 (`server.key`)，由您的 CA 签署。

3. 一个客户端证书 (`client.crt`) 和私钥 (`client.key`)，由您的 CA 签署。

代码通常以相对路径（如 `../../cert/`）引用这些证书。这意味着您应该在项目根目录下创建一个 `cert` 目录 (例如, `PQC-TLS-VPN/cert/`) 并将这些文件放在那里。

您可以使用 OpenSSL 或其他证书管理工具生成这些证书。请确保服务器证书中的通用名称 (CN) 或主题备用名称 (SAN) 与客户端用于连接的地址匹配。

## 构建和运行

### 前置条件

* **Go:** 1.19 或更高版本 (以便 `crypto/tls` 支持 `X25519MLKEM768`)。

* **GCC/Cgo:** Fyne 应用程序需要。

* **Fyne 依赖项:** 根据您操作系统的 Fyne 文档安装 (例如，Linux 上的图形驱动程序、X11 开发库)。

* **TUN 设备:**

  * **Linux:** 确保 `tun` 模块已加载。应用程序尝试使用 `ip` 和 `iptables` 命令配置 TUN 接口。您可能需要使用 `sudo` 运行服务器和客户端应用程序，或调整网络配置的权限/能力。

  * **macOS:** 通常支持 TUN。

  * **Windows:** TUN 设置不同 (例如，OpenVPN TAP 驱动程序)。提供的脚本主要针对 Linux。

* **`ps` 命令:** 用于基准测试工具中的 CPU 使用率指标 (在 Linux/macOS 上可用)。

### 1. VPN 服务器

两个服务器默认在端口 `443` 上侦听，并需要 `server.crt` 和 `server.key`。它们还会将 TLS 主密钥输出到各自目录中的 `tls_keys.log`。

**A. 标准 TLS 服务器:**

```shell
cd tls_vpn_server/code/TLS/
go build -o vpn_server_tls server.go
sudo ./vpn_server_tls # 可能需要 sudo 进行网络配置
```

**B. 支持 PQC-TLS 的服务器:**
此服务器本质上是一个 TLS 1.3 服务器，如果客户端 (例如 `PQ-TLS/client_ui.go`) 提议，它可以协商 PQC 密码套件，如 `X25519MLKEM768`。

```shell
cd tls_vpn_server/code/PQ-TLS/
go build -o vpn_server_pqtls server.go
sudo ./vpn_server_pqtls # 可能需要 sudo 进行网络配置
```

### 2. VPN 客户端 (GUI)

这些客户端需要 `ca.crt`、`client.crt` 和 `client.key`。默认服务器地址是 `10.37.129.4:443`，可以在 UI 中更改。

**A. 标准 TLS GUI 客户端:**

```shell
cd tls_vpn_client/code/TLS/
go build -o vpn_client_tls_ui client_ui.go
sudo ./vpn_client_tls_ui # 可能需要 sudo 进行网络配置
```

**B. PQC-TLS GUI 客户端 (在 TLS 1.3 中使用 X25519MLKEM768):**
此客户端将在 TLS 1.3 握手期间尝试使用 `X25519MLKEM768`。

```shell
cd tls_vpn_client/code/PQ-TLS/
go build -o vpn_client_pqtls_ui client_ui.go
sudo ./vpn_client_pqtls_ui # 可能需要 sudo 进行网络配置
```

GUI 客户端还具有“测试 TLS 握手”功能，用于测量与配置服务器的握手性能。

### 3. VPN 客户端 (CLI)

**A. 标准 TLS CLI 客户端:**

```shell
cd tls_vpn_client/code/TLS/
go build -o vpn_client_tls_cli client.go
sudo ./vpn_client_tls_cli # 可能需要 sudo 进行网络配置
```

**B. 自定义 PQC 握手 CLI 客户端 (Kyber+Dilithium over TLS):**
此客户端首先执行标准 TLS 握手，然后执行使用 Kyber 和 Dilithium 的额外自定义 PQC 握手。请确保其连接的服务器是标准 TLS 服务器（例如 `tls_vpn_server/code/TLS/server.go` 或 `tls_vpn_server/code/PQ-TLS/server.go`，因为它们未实现此自定义 PQC 握手的服务器端）。自定义 PQC 部分旨在在初始 TLS 设置*之后*保护数据。

```shell
cd tls_vpn_client/code/PQ-TLS/
go build -o vpn_client_custom_pqc_cli client.go
sudo ./vpn_client_custom_pqc_cli # 可能需要 sudo 进行网络配置
```

**注意:** 针对此特定自定义 PQC 握手客户端 (`vpn_client_custom_pqc_cli`) 的服务器端逻辑并未明确存在于提供的服务器文件中。这些服务器充当标准 TLS 端点。此客户端似乎是在已建立的 TLS 通道上分层 PQC 的实验。

### 4. 基准测试工具

**A. 客户端握手和传输基准测试 (GUI):**
此工具 (`tls_vpn_client/code/PQ-TLS/benchmark.go`) 连接到服务器（理想情况下是 `tls_vpn_server/code/PQ-TLS/benchmark.go` 服务器或任何标准/PQC-TLS 服务器），并对标准 TLS 和 PQC-TLS（使用 `X25519MLKEM768`）执行多次握手测试。它测量握手时间、CPU/内存使用情况（客户端）以及可选的数据传输吞吐量。

```shell
cd tls_vpn_client/code/PQ-TLS/
go build -o pq_std_benchmark_client benchmark.go
./pq_std_benchmark_client
```

在 UI 中配置服务器地址、证书路径和测试参数。

**B. 服务器端握手基准测试:**
此服务器 (`tls_vpn_server/code/PQ-TLS/benchmark.go`) 设计用于接收大量的 TLS 握手尝试。它记录有关握手持续时间、成功/失败率以及服务器端 CPU/内存消耗的详细统计信息。它旨在与进行大量连接尝试的客户端（如客户端基准测试工具或脚本）一起使用。

```shell
cd tls_vpn_server/code/PQ-TLS/
go build -o benchmark_server benchmark.go
./benchmark_server
```

它在端口 `443` 上侦听，并使用 `../../cert/server.crt` 和 `../../cert/server.key`。

## 关于 PQC 实现的说明

* **集成的 PQC (TLS 1.3 中的 X25519MLKEM768):**

  * 用于 `tls_vpn_client/code/PQ-TLS/client_ui.go` 和客户端 `benchmark.go`。

  * 依赖于 Go 内置的对 `X25519MLKEM768` 的支持 (在 Go 1.19+ 中可用)，通过 `tls.Config.CurvePreferences` 实现。

  * 如果客户端提议并且其 Go 版本支持，服务器 (`tls_vpn_server/code/PQ-TLS/server.go` 和 `tls_vpn_server/code/TLS/server.go`) 将协商此机制。

* **自定义 PQC 协议 (基于 TLS 的 Kyber KEM + Dilithium 签名):**

  * 在 `tls_vpn_client/code/PQ-TLS/client.go` 中实现。

  * 此客户端执行标准 TLS 1.3 握手，然后发送 Kyber 公钥。服务器（如果是自定义 PQC 服务器）将使用 Dilithium 对其进行签名并响应密文（封装的共享密钥）。客户端验证签名并解封装共享密钥。

  * 这会建立一个 PQC 派生的共享密钥，该密钥*独立于*初始 TLS 握手的主密钥。

  * **重要提示:** 提供的服务器文件（两个服务器目录中的 `server.go`）**不包含**此自定义 PQC 握手的相应服务器端逻辑。它们充当标准 TLS 服务器。此客户端是一个实验性演示。

## 使用方法

1. **设置证书:** 确保您的 `cert/` 目录中包含必要的 CA、服务器和客户端证书及密钥。

2. **启动服务器:** 选择并运行一个 VPN 服务器 (例如 `vpn_server_pqtls`)。记下其 IP 地址。

3. **启动客户端:**

   * **GUI 客户端:** 运行所需的 GUI 客户端 (例如 `vpn_client_pqtls_ui`)。如果服务器 IP 地址与默认值不同，请输入它。如果证书路径与客户端中编码的默认路径 (`../../cert/`) 不同，请配置它们。点击“连接”。在 UI 中监控状态、日志和统计信息。使用“测试 TLS 握手”功能进行快速性能检查。

   * **CLI 客户端:** 运行所选的 CLI 客户端。它将尝试使用硬编码或默认参数进行连接。

4. **基准测试:**

   * 如果要测试高负载下的服务器端性能，请运行 `benchmark_server`。

   * 运行 `pq_std_benchmark_client` GUI 工具。配置服务器地址（可以是 `benchmark_server` 或 VPN 服务器之一）和证书路径。开始测试。结果将显示在 UI 中。

##潜在问题和注意事项

* **权限:** 运行客户端和服务器可能需要 `sudo` 或特定的网络能力来配置 TUN 接口和路由。

* **平台特性:** TUN/TAP 设置和用于 CPU 指标的 `ps` 命令主要适用于 Linux/macOS。Windows 用户需要进行调整。

* **证书路径:** 确保代码中的证书路径与您的设置匹配，或相应地修改它们。客户端和基准测试工具通常硬编码了这些路径。

* **防火墙:** 确保您的防火墙允许 VPN 端口（默认为 443/TCP）上的流量，并允许通过 TUN 接口的流量。

* **实验性质:** 本项目用于探索和基准测试。自定义 PQC 协议客户端尤其具有实验性，并且缺少其独特握手的相应服务器实现。
