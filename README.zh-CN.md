# TLS Extension TLS13

[![PHP 版本](https://img.shields.io/badge/php-%3E%3D8.1-blue)](https://php.net/)
[![许可证](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![构建状态](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/your-org/your-repo)
[![代码覆盖率](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/your-org/your-repo)

[English](README.md) | [中文](README.zh-CN.md)

TLS 1.3 扩展包 - 为安全通信协议提供的 TLS 1.3 特定扩展的全面实现。

## 目录

- [功能特性](#功能特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [依赖项](#依赖项)
- [基本用法](#基本用法)
- [高级用法](#高级用法)
- [API 参考](#api-参考)
- [测试](#测试)
- [贡献](#贡献)
- [许可证](#许可证)

## 功能特性

此包实现了关键的 TLS 1.3 特定扩展：

- **密钥共享扩展** - 为 TLS 1.3 实现 Diffie-Hellman 密钥交换
- **预共享密钥扩展** - 支持基于 PSK 的身份验证和会话恢复
- **早期数据扩展** - 启用 0-RTT 数据传输
- **握手后身份验证扩展** - 支持握手后的客户端身份验证
- **Cookie 扩展** - 提供无状态操作支持

## 安装

```bash
composer require tourze/tls-extension-tls13
```

### 系统要求

- PHP 8.1 或更高版本
- tourze/tls-common
- tourze/tls-extension-naming
- tourze/tls-extension-secure
- tourze/tls-handshake-flow

## 快速开始

只需几行代码即可开始使用 TLS 1.3 扩展：

```php
<?php

use Tourze\TLSExtensionTLS13\Extension\KeyShareExtension;
use Tourze\TLSExtensionTLS13\Extension\KeyShareEntry;

// 创建简单的密钥共享扩展
$keyShare = new KeyShareExtension();
$entry = new KeyShareEntry();
$entry->setGroup(0x001d); // X25519
$entry->setKeyExchange(random_bytes(32));
$keyShare->addEntry($entry);

// 编码用于传输
$data = $keyShare->encode();

// 解码接收的数据
$decoded = KeyShareExtension::decode($data);
echo "扩展类型: " . $decoded->getType() . "\n";
```

就是这样！您现在拥有了一个可工作的 TLS 1.3 密钥共享扩展。

## 依赖项

此包依赖于几个核心 TLS 包：

```json
{
  "tourze/tls-common": "0.0.*",
  "tourze/tls-extension-naming": "0.0.*", 
  "tourze/tls-extension-secure": "^1.0",
  "tourze/tls-handshake-flow": "0.0.*"
}
```

## 基本用法

### 密钥共享扩展

```php
use Tourze\TLSExtensionTLS13\Extension\KeyShareExtension;
use Tourze\TLSExtensionTLS13\Extension\KeyShareEntry;

// 创建密钥共享扩展
$keyShare = new KeyShareExtension(false); // false = 客户端格式

// 添加密钥共享条目
$entry = new KeyShareEntry();
$entry->setGroup(0x001d); // X25519
$entry->setKeyExchange(random_bytes(32));
$keyShare->addEntry($entry);

// 编码为二进制数据
$binaryData = $keyShare->encode();

// 从二进制数据解码
$decoded = KeyShareExtension::decode($binaryData, false);
```

### 预共享密钥扩展

```php
use Tourze\TLSExtensionTLS13\Extension\PreSharedKeyExtension;
use Tourze\TLSExtensionTLS13\Extension\PSKIdentity;

// 创建 PSK 扩展
$psk = new PreSharedKeyExtension(false); // false = 客户端格式

// 添加 PSK 标识
$identity = new PSKIdentity();
$identity->setIdentity('session-ticket-data');
$identity->setObfuscatedTicketAge(1000);
$psk->addIdentity($identity);

// 添加绑定器
$psk->addBinder(hash('sha256', 'binder-key', true));

// 编码和解码
$encoded = $psk->encode();
$decoded = PreSharedKeyExtension::decode($encoded, false);
```

## 高级用法

### 自定义密钥交换组

```php
// 支持不同的密钥交换组
$entry = new KeyShareEntry();
$entry->setGroup(0x0017); // secp256r1
$entry->setKeyExchange($publicKey);

// 服务器端密钥共享（单个条目）
$serverKeyShare = new KeyShareExtension(true); // true = 服务器格式
$serverKeyShare->addEntry($entry);
```

### PSK 服务器选择

```php
// 服务器端 PSK 扩展（标识选择）
$serverPsk = new PreSharedKeyExtension(true); // true = 服务器格式
$serverPsk->setSelectedIdentity(0); // 选择第一个标识
```

### 扩展验证

```php
// 检查扩展是否适用于 TLS 版本
if ($keyShare->isApplicableForVersion('1.3')) {
    // 使用扩展
    $data = $keyShare->encode();
}

// 获取扩展类型
$type = $keyShare->getType(); // 返回 ExtensionType::KEY_SHARE->value
```

## API 参考

### KeyShareExtension

```php
class KeyShareExtension extends AbstractExtension
{
    public function __construct(bool $isServerFormat = false)
    public function getType(): int
    public function isServerFormat(): bool
    public function getEntries(): array
    public function setEntries(array $entries): self
    public function addEntry(KeyShareEntry $entry): self
    public function getEntryByGroup(int $group): ?KeyShareEntry
    public function encode(): string
    public static function decode(string $data, bool $isServerFormat = false): static
    public function isApplicableForVersion(string $tlsVersion): bool
}
```

### PreSharedKeyExtension

```php
class PreSharedKeyExtension extends AbstractExtension
{
    public function __construct(bool $isServerFormat = false)
    public function getType(): int
    public function isServerFormat(): bool
    public function getIdentities(): array
    public function setIdentities(array $identities): self
    public function addIdentity(PSKIdentity $identity): self
    public function getBinders(): array
    public function setBinders(array $binders): self
    public function addBinder(string $binder): self
    public function getSelectedIdentity(): int
    public function setSelectedIdentity(int $selectedIdentity): self
    public function encode(): string
    public static function decode(string $data, bool $isServerFormat = false): static
    public function isApplicableForVersion(string $tlsVersion): bool
}
```

## 测试

```bash
# 运行测试
./vendor/bin/phpunit packages/tls-extension-tls13/tests

# 运行带覆盖率的测试
./vendor/bin/phpunit packages/tls-extension-tls13/tests --coverage-html coverage

# 静态分析
./vendor/bin/phpstan analyse packages/tls-extension-tls13/src
```

## 贡献

1. Fork 仓库
2. 创建您的功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开一个 Pull Request

请确保所有测试通过，代码遵循 PSR-12 标准。

## 许可证

该项目基于 MIT 许可证授权 - 查看 [LICENSE](LICENSE) 文件了解详情。 