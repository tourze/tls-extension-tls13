<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Extension;

use Tourze\TLSExtensionNaming\Extension\AbstractExtension;
use Tourze\TLSExtensionNaming\Extension\ExtensionType;
use Tourze\TLSExtensionTLS13\Exception\InvalidExtensionDataException;

/**
 * 密钥共享扩展
 *
 * TLS 1.3中引入的扩展，用于传输密钥协商参数
 *
 * 参考：RFC 8446 (TLS 1.3) Section 4.2.8
 */
final class KeyShareExtension extends AbstractExtension
{
    /**
     * 密钥共享条目列表
     *
     * @var array<KeyShareEntry>
     */
    private array $entries = [];

    /**
     * 构造函数
     *
     * @param bool $isServerFormat 是否为服务器格式
     */
    public function __construct(private readonly bool $isServerFormat = false)
    {
    }

    /**
     * 获取扩展类型
     *
     * @return int 扩展类型值
     */
    public function getType(): int
    {
        return ExtensionType::KEY_SHARE->value;
    }

    /**
     * 检查是否为服务器格式
     *
     * @return bool 是否为服务器格式
     */
    public function isServerFormat(): bool
    {
        return $this->isServerFormat;
    }

    /**
     * 获取密钥共享条目列表
     *
     * @return array<KeyShareEntry> 密钥共享条目列表
     */
    public function getEntries(): array
    {
        return $this->entries;
    }

    /**
     * 设置密钥共享条目列表
     *
     * @param array<KeyShareEntry> $entries 密钥共享条目列表
     */
    public function setEntries(array $entries): void
    {
        $this->entries = $entries;
    }

    /**
     * 添加密钥共享条目
     *
     * @param KeyShareEntry $entry 密钥共享条目
     *
     * @return self 返回自身以支持链式调用
     */
    public function addEntry(KeyShareEntry $entry): self
    {
        $this->entries[] = $entry;

        return $this;
    }

    /**
     * 根据组标识符获取密钥共享条目
     *
     * @param int $group 组标识符
     *
     * @return KeyShareEntry|null 如果找到返回条目，否则返回null
     */
    public function getEntryByGroup(int $group): ?KeyShareEntry
    {
        foreach ($this->entries as $entry) {
            if ($entry->getGroup() === $group) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * 将扩展编码为二进制数据
     *
     * 格式（客户端）：
     * struct {
     *     uint16 client_shares_length;
     *     KeyShareEntry client_shares[client_shares_length];
     * } KeyShareClientHello;
     *
     * 格式（服务器）：
     * struct {
     *     KeyShareEntry server_share;
     * } KeyShareServerHello;
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        $result = '';

        // 编码所有条目
        $entriesData = '';
        foreach ($this->entries as $entry) {
            // 组标识符
            $entriesData .= $this->encodeUint16($entry->getGroup());

            // 密钥交换数据长度
            $entriesData .= $this->encodeUint16(strlen($entry->getKeyExchange()));

            // 密钥交换数据
            $entriesData .= $entry->getKeyExchange();
        }

        // 服务器格式不包含条目列表长度；客户端格式需要在前面编码长度
        if (!$this->isServerFormat) {
            $result .= $this->encodeUint16(strlen($entriesData));
        }

        // 条目列表数据
        $result .= $entriesData;

        return $result;
    }

    /**
     * 从二进制数据解码扩展
     *
     * @param string $data           二进制数据
     * @param bool   $isServerFormat 是否为服务器格式
     *
     * @return static 解码后的扩展对象
     *
     * @throws \InvalidArgumentException 如果数据格式无效
     */
    public static function decode(string $data, bool $isServerFormat = false): static
    {
        $extension = new self($isServerFormat);

        if ($isServerFormat) {
            self::decodeServerFormat($extension, $data);
        } else {
            self::decodeClientFormat($extension, $data);
        }

        return $extension;
    }

    /**
     * 解码服务器格式的数据
     *
     * @param KeyShareExtension $extension 扩展对象
     * @param string            $data      二进制数据
     *
     * @throws InvalidExtensionDataException
     */
    private static function decodeServerFormat(self $extension, string $data): void
    {
        // 服务器格式只有一个条目，没有长度前缀
        if (strlen($data) < 4) { // 至少需要2字节的组标识符和2字节的密钥交换数据长度
            throw new InvalidExtensionDataException('KeyShare server extension data too short');
        }

        $offset = 0;
        $entry = new KeyShareEntry();

        // 组标识符
        [$group, $offset] = self::decodeUint16($data, $offset);
        $entry->setGroup($group);

        // 密钥交换数据长度
        [$keyExchangeLength, $offset] = self::decodeUint16($data, $offset);

        // 检查数据长度是否足够
        if ($offset + $keyExchangeLength > strlen($data)) {
            throw new InvalidExtensionDataException('KeyShare server extension key exchange data incomplete');
        }

        // 密钥交换数据
        $keyExchange = substr($data, $offset, $keyExchangeLength);
        $entry->setKeyExchange($keyExchange);

        // 添加条目
        $extension->addEntry($entry);
    }

    /**
     * 解码客户端格式的数据
     *
     * @param KeyShareExtension $extension 扩展对象
     * @param string            $data      二进制数据
     *
     * @throws InvalidExtensionDataException
     */
    private static function decodeClientFormat(self $extension, string $data): void
    {
        // 客户端格式有长度前缀和多个条目
        if (strlen($data) < 2) { // 至少需要2字节的条目列表长度
            throw new InvalidExtensionDataException('KeyShare client extension data too short');
        }

        $offset = 0;

        // 条目列表长度
        [$entriesLength, $offset] = self::decodeUint16($data, $offset);

        // 检查数据长度是否一致
        if ($offset + $entriesLength > strlen($data)) {
            throw new InvalidExtensionDataException('KeyShare client extension entries length mismatch');
        }

        // 解析条目列表
        $entriesEnd = $offset + $entriesLength;
        while ($offset < $entriesEnd) {
            [$entry, $offset] = self::decodeKeyShareEntry($data, $offset, $entriesEnd);
            $extension->addEntry($entry);
        }
    }

    /**
     * 解码单个密钥共享条目
     *
     * @param string $data       二进制数据
     * @param int    $offset     当前偏移量
     * @param int    $entriesEnd 条目结束位置
     *
     * @return array{KeyShareEntry, int} 解码后的条目和新的偏移量
     *
     * @throws InvalidExtensionDataException
     */
    private static function decodeKeyShareEntry(string $data, int $offset, int $entriesEnd): array
    {
        // 确保有足够的数据来解析条目头部
        if ($offset + 4 > $entriesEnd) {
            throw new InvalidExtensionDataException('KeyShare client extension entry header incomplete');
        }

        $entry = new KeyShareEntry();

        // 组标识符
        [$group, $offset] = self::decodeUint16($data, $offset);
        $entry->setGroup($group);

        // 密钥交换数据长度
        [$keyExchangeLength, $offset] = self::decodeUint16($data, $offset);

        // 检查是否有足够的数据
        if ($offset + $keyExchangeLength > $entriesEnd) {
            throw new InvalidExtensionDataException('KeyShare client extension key exchange data incomplete');
        }

        // 密钥交换数据
        $keyExchange = substr($data, $offset, $keyExchangeLength);
        $offset += $keyExchangeLength;
        $entry->setKeyExchange($keyExchange);

        return [$entry, $offset];
    }

    /**
     * 检查扩展是否适用于指定的TLS版本
     *
     * 密钥共享扩展仅适用于TLS 1.3
     *
     * @param string $tlsVersion TLS版本（例如："1.2", "1.3"）
     *
     * @return bool 是否适用
     */
    public function isApplicableForVersion(string $tlsVersion): bool
    {
        return '1.3' === $tlsVersion;
    }
}
