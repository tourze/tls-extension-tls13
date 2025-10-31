<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Extension;

use Tourze\TLSExtensionNaming\Extension\AbstractExtension;
use Tourze\TLSExtensionNaming\Extension\ExtensionType;

/**
 * TLS 1.3后握手认证扩展
 *
 * 参考RFC 8446第4.2.6节
 * 此扩展用于指示客户端愿意在握手后接收CertificateRequest消息
 */
final class PostHandshakeAuthExtension extends AbstractExtension
{
    /**
     * 扩展类型
     */
    protected ExtensionType $type;

    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->type = ExtensionType::POST_HANDSHAKE_AUTH;
    }

    /**
     * 获取扩展类型
     *
     * @return int 扩展类型
     */
    public function getType(): int
    {
        return $this->type->value;
    }

    /**
     * 将扩展编码为二进制数据
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        // 后握手认证扩展没有内容
        return '';
    }

    /**
     * 从二进制数据解码扩展
     *
     * @param string $data 二进制数据
     *
     * @return static 解码后的扩展对象
     */
    public static function decode(string $data): static
    {
        // 后握手认证扩展没有内容
        return new self();
    }

    /**
     * 检查扩展是否适用于指定的TLS版本
     *
     * @param string $tlsVersion TLS版本
     *
     * @return bool 是否适用
     */
    public function isApplicableForVersion(string $tlsVersion): bool
    {
        // 后握手认证扩展仅适用于TLS 1.3及以上版本
        return '1.3' === $tlsVersion;
    }
}
