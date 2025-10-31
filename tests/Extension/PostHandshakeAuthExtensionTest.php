<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSExtensionTLS13\Extension\PostHandshakeAuthExtension;
use Tourze\TLSHandshakeFlow\Handshake\PostHandshakeAuthManager;
use Tourze\TLSHandshakeFlow\Protocol\TLSVersion;

/**
 * TLS 1.3后握手认证测试类
 *
 * @internal
 */
#[CoversClass(PostHandshakeAuthExtension::class)]
final class PostHandshakeAuthExtensionTest extends TestCase
{
    /**
     * 测试创建后握手认证扩展
     */
    public function testCreatePostHandshakeAuthExtension(): void
    {
        $extension = new PostHandshakeAuthExtension();
        $this->assertNotNull($extension);

        // 后握手认证扩展没有数据
        $this->assertEmpty($extension->encode());
    }

    /**
     * 测试后握手认证扩展序列化与反序列化
     */
    public function testPostHandshakeAuthExtensionSerialize(): void
    {
        $extension = new PostHandshakeAuthExtension();
        $data = $extension->encode();

        $decoded = PostHandshakeAuthExtension::decode($data);
        $this->assertInstanceOf(PostHandshakeAuthExtension::class, $decoded);
    }

    /**
     * 测试创建后握手认证管理器
     */
    public function testCreatePostHandshakeAuthManager(): void
    {
        $manager = new PostHandshakeAuthManager();
        $this->assertFalse($manager->isEnabled());

        $manager->setEnabled(true);
        $this->assertTrue($manager->isEnabled());
    }

    /**
     * 测试后握手认证仅支持TLS 1.3
     */
    public function testPostHandshakeAuthOnlySupportsTLS13(): void
    {
        $manager = new PostHandshakeAuthManager();

        // 后握手认证只支持TLS 1.3
        $this->assertTrue($manager->isSupportedForVersion(TLSVersion::TLS_1_3));
        $this->assertFalse($manager->isSupportedForVersion(TLSVersion::TLS_1_2));
    }

    /**
     * 测试请求客户端证书
     */
    public function testRequestClientCertificate(): void
    {
        $manager = new PostHandshakeAuthManager();
        $manager->setEnabled(true);

        $this->assertFalse($manager->isRequestingCertificate());

        $manager->requestClientCertificate();
        $this->assertTrue($manager->isRequestingCertificate());

        $manager->resetCertificateRequest();
        $this->assertFalse($manager->isRequestingCertificate());
    }

    /**
     * 测试encode方法
     */
    public function testEncode(): void
    {
        $extension = new PostHandshakeAuthExtension();

        // 后握手认证扩展的编码应为空字符串
        $encoded = $extension->encode();
        $this->assertEmpty($encoded);
        $this->assertEquals('', $encoded);

        // 验证编码结果是字符串类型
        $this->assertIsString($encoded);
    }
}
