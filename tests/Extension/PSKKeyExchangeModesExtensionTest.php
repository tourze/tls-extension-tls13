<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSExtensionNaming\Extension\ExtensionType;
use Tourze\TLSExtensionTLS13\Extension\PSKKeyExchangeModesExtension;

/**
 * PSK Key Exchange Modes 扩展测试类
 *
 * @internal
 */
#[CoversClass(PSKKeyExchangeModesExtension::class)]
final class PSKKeyExchangeModesExtensionTest extends TestCase
{
    /**
     * 测试扩展类型是否正确
     */
    public function testType(): void
    {
        $extension = new PSKKeyExchangeModesExtension();
        $this->assertEquals(ExtensionType::PSK_KEY_EXCHANGE_MODES->value, $extension->getType());
    }

    /**
     * 测试构造函数和默认值
     */
    public function testConstructor(): void
    {
        // 测试无参数构造
        $extension1 = new PSKKeyExchangeModesExtension();
        $encoded1 = $extension1->encode();
        $this->assertEquals(chr(0), $encoded1); // 空列表

        // 测试带参数构造
        $modes = [PSKKeyExchangeModesExtension::PSK_KE, PSKKeyExchangeModesExtension::PSK_DHE_KE];
        $extension2 = new PSKKeyExchangeModesExtension($modes);
        $encoded2 = $extension2->encode();
        $this->assertEquals(chr(2) . chr(PSKKeyExchangeModesExtension::PSK_KE) . chr(PSKKeyExchangeModesExtension::PSK_DHE_KE), $encoded2);
    }

    /**
     * 测试常量定义
     */
    public function testConstants(): void
    {
        $this->assertEquals(0x00, PSKKeyExchangeModesExtension::PSK_KE);
        $this->assertEquals(0x01, PSKKeyExchangeModesExtension::PSK_DHE_KE);
    }

    /**
     * 测试编码功能
     */
    public function testEncode(): void
    {
        // 测试空模式列表
        $extension1 = new PSKKeyExchangeModesExtension([]);
        $encoded1 = $extension1->encode();
        $this->assertEquals(chr(0), $encoded1);

        // 测试单个模式
        $extension2 = new PSKKeyExchangeModesExtension([PSKKeyExchangeModesExtension::PSK_KE]);
        $encoded2 = $extension2->encode();
        $this->assertEquals(chr(1) . chr(0x00), $encoded2);

        // 测试多个模式
        $extension3 = new PSKKeyExchangeModesExtension([PSKKeyExchangeModesExtension::PSK_KE, PSKKeyExchangeModesExtension::PSK_DHE_KE]);
        $encoded3 = $extension3->encode();
        $this->assertEquals(chr(2) . chr(0x00) . chr(0x01), $encoded3);

        // 测试自定义值
        $extension4 = new PSKKeyExchangeModesExtension([0x02, 0x03, 0x04]);
        $encoded4 = $extension4->encode();
        $this->assertEquals(chr(3) . chr(0x02) . chr(0x03) . chr(0x04), $encoded4);
    }

    /**
     * 测试解码功能
     */
    public function testDecode(): void
    {
        // 测试解码空列表
        $data1 = chr(0);
        $extension1 = PSKKeyExchangeModesExtension::decode($data1);
        $encoded1 = $extension1->encode();
        $this->assertEquals($data1, $encoded1);

        // 测试解码单个模式
        $data2 = chr(1) . chr(PSKKeyExchangeModesExtension::PSK_DHE_KE);
        $extension2 = PSKKeyExchangeModesExtension::decode($data2);
        $encoded2 = $extension2->encode();
        $this->assertEquals($data2, $encoded2);

        // 测试解码多个模式
        $data3 = chr(2) . chr(PSKKeyExchangeModesExtension::PSK_KE) . chr(PSKKeyExchangeModesExtension::PSK_DHE_KE);
        $extension3 = PSKKeyExchangeModesExtension::decode($data3);
        $encoded3 = $extension3->encode();
        $this->assertEquals($data3, $encoded3);
    }

    /**
     * 测试编码和解码的完整流程
     */
    public function testEncodeAndDecode(): void
    {
        // 测试各种模式组合
        $testCases = [
            [],
            [PSKKeyExchangeModesExtension::PSK_KE],
            [PSKKeyExchangeModesExtension::PSK_DHE_KE],
            [PSKKeyExchangeModesExtension::PSK_KE, PSKKeyExchangeModesExtension::PSK_DHE_KE],
            [0x02, 0x03, 0x04, 0x05],
            [0xFF], // 边界值测试
        ];

        foreach ($testCases as $modes) {
            $originalExtension = new PSKKeyExchangeModesExtension($modes);
            $encoded = $originalExtension->encode();
            $decodedExtension = PSKKeyExchangeModesExtension::decode($encoded);
            $reEncoded = $decodedExtension->encode();

            $this->assertEquals($encoded, $reEncoded, 'Encode/decode cycle should be idempotent');
        }
    }

    /**
     * 测试编码格式是否符合RFC 8446规范
     */
    public function testEncodeFormat(): void
    {
        // 根据 RFC 8446 Section 4.2.9:
        // struct {
        //     PskKeyExchangeMode ke_modes<1..255>;
        // } PskKeyExchangeModes;
        //
        // enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;

        // 测试标准模式组合
        $extension = new PSKKeyExchangeModesExtension([PSKKeyExchangeModesExtension::PSK_KE, PSKKeyExchangeModesExtension::PSK_DHE_KE]);
        $encoded = $extension->encode();

        // 应该是: 长度(1字节) + 模式列表
        $this->assertEquals(3, strlen($encoded)); // 1字节长度 + 2字节模式
        $this->assertEquals(2, ord($encoded[0])); // 长度字段应该是2
        $this->assertEquals(PSKKeyExchangeModesExtension::PSK_KE, ord($encoded[1]));
        $this->assertEquals(PSKKeyExchangeModesExtension::PSK_DHE_KE, ord($encoded[2]));
    }

    /**
     * 测试边界条件
     */
    public function testBoundaryConditions(): void
    {
        // 测试最大长度（255个模式）
        $maxModes = array_fill(0, 255, 0x01);
        $extension = new PSKKeyExchangeModesExtension($maxModes);
        $encoded = $extension->encode();
        $this->assertEquals(256, strlen($encoded)); // 1字节长度 + 255字节数据
        $this->assertEquals(255, ord($encoded[0])); // 长度字段

        // 测试解码最大长度数据
        $decoded = PSKKeyExchangeModesExtension::decode($encoded);
        $reEncoded = $decoded->encode();
        $this->assertEquals($encoded, $reEncoded);
    }

    /**
     * 测试值的范围
     */
    public function testValueRange(): void
    {
        // 测试0-255的所有可能值
        for ($i = 0; $i <= 255; ++$i) {
            $extension = new PSKKeyExchangeModesExtension([$i]);
            $encoded = $extension->encode();
            $this->assertEquals(chr(1) . chr($i), $encoded);

            $decoded = PSKKeyExchangeModesExtension::decode($encoded);
            $reEncoded = $decoded->encode();
            $this->assertEquals($encoded, $reEncoded);
        }
    }
}
