<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSExtensionNaming\Extension\ExtensionType;
use Tourze\TLSExtensionSecure\Extension\NamedGroup;
use Tourze\TLSExtensionTLS13\Extension\KeyShareEntry;
use Tourze\TLSExtensionTLS13\Extension\KeyShareExtension;

/**
 * 密钥共享扩展测试类
 *
 * @internal
 */
#[CoversClass(KeyShareExtension::class)]
final class KeyShareExtensionTest extends TestCase
{
    /**
     * 测试扩展类型是否正确
     */
    public function testType(): void
    {
        $extension = new KeyShareExtension();
        $this->assertEquals(ExtensionType::KEY_SHARE->value, $extension->getType());
    }

    /**
     * 测试设置和获取密钥共享条目
     */
    public function testSetAndGetEntries(): void
    {
        $extension = new KeyShareExtension();

        // 测试默认值
        $this->assertEmpty($extension->getEntries());

        // 创建测试条目
        $entry1 = new KeyShareEntry();
        $entry1->setGroup(NamedGroup::X25519->value);
        $keyExchangeData1 = hex2bin('abcdef1234567890');
        $this->assertIsString($keyExchangeData1);
        $entry1->setKeyExchange($keyExchangeData1);

        $entry2 = new KeyShareEntry();
        $entry2->setGroup(NamedGroup::SECP256R1->value);
        $keyExchangeData2 = hex2bin('1122334455667788');
        $this->assertIsString($keyExchangeData2);
        $entry2->setKeyExchange($keyExchangeData2);

        // 测试设置条目
        $entries = [$entry1, $entry2];
        $extension->setEntries($entries);
        $this->assertEquals($entries, $extension->getEntries());

        // 测试添加条目
        $extension = new KeyShareExtension();
        $extension->addEntry($entry1);
        $this->assertCount(1, $extension->getEntries());
        $this->assertEquals($entry1, $extension->getEntries()[0]);
    }

    /**
     * 测试扩展的编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalExtension = new KeyShareExtension();

        // 创建条目
        $entry = new KeyShareEntry();
        $entry->setGroup(NamedGroup::X25519->value);
        $keyExchangeData = hex2bin('01020304');
        $this->assertIsString($keyExchangeData);
        $entry->setKeyExchange($keyExchangeData);

        $originalExtension->addEntry($entry);

        // 编码
        $encodedData = $originalExtension->encode();
        $this->assertNotEmpty($encodedData);

        // 解码
        $decodedExtension = KeyShareExtension::decode($encodedData);

        // 验证解码后的扩展
        $this->assertCount(1, $decodedExtension->getEntries());
        $decodedEntry = $decodedExtension->getEntries()[0];
        $this->assertEquals(NamedGroup::X25519->value, $decodedEntry->getGroup());
        $expectedKeyExchange = hex2bin('01020304');
        $this->assertIsString($expectedKeyExchange);
        $this->assertEquals($expectedKeyExchange, $decodedEntry->getKeyExchange());
    }

    /**
     * 测试编码格式是否符合RFC规范
     */
    public function testEncodeFormat(): void
    {
        $extension = new KeyShareExtension();

        // 创建条目
        $entry = new KeyShareEntry();
        $entry->setGroup(NamedGroup::X25519->value);
        $keyExchangeData = hex2bin('0102');
        $this->assertIsString($keyExchangeData);
        $entry->setKeyExchange($keyExchangeData);

        $extension->addEntry($entry);

        $encoded = $extension->encode();

        // 客户端扩展数据应为：
        // - 2字节的条目列表长度 (0006) - 6字节，一个条目
        // - 2字节的组标识符 (001d) - X25519
        // - 2字节的密钥交换数据长度 (0002) - 2字节
        // - 密钥交换数据 (0102)
        $part1 = hex2bin('0006');
        $part2 = hex2bin('001d');
        $part3 = hex2bin('0002');
        $part4 = hex2bin('0102');
        $this->assertIsString($part1);
        $this->assertIsString($part2);
        $this->assertIsString($part3);
        $this->assertIsString($part4);
        $expected = $part1 . $part2 . $part3 . $part4;

        $this->assertEquals($expected, $encoded);
    }

    /**
     * 测试服务器格式的扩展
     */
    public function testServerFormat(): void
    {
        $extension = new KeyShareExtension(true); // 服务器格式

        // 创建条目
        $entry = new KeyShareEntry();
        $entry->setGroup(NamedGroup::X25519->value);
        $keyExchangeData = hex2bin('0102');
        $this->assertIsString($keyExchangeData);
        $entry->setKeyExchange($keyExchangeData);

        $extension->addEntry($entry);

        $encoded = $extension->encode();

        // 服务器扩展数据应为：
        // - 2字节的组标识符 (001d) - X25519
        // - 2字节的密钥交换数据长度 (0002) - 2字节
        // - 密钥交换数据 (0102)
        $part1 = hex2bin('001d');
        $part2 = hex2bin('0002');
        $part3 = hex2bin('0102');
        $this->assertIsString($part1);
        $this->assertIsString($part2);
        $this->assertIsString($part3);
        $expected = $part1 . $part2 . $part3;

        $this->assertEquals($expected, $encoded);

        // 测试解码
        $decodedExtension = KeyShareExtension::decode($encoded, true);
        $this->assertTrue($decodedExtension->isServerFormat());
        $this->assertCount(1, $decodedExtension->getEntries());
    }

    /**
     * 测试解码无效数据时的异常处理
     */
    public function testDecodeInvalidData(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // 创建无效的数据 (长度字段表示有6个字节的数据，但实际只有4个字节)
        $part1 = hex2bin('0006');
        $part2 = hex2bin('001d0000');
        $this->assertIsString($part1);
        $this->assertIsString($part2);
        $invalidData = $part1 . $part2;

        KeyShareExtension::decode($invalidData);
    }

    /**
     * 测试TLS版本兼容性
     */
    public function testVersionCompatibility(): void
    {
        $extension = new KeyShareExtension();

        // 此扩展仅适用于TLS 1.3
        $this->assertFalse($extension->isApplicableForVersion('1.2'));
        $this->assertTrue($extension->isApplicableForVersion('1.3'));
    }

    /**
     * 测试通过组获取条目
     */
    public function testGetEntryByGroup(): void
    {
        $extension = new KeyShareExtension();

        // 创建测试条目
        $entry1 = new KeyShareEntry();
        $entry1->setGroup(NamedGroup::X25519->value);
        $keyExchangeData1 = hex2bin('01020304');
        $this->assertIsString($keyExchangeData1);
        $entry1->setKeyExchange($keyExchangeData1);

        $entry2 = new KeyShareEntry();
        $entry2->setGroup(NamedGroup::SECP256R1->value);
        $keyExchangeData2Alt = hex2bin('05060708');
        $this->assertIsString($keyExchangeData2Alt);
        $entry2->setKeyExchange($keyExchangeData2Alt);

        $extension->addEntry($entry1);
        $extension->addEntry($entry2);

        // 测试获取存在的条目
        $retrievedEntry = $extension->getEntryByGroup(NamedGroup::X25519->value);
        $this->assertNotNull($retrievedEntry);
        $expectedKeyExchange = hex2bin('01020304');
        $this->assertIsString($expectedKeyExchange);
        $this->assertEquals($expectedKeyExchange, $retrievedEntry->getKeyExchange());

        // 测试获取不存在的条目
        $this->assertNull($extension->getEntryByGroup(NamedGroup::SECP521R1->value));
    }

    /**
     * 测试addEntry方法
     */
    public function testAddEntry(): void
    {
        $extension = new KeyShareExtension();

        // 初始状态应为空
        $this->assertEmpty($extension->getEntries());

        // 创建第一个测试条目
        $entry1 = new KeyShareEntry();
        $entry1->setGroup(NamedGroup::X25519->value);
        $keyExchangeData1 = hex2bin('01020304');
        $this->assertIsString($keyExchangeData1);
        $entry1->setKeyExchange($keyExchangeData1);

        // 添加第一个条目
        $result = $extension->addEntry($entry1);
        $this->assertSame($extension, $result); // 验证返回自身以支持链式调用
        $this->assertCount(1, $extension->getEntries());
        $this->assertEquals($entry1, $extension->getEntries()[0]);

        // 创建第二个测试条目
        $entry2 = new KeyShareEntry();
        $entry2->setGroup(NamedGroup::SECP256R1->value);
        $keyExchangeData2Alt2 = hex2bin('05060708');
        $this->assertIsString($keyExchangeData2Alt2);
        $entry2->setKeyExchange($keyExchangeData2Alt2);

        // 添加第二个条目
        $extension->addEntry($entry2);
        $this->assertCount(2, $extension->getEntries());
        $this->assertEquals($entry1, $extension->getEntries()[0]);
        $this->assertEquals($entry2, $extension->getEntries()[1]);

        // 验证条目的顺序保持添加顺序
        $entries = $extension->getEntries();
        $this->assertEquals(NamedGroup::X25519->value, $entries[0]->getGroup());
        $this->assertEquals(NamedGroup::SECP256R1->value, $entries[1]->getGroup());
    }
}
