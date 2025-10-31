<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSExtensionNaming\Extension\ExtensionType;
use Tourze\TLSExtensionTLS13\Extension\PreSharedKeyExtension;
use Tourze\TLSExtensionTLS13\Extension\PSKIdentity;

/**
 * PSK扩展测试类
 *
 * @internal
 */
#[CoversClass(PreSharedKeyExtension::class)]
final class PreSharedKeyExtensionTest extends TestCase
{
    /**
     * 测试扩展类型是否正确
     */
    public function testType(): void
    {
        $extension = new PreSharedKeyExtension();
        $this->assertEquals(ExtensionType::PRE_SHARED_KEY->value, $extension->getType());
    }

    /**
     * 测试设置和获取PSK标识列表
     */
    public function testSetAndGetIdentities(): void
    {
        $extension = new PreSharedKeyExtension();

        // 测试默认值
        $this->assertEmpty($extension->getIdentities());

        // 创建测试标识
        $identity1 = new PSKIdentity();
        $identity1Data = hex2bin('abcd');
        $this->assertIsString($identity1Data);
        $identity1->setIdentity($identity1Data);
        $identity1->setObfuscatedTicketAge(1000);

        $identity2 = new PSKIdentity();
        $identity2Data = hex2bin('1234');
        $this->assertIsString($identity2Data);
        $identity2->setIdentity($identity2Data);
        $identity2->setObfuscatedTicketAge(2000);

        // 测试设置标识
        $identities = [$identity1, $identity2];
        $extension->setIdentities($identities);
        $this->assertEquals($identities, $extension->getIdentities());

        // 测试添加标识
        $extension = new PreSharedKeyExtension();
        $extension->addIdentity($identity1);
        $this->assertCount(1, $extension->getIdentities());
        $this->assertEquals($identity1, $extension->getIdentities()[0]);
    }

    /**
     * 测试设置和获取PSK绑定器列表
     */
    public function testSetAndGetBinders(): void
    {
        $extension = new PreSharedKeyExtension();

        // 测试默认值
        $this->assertEmpty($extension->getBinders());

        // 测试设置绑定器
        $binder1 = hex2bin('aa');
        $binder2 = hex2bin('bb');
        $this->assertIsString($binder1);
        $this->assertIsString($binder2);
        $binders = [$binder1, $binder2];
        $extension->setBinders($binders);
        $this->assertEquals($binders, $extension->getBinders());

        // 测试添加绑定器
        $extension = new PreSharedKeyExtension();
        $binderData = hex2bin('cc');
        $this->assertIsString($binderData);
        $extension->addBinder($binderData);
        $this->assertCount(1, $extension->getBinders());
        $expectedBinder = hex2bin('cc');
        $this->assertIsString($expectedBinder);
        $this->assertEquals($expectedBinder, $extension->getBinders()[0]);
    }

    /**
     * 测试客户端格式的编码和解码
     */
    public function testClientEncodeAndDecode(): void
    {
        $originalExtension = new PreSharedKeyExtension();

        // 创建测试标识和绑定器
        $identity = new PSKIdentity();
        $identityData = hex2bin('abcd');
        $this->assertIsString($identityData);
        $identity->setIdentity($identityData);
        $identity->setObfuscatedTicketAge(1000);
        $originalExtension->addIdentity($identity);

        $binderData = hex2bin('1234');
        $this->assertIsString($binderData);
        $originalExtension->addBinder($binderData);

        // 编码
        $encodedData = $originalExtension->encode();
        $this->assertNotEmpty($encodedData);

        // 解码
        $decodedExtension = PreSharedKeyExtension::decode($encodedData);

        // 验证解码后的扩展
        $this->assertCount(1, $decodedExtension->getIdentities());
        $decodedIdentity = $decodedExtension->getIdentities()[0];
        $expectedIdentity = hex2bin('abcd');
        $this->assertIsString($expectedIdentity);
        $this->assertEquals($expectedIdentity, $decodedIdentity->getIdentity());
        $this->assertEquals(1000, $decodedIdentity->getObfuscatedTicketAge());

        $this->assertCount(1, $decodedExtension->getBinders());
        $expectedBinder = hex2bin('1234');
        $this->assertIsString($expectedBinder);
        $this->assertEquals($expectedBinder, $decodedExtension->getBinders()[0]);
    }

    /**
     * 测试服务器格式的编码和解码
     */
    public function testServerEncodeAndDecode(): void
    {
        $originalExtension = new PreSharedKeyExtension(true);
        $originalExtension->setSelectedIdentity(2);

        // 编码
        $encodedData = $originalExtension->encode();
        $this->assertNotEmpty($encodedData);

        // 解码
        $decodedExtension = PreSharedKeyExtension::decode($encodedData, true);

        // 验证解码后的扩展
        $this->assertTrue($decodedExtension->isServerFormat());
        $this->assertEquals(2, $decodedExtension->getSelectedIdentity());
    }

    /**
     * 测试客户端编码格式是否符合RFC规范
     */
    public function testClientEncodeFormat(): void
    {
        $extension = new PreSharedKeyExtension();

        // 创建测试标识和绑定器
        $identity = new PSKIdentity();
        $identityData = hex2bin('ab');
        $this->assertIsString($identityData);
        $identity->setIdentity($identityData);
        $identity->setObfuscatedTicketAge(1000);
        $extension->addIdentity($identity);

        $binderData = hex2bin('cd');
        $this->assertIsString($binderData);
        $extension->addBinder($binderData);

        $encoded = $extension->encode();

        // 客户端扩展数据应为：
        // - 2字节的标识列表长度 (0008) - 8字节
        // - 2字节的标识长度 (0002) - 2字节
        // - 标识数据 (ab)
        // - 4字节的票据年龄 (000003e8) - 1000
        // - 2字节的绑定器列表长度 (0004) - 4字节
        // - 1字节的绑定器长度 (01) - 1字节
        // - 绑定器数据 (cd)
        $part1 = hex2bin('0008');
        $part2 = hex2bin('0002');
        $part3 = hex2bin('ab');
        $part4 = hex2bin('000003e8');
        $part5 = hex2bin('0004');
        $part6 = hex2bin('01');
        $part7 = hex2bin('cd');
        $this->assertIsString($part1);
        $this->assertIsString($part2);
        $this->assertIsString($part3);
        $this->assertIsString($part4);
        $this->assertIsString($part5);
        $this->assertIsString($part6);
        $this->assertIsString($part7);
        $expected = $part1 . $part2 . $part3 . $part4 . $part5 . $part6 . $part7;

        $this->assertEquals($expected, $encoded);
    }

    /**
     * 测试服务器编码格式是否符合RFC规范
     */
    public function testServerEncodeFormat(): void
    {
        $extension = new PreSharedKeyExtension(true);
        $extension->setSelectedIdentity(2);

        $encoded = $extension->encode();

        // 服务器扩展数据应为：
        // - 2字节的选定标识索引 (0002)
        $expected = hex2bin('0002');
        $this->assertIsString($expected);

        $this->assertEquals($expected, $encoded);
    }

    /**
     * 测试解码无效数据时的异常处理
     */
    public function testDecodeInvalidData(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // 创建无效的客户端数据 (标识列表长度字段表示有4个字节的数据，但实际只有2个字节)
        $part1 = hex2bin('0004');
        $part2 = hex2bin('0000');
        $this->assertIsString($part1);
        $this->assertIsString($part2);
        $invalidData = $part1 . $part2;

        PreSharedKeyExtension::decode($invalidData);
    }

    /**
     * 测试TLS版本兼容性
     */
    public function testVersionCompatibility(): void
    {
        $extension = new PreSharedKeyExtension();

        // 此扩展仅适用于TLS 1.3
        $this->assertFalse($extension->isApplicableForVersion('1.2'));
        $this->assertTrue($extension->isApplicableForVersion('1.3'));
    }

    /**
     * 测试addBinder方法
     */
    public function testAddBinder(): void
    {
        $extension = new PreSharedKeyExtension();

        // 初始状态应为空
        $this->assertEmpty($extension->getBinders());

        // 添加第一个绑定器
        $binder1 = hex2bin('aabbccdd');
        $this->assertIsString($binder1);
        $result = $extension->addBinder($binder1);
        $this->assertSame($extension, $result); // 验证返回自身以支持链式调用
        $this->assertCount(1, $extension->getBinders());
        $this->assertEquals($binder1, $extension->getBinders()[0]);

        // 添加第二个绑定器
        $binder2 = hex2bin('11223344');
        $this->assertIsString($binder2);
        $extension->addBinder($binder2);
        $this->assertCount(2, $extension->getBinders());
        $this->assertEquals($binder1, $extension->getBinders()[0]);
        $this->assertEquals($binder2, $extension->getBinders()[1]);

        // 验证绑定器的顺序保持添加顺序
        $binders = $extension->getBinders();
        $this->assertEquals($binder1, $binders[0]);
        $this->assertEquals($binder2, $binders[1]);
    }

    /**
     * 测试addIdentity方法
     */
    public function testAddIdentity(): void
    {
        $extension = new PreSharedKeyExtension();

        // 初始状态应为空
        $this->assertEmpty($extension->getIdentities());

        // 创建第一个测试标识
        $identity1 = new PSKIdentity();
        $identity1Data = hex2bin('abcdef');
        $this->assertIsString($identity1Data);
        $identity1->setIdentity($identity1Data);
        $identity1->setObfuscatedTicketAge(1000);

        // 添加第一个标识
        $result = $extension->addIdentity($identity1);
        $this->assertSame($extension, $result); // 验证返回自身以支持链式调用
        $this->assertCount(1, $extension->getIdentities());
        $this->assertEquals($identity1, $extension->getIdentities()[0]);

        // 创建第二个测试标识
        $identity2 = new PSKIdentity();
        $identity2Data = hex2bin('123456');
        $this->assertIsString($identity2Data);
        $identity2->setIdentity($identity2Data);
        $identity2->setObfuscatedTicketAge(2000);

        // 添加第二个标识
        $extension->addIdentity($identity2);
        $this->assertCount(2, $extension->getIdentities());
        $this->assertEquals($identity1, $extension->getIdentities()[0]);
        $this->assertEquals($identity2, $extension->getIdentities()[1]);

        // 验证标识的顺序保持添加顺序
        $identities = $extension->getIdentities();
        $expectedIdentity1 = hex2bin('abcdef');
        $this->assertIsString($expectedIdentity1);
        $this->assertEquals($expectedIdentity1, $identities[0]->getIdentity());
        $this->assertEquals(1000, $identities[0]->getObfuscatedTicketAge());
        $expectedIdentity2 = hex2bin('123456');
        $this->assertIsString($expectedIdentity2);
        $this->assertEquals($expectedIdentity2, $identities[1]->getIdentity());
        $this->assertEquals(2000, $identities[1]->getObfuscatedTicketAge());
    }

    /**
     * 测试encode方法
     */
    public function testEncode(): void
    {
        // 测试客户端格式的编码
        $clientExtension = new PreSharedKeyExtension();

        // 创建标识和绑定器
        $identity = new PSKIdentity();
        $identityData = hex2bin('74657374'); // 'test' in hex
        $this->assertIsString($identityData);
        $identity->setIdentity($identityData);
        $identity->setObfuscatedTicketAge(0x12345678);
        $clientExtension->addIdentity($identity);
        $binderData = hex2bin('62696e646572'); // 'binder' in hex
        $this->assertIsString($binderData);
        $clientExtension->addBinder($binderData);

        $clientEncoded = $clientExtension->encode();
        $this->assertNotEmpty($clientEncoded);
        $this->assertIsString($clientEncoded);

        // 测试服务器格式的编码
        $serverExtension = new PreSharedKeyExtension(true);
        $serverExtension->setSelectedIdentity(42);

        $serverEncoded = $serverExtension->encode();
        $this->assertNotEmpty($serverEncoded);
        $expectedEncoded = hex2bin('002a'); // 42 = 0x002a
        $this->assertIsString($expectedEncoded);
        $this->assertEquals($expectedEncoded, $serverEncoded);

        // 测试空客户端扩展
        $emptyClientExtension = new PreSharedKeyExtension();
        $emptyEncoded = $emptyClientExtension->encode();
        $expectedEmpty = hex2bin('00000000'); // 空的标识列表和绑定器列表
        $this->assertIsString($expectedEmpty);
        $this->assertEquals($expectedEmpty, $emptyEncoded);
    }
}
