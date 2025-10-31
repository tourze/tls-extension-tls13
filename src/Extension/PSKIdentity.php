<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Extension;

/**
 * PSK标识类
 *
 * 表示TLS 1.3 PSK扩展中的单个标识
 */
class PSKIdentity
{
    /**
     * 标识数据
     */
    private string $identity = '';

    /**
     * 模糊化的票据年龄
     */
    private int $obfuscatedTicketAge = 0;

    /**
     * 获取标识数据
     *
     * @return string 标识数据
     */
    public function getIdentity(): string
    {
        return $this->identity;
    }

    /**
     * 设置标识数据
     *
     * @param string $identity 标识数据
     */
    public function setIdentity(string $identity): void
    {
        $this->identity = $identity;
    }

    /**
     * 获取模糊化的票据年龄
     *
     * @return int 模糊化的票据年龄
     */
    public function getObfuscatedTicketAge(): int
    {
        return $this->obfuscatedTicketAge;
    }

    /**
     * 设置模糊化的票据年龄
     *
     * @param int $obfuscatedTicketAge 模糊化的票据年龄
     */
    public function setObfuscatedTicketAge(int $obfuscatedTicketAge): void
    {
        $this->obfuscatedTicketAge = $obfuscatedTicketAge;
    }
}
