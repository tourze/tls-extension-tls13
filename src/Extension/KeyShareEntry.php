<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Extension;

/**
 * 密钥共享条目
 *
 * 表示TLS 1.3密钥共享扩展中的单个密钥共享条目
 */
class KeyShareEntry
{
    /**
     * 组标识符
     */
    private int $group;

    /**
     * 密钥交换数据
     */
    private string $keyExchange = '';

    /**
     * 获取组标识符
     *
     * @return int 组标识符
     */
    public function getGroup(): int
    {
        return $this->group;
    }

    /**
     * 设置组标识符
     *
     * @param int $group 组标识符
     */
    public function setGroup(int $group): void
    {
        $this->group = $group;
    }

    /**
     * 获取密钥交换数据
     *
     * @return string 密钥交换数据
     */
    public function getKeyExchange(): string
    {
        return $this->keyExchange;
    }

    /**
     * 设置密钥交换数据
     *
     * @param string $keyExchange 密钥交换数据
     */
    public function setKeyExchange(string $keyExchange): void
    {
        $this->keyExchange = $keyExchange;
    }
}
