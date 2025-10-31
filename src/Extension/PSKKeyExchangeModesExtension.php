<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Extension;

use Tourze\TLSExtensionNaming\Extension\AbstractExtension;
use Tourze\TLSExtensionNaming\Extension\ExtensionType;

/**
 * TLS 1.3 PSK Key Exchange Modes 扩展
 * 参考 RFC 8446 Section 4.2.9
 */
final class PSKKeyExchangeModesExtension extends AbstractExtension
{
    /** @var array<int> */
    private array $modes = [];

    public const PSK_KE = 0x00;
    public const PSK_DHE_KE = 0x01;

    /**
     * 构造函数
     *
     * @param array<int> $modes PSK密钥交换模式列表
     */
    public function __construct(array $modes = [])
    {
        $this->modes = $modes;
    }

    public function getType(): int
    {
        return ExtensionType::PSK_KEY_EXCHANGE_MODES->value;
    }

    public function encode(): string
    {
        $list = '';
        foreach ($this->modes as $mode) {
            $list .= chr($mode);
        }

        return chr(strlen($list)) . $list; // opaque psk_ke_modes<1..255>
    }

    public static function decode(string $data): static
    {
        $offset = 0;
        $len = ord($data[$offset]);
        ++$offset;
        $modes = [];
        for ($i = 0; $i < $len; ++$i) {
            $modes[] = ord($data[$offset + $i]);
        }

        return new self($modes);
    }
}
