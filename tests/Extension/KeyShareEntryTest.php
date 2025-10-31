<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSExtensionTLS13\Extension\KeyShareEntry;

/**
 * @internal
 */
#[CoversClass(KeyShareEntry::class)]
final class KeyShareEntryTest extends TestCase
{
    public function testGetSetGroup(): void
    {
        $entry = new KeyShareEntry();
        $group = 23; // secp256r1

        $entry->setGroup($group);

        $this->assertSame($group, $entry->getGroup());
    }

    public function testGetSetKeyExchange(): void
    {
        $entry = new KeyShareEntry();
        $keyExchange = 'test-key-exchange-data';

        $entry->setKeyExchange($keyExchange);

        $this->assertSame($keyExchange, $entry->getKeyExchange());
    }

    public function testDefaultValues(): void
    {
        $entry = new KeyShareEntry();

        $this->assertSame('', $entry->getKeyExchange());
    }

    public function testMultipleSetters(): void
    {
        $entry = new KeyShareEntry();
        $group = 29; // x25519
        $keyExchange = 'x25519-key-data';

        $entry->setGroup($group);
        $entry->setKeyExchange($keyExchange);

        $this->assertSame($group, $entry->getGroup());
        $this->assertSame($keyExchange, $entry->getKeyExchange());
    }
}
