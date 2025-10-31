<?php

declare(strict_types=1);

namespace Tourze\TLSExtensionTLS13\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSExtensionTLS13\Extension\PSKIdentity;

/**
 * @internal
 */
#[CoversClass(PSKIdentity::class)]
final class PSKIdentityTest extends TestCase
{
    public function testGetSetIdentity(): void
    {
        $pskIdentity = new PSKIdentity();
        $identity = 'test-psk-identity';

        $pskIdentity->setIdentity($identity);

        $this->assertSame($identity, $pskIdentity->getIdentity());
    }

    public function testGetSetObfuscatedTicketAge(): void
    {
        $pskIdentity = new PSKIdentity();
        $ticketAge = 123456;

        $pskIdentity->setObfuscatedTicketAge($ticketAge);

        $this->assertSame($ticketAge, $pskIdentity->getObfuscatedTicketAge());
    }

    public function testDefaultValues(): void
    {
        $pskIdentity = new PSKIdentity();

        $this->assertSame('', $pskIdentity->getIdentity());
        $this->assertSame(0, $pskIdentity->getObfuscatedTicketAge());
    }

    public function testMultipleSetters(): void
    {
        $pskIdentity = new PSKIdentity();
        $identity = 'session-ticket-data';
        $ticketAge = 987654;

        $pskIdentity->setIdentity($identity);
        $pskIdentity->setObfuscatedTicketAge($ticketAge);

        $this->assertSame($identity, $pskIdentity->getIdentity());
        $this->assertSame($ticketAge, $pskIdentity->getObfuscatedTicketAge());
    }
}
