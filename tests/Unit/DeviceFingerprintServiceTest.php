<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Authentication\Device\DeviceFingerprintService;
use Illuminate\Http\Request;
use Tests\TestCase;

class DeviceFingerprintServiceTest extends TestCase
{
    protected DeviceFingerprintService $service;

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new DeviceFingerprintService();
    }

    /** @test */
    public function it_generates_fingerprint_from_request(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
            'REMOTE_ADDR' => '192.168.1.1',
        ]);

        $fingerprint = $this->service->generateFingerprint($request);

        $this->assertIsArray($fingerprint);
        $this->assertArrayHasKey('hash', $fingerprint);
        $this->assertArrayHasKey('components', $fingerprint);
        $this->assertNotEmpty($fingerprint['hash']);
    }

    /** @test */
    public function it_generates_consistent_fingerprints_for_same_request(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
            'REMOTE_ADDR' => '192.168.1.1',
        ]);

        $fingerprint1 = $this->service->generateFingerprint($request);
        $fingerprint2 = $this->service->generateFingerprint($request);

        $this->assertEquals($fingerprint1['hash'], $fingerprint2['hash']);
    }

    /** @test */
    public function it_generates_different_fingerprints_for_different_requests(): void
    {
        $request1 = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 Chrome',
            'REMOTE_ADDR' => '192.168.1.1',
        ]);

        $request2 = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox',
            'REMOTE_ADDR' => '192.168.1.2',
        ]);

        $fingerprint1 = $this->service->generateFingerprint($request1);
        $fingerprint2 = $this->service->generateFingerprint($request2);

        $this->assertNotEquals($fingerprint1['hash'], $fingerprint2['hash']);
    }

    /** @test */
    public function it_extracts_device_info_from_user_agent(): void
    {
        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]);

        $fingerprint = $this->service->generateFingerprint($request);
        $components = $fingerprint['components'];

        $this->assertArrayHasKey('user_agent', $components);
    }
}
