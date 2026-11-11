import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import test from 'node:test';
import {
    decompressGatewayFrame,
    ECJPAKE,
    normalizeGatewayBaseUrl,
    validateGatewayUrl,
} from '../../src/core/gateway/client';

test('validateGatewayUrl 放行合法局域网地址并归一化基准 URL', () => {
    assert.equal(validateGatewayUrl('http://192.168.1.50').hostname, '192.168.1.50');
    assert.equal(validateGatewayUrl('https://10.0.0.8:8443').port, '8443');
    assert.equal(validateGatewayUrl('http://mijia-hub.lan').hostname, 'mijia-hub.lan');
    assert.equal(normalizeGatewayBaseUrl('http://192.168.1.50/'), 'http://192.168.1.50:80');
    assert.equal(normalizeGatewayBaseUrl('http://192.168.1.50:80'), 'http://192.168.1.50:80');
});

test('validateGatewayUrl 拦截非 HTTP(S) 协议、凭据与查询/片段注入', () => {
    assert.throws(() => validateGatewayUrl('ws://192.168.1.50'), /不支持的网关协议/);
    assert.throws(() => validateGatewayUrl('file:///etc/passwd'), /不支持的网关协议/);
    assert.throws(() => validateGatewayUrl('http://admin:123456@192.168.1.50'), /用户名或密码/);
    assert.throws(() => validateGatewayUrl('http://192.168.1.50/?token=leak'), /查询参数或片段/);
    assert.throws(() => validateGatewayUrl('http://192.168.1.50#frag'), /查询参数或片段/);
});

test('validateGatewayUrl 默认拦截回环、通配、链路本地元数据与组播地址', () => {
    const blocked = [
        'http://localhost:3000',
        'http://sub.localhost',
        'http://127.0.0.1:8080',
        'http://127.1.2.3',
        'http://[::1]:8080',
        'http://[::ffff:127.0.0.1]',
        'http://0.0.0.0',
        'http://[::]',
        'http://169.254.169.254',
        'http://[::ffff:169.254.169.254]',
        'http://[fe80::1]',
        'http://metadata.google.internal',
        'http://224.0.0.1',
        'http://255.255.255.255',
        'http://[ff02::1]',
    ];
    for (const url of blocked) {
        assert.throws(() => validateGatewayUrl(url), /拒绝连接受限的网关地址/, `未拦截受限地址: ${url}`);
    }

    // 显式开启 allowLoopback 时仅放行回环地址，仍拦截云元数据地址
    assert.equal(validateGatewayUrl('http://127.0.0.1:18080', { allowLoopback: true }).hostname, '127.0.0.1');
    assert.throws(() => validateGatewayUrl('http://169.254.169.254', { allowLoopback: true }), /拒绝连接受限的网关地址/);
});

test('decompressGatewayFrame 正常解压合法帧，并拦截声明超限与伪造长度的压缩炸弹', () => {
    const plain = Buffer.from('{"id":1,"result":{"ok":true}}', 'utf8');
    const compressed = deflateRawSync(plain);
    const validFrame = Buffer.alloc(4 + compressed.length);
    validFrame.writeUInt32LE(plain.length, 0);
    compressed.copy(validFrame, 4);
    assert.deepEqual(decompressGatewayFrame(validFrame, 1024), plain);

    // 1. 头部声明长度超限：在解压前直接拒绝
    const declaredHuge = Buffer.alloc(4 + compressed.length);
    declaredHuge.writeUInt32LE(10 * 1024, 0);
    compressed.copy(declaredHuge, 4);
    assert.throws(() => decompressGatewayFrame(declaredHuge, 1024), /exceeds limit/);

    // 2. 伪造小声明长度（仅声明 32 字节），但实际解压数据达 64 KiB：由 maxOutputLength 拦截
    const bombPayload = deflateRawSync(Buffer.alloc(64 * 1024, 0x41));
    const lyingHeaderFrame = Buffer.alloc(4 + bombPayload.length);
    lyingHeaderFrame.writeUInt32LE(32, 0);
    bombPayload.copy(lyingHeaderFrame, 4);
    assert.throws(() => decompressGatewayFrame(lyingHeaderFrame, 1024));
});

test('ECJPAKE 校验曲线点合法性，拒绝不在 secp256k1 曲线上的伪造公钥点', () => {
    const client = new ECJPAKE('123456', 'client');
    const server = new ECJPAKE('123456', 'server');
    const r1Client = client.writeRoundOne();
    const r1Server = server.writeRoundOne();

    // 正常握手可通过 Round 1
    assert.doesNotThrow(() => server.readRoundOne(r1Client));

    // 篡改服务端公钥点坐标为不在 secp256k1 曲线上的点 (x=1, y=1)
    const forged = Buffer.from(r1Server);
    forged[0] = 65;
    forged[1] = 4;
    forged.fill(0, 2, 66);
    forged[33] = 1; // x = 1
    forged[65] = 1; // y = 1 (1^2 != 1^3 + 7 mod p)
    assert.throws(() => client.readRoundOne(forged), /Invalid EC point/);
});
