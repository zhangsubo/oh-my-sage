import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { GatewayManager, GatewayVerifyResult } from '../../src/core/gateway/manager';
import { startHttpServer } from '../../src/mcp/http';
import { GraphDraftStore } from '../../src/mcp/tools/graphDraft';

const TOKEN = 'sec-token-456';

function stubManager(onConnect?: (passcode: string, url?: string) => Promise<void>): GatewayManager {
    const verifyResult: GatewayVerifyResult = { connected: false, responsive: false, error: '未连接' };
    return {
        gateway: null,
        isConnected: () => false,
        async connect(passcode: string, url?: string) {
            if (onConnect) await onConnect(passcode, url);
        },
        async disconnect() {},
        ensureConnected() { throw new Error('网关未连接'); },
        async verify() { return verifyResult; },
    };
}

function rawRequest(port: number, options: http.RequestOptions, body?: string): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, ...options }, (res) => {
            let text = '';
            res.setEncoding('utf8');
            res.on('data', (chunk) => { text += chunk; });
            res.on('end', () => resolve({ status: res.statusCode ?? 0, text }));
        });
        req.on('error', reject);
        if (body) req.write(body);
        req.end();
    });
}

const INIT_BODY = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'sec-test', version: '0' } },
});

test('MCP HTTP 拒绝未白名单的浏览器 Origin、非 JSON Content-Type 并限制最大会话数', async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oh-my-sage-mcp-sec-'));
    const server = await startHttpServer({
        host: '127.0.0.1',
        port: 0,
        authToken: TOKEN,
        allowedOrigins: ['http://127.0.0.1:3000'],
        maxSessions: 2,
        gatewayManager: stubManager(),
        drafts: new GraphDraftStore(path.join(dir, 'drafts.json')),
    });
    try {
        await t.test('浏览器跨站 Origin 在 /mcp 与 /healthz 均返回 403，白名单内 Origin 放行', async () => {
            const badHealth = await rawRequest(server.port, {
                method: 'GET',
                path: '/healthz',
                headers: { Origin: 'http://evil.example.com' },
            });
            assert.equal(badHealth.status, 403);

            const okHealth = await rawRequest(server.port, {
                method: 'GET',
                path: '/healthz',
                headers: { Origin: 'http://127.0.0.1:3000' },
            });
            assert.equal(okHealth.status, 200);

            const badMcp = await rawRequest(server.port, {
                method: 'POST',
                path: '/mcp',
                headers: {
                    Origin: 'http://evil.example.com',
                    Authorization: `Bearer ${TOKEN}`,
                    'Content-Type': 'application/json',
                    Accept: 'application/json, text/event-stream',
                },
            }, INIT_BODY);
            assert.equal(badMcp.status, 403);
        });

        await t.test('POST /mcp 非 application/json 返回 415', async () => {
            const res = await rawRequest(server.port, {
                method: 'POST',
                path: '/mcp',
                headers: {
                    Authorization: `Bearer ${TOKEN}`,
                    'Content-Type': 'text/plain',
                    Accept: 'application/json, text/event-stream',
                },
            }, INIT_BODY);
            assert.equal(res.status, 415);
        });

        await t.test('活跃会话达到 maxSessions 上限时返回 503', async () => {
            const headers = {
                Authorization: `Bearer ${TOKEN}`,
                'Content-Type': 'application/json',
                Accept: 'application/json, text/event-stream',
            };
            const s1 = await rawRequest(server.port, { method: 'POST', path: '/mcp', headers }, INIT_BODY);
            const s2 = await rawRequest(server.port, { method: 'POST', path: '/mcp', headers }, INIT_BODY);
            assert.equal(s1.status, 200);
            assert.equal(s2.status, 200);
            assert.equal(server.sessionCount(), 2);

            const s3 = await rawRequest(server.port, { method: 'POST', path: '/mcp', headers }, INIT_BODY);
            assert.equal(s3.status, 503);
        });
    } finally {
        await server.close();
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('mijia_auth 锁定服务端预设 GATEWAY_URL 并拦截受限 SSRF 地址，mijia_call_api 限制最大 timeout', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oh-my-sage-auth-sec-'));
    let connectCalled = false;
    const server = await startHttpServer({
        host: '127.0.0.1',
        port: 0,
        authToken: TOKEN,
        userConfig: { gatewayUrl: 'http://192.168.1.10' },
        gatewayManager: stubManager(async () => {
            connectCalled = true;
        }),
        drafts: new GraphDraftStore(path.join(dir, 'drafts.json')),
    });
    const client = new Client({ name: 'sec-client', version: '0.0.0' });
    const transport = new StreamableHTTPClientTransport(new URL(server.url), {
        requestInit: { headers: { Authorization: `Bearer ${TOKEN}` } },
    });
    await client.connect(transport);

    try {
        // 1. 尝试覆盖已固定的 GATEWAY_URL 应被拦截
        const overrideAttempt = await client.callTool({
            name: 'mijia_auth',
            arguments: { passcode: '123456', gateway_url: 'http://192.168.1.99' },
        });
        assert.equal(overrideAttempt.isError, true);
        assert.equal(connectCalled, false);
        const text = (overrideAttempt.content as Array<{ text: string }>)[0].text;
        assert.match(text, /禁止通过 gateway_url 参数覆盖/);

        // 2. 相同网关地址（仅末尾斜杠差异）允许正常连接
        const sameTarget = await client.callTool({
            name: 'mijia_auth',
            arguments: { passcode: '123456', gateway_url: 'http://192.168.1.10/' },
        });
        assert.notEqual(sameTarget.isError, true);
        assert.equal(connectCalled, true);

        // 3. mijia_call_api 超大 timeout 被参数校验拦截
        const badTimeout = await client.callTool({
            name: 'mijia_call_api',
            arguments: { method: 'getDevList', timeout: 120000 },
        });
        assert.equal(badTimeout.isError, true);
    } finally {
        await client.close().catch(() => undefined);
        await server.close();
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('GraphDraftStore 使用私有权限落盘并拒绝符号链接目标', { skip: process.platform === 'win32' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oh-my-sage-draft-sec-'));
    try {
        const storeFile = path.join(dir, 'sub', 'drafts.json');
        const store = new GraphDraftStore(storeFile);
        store.begin({ name: 'sec' });

        const fileMode = fs.statSync(storeFile).mode & 0o777;
        assert.equal(fileMode, 0o600);

        const outsideTarget = path.join(dir, 'outside.json');
        fs.writeFileSync(outsideTarget, '{}');
        const symlinkPath = path.join(dir, 'symlink-drafts.json');
        fs.symlinkSync(outsideTarget, symlinkPath);

        const symlinkStore = new GraphDraftStore(symlinkPath);
        assert.throws(() => symlinkStore.begin({ name: 'bad' }), /符号链接/);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
