import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { SessionStore, isValidSessionId } from '../../src/server/session/store';
import {
    AUTH_MAX_FAILURES,
    checkAuthRateLimit,
    clearAuthFailures,
    guardWebRequest,
    issueWebSessionCookie,
    recordAuthFailure,
    resetWebAuthStateForTests,
    WEB_SESSION_COOKIE,
} from '../../src/server/security/webAuth';

test('SessionStore 严格校验 Session ID 并阻断目录遍历与未索引文件篡改', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oh-my-sage-session-sec-'));
    try {
        const store = new SessionStore(dir);
        const created = await store.createSession('测试会话');
        assert.equal(isValidSessionId(created.id), true);

        const traversalIds = [
            '../../etc/passwd',
            '../secret',
            'session_123_abc/../../evil',
            'session_123_abc\\..\\evil',
            'not_a_session_id',
            '',
        ];

        for (const badId of traversalIds) {
            assert.equal(isValidSessionId(badId), false);
            assert.equal(await store.getSessionMeta(badId), null);
            await assert.rejects(() => store.getMessages(badId), /无效的 Session ID/);
            await assert.rejects(
                () => store.appendMessage(badId, { role: 'user', content: 'x', timestamp: new Date().toISOString() }),
                /Session 不存在|无效的 Session ID/,
            );
            await assert.rejects(() => store.truncateSession(badId, 0), /Session 不存在|无效的 Session ID/);
            await assert.rejects(() => store.deleteSession(badId), /无效的 Session ID/);
        }

        // 格式合法但不在索引中的 ID：禁止追加、截断或盲删磁盘文件
        const unindexedId = 'session_1700000000000_deadbeef1234';
        const orphanFile = path.join(dir, `${unindexedId}.jsonl`);
        fs.writeFileSync(orphanFile, '{"seq":0}\n');

        await assert.rejects(
            () => store.appendMessage(unindexedId, { role: 'user', content: 'hi', timestamp: new Date().toISOString() }),
            /Session 不存在/,
        );
        await assert.rejects(() => store.truncateSession(unindexedId, 0), /Session 不存在/);
        assert.equal(await store.deleteSession(unindexedId), false);
        assert.equal(fs.existsSync(orphanFile), true, '未索引文件不应被 deleteSession 盲删');

        // 已索引的正常会话可正常删除
        assert.equal(await store.deleteSession(created.id), true);
        assert.equal(await store.getSessionMeta(created.id), null);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('SessionStore 在 POSIX 下使用 0600 权限并拒绝符号链接会话文件', { skip: process.platform === 'win32' }, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oh-my-sage-session-perm-'));
    try {
        const store = new SessionStore(dir);
        const session = await store.createSession('权限测试');
        const sessionFile = path.join(dir, `${session.id}.jsonl`);
        const indexFile = path.join(dir, 'index.json');

        assert.equal(fs.statSync(sessionFile).mode & 0o777, 0o600);
        assert.equal(fs.statSync(indexFile).mode & 0o777, 0o600);

        const outside = path.join(dir, 'outside-target.jsonl');
        fs.writeFileSync(outside, '');
        fs.unlinkSync(sessionFile);
        fs.symlinkSync(outside, sessionFile);

        await assert.rejects(() => store.getMessages(session.id), /符号链接/);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('guardWebRequest 拦截未授权请求、非法 Host、跨站 CSRF 与非 JSON Content-Type', () => {
    resetWebAuthStateForTests();
    const env: NodeJS.ProcessEnv = { NODE_ENV: 'test' };

    // 1. 未登录请求返回 401
    const unauthGet = new Request('http://127.0.0.1:3000/api/devices', {
        method: 'GET',
        headers: { host: '127.0.0.1:3000' },
    });
    assert.equal(guardWebRequest(unauthGet, { env })?.status, 401);

    // 2. DNS Rebinding 非法 Host 返回 403
    const evilHost = new Request('http://evil.example.com:3000/api/auth', {
        method: 'GET',
        headers: { host: 'evil.example.com:3000' },
    });
    assert.equal(guardWebRequest(evilHost, { env, requireAuth: false })?.status, 403);

    // 配置 WEB_ALLOWED_HOSTS 后放行自定义域名
    assert.equal(
        guardWebRequest(evilHost, {
            env: { ...env, WEB_ALLOWED_HOSTS: 'evil.example.com' },
            requireAuth: false,
        }),
        null,
    );

    // 3. 签发服务端 Session Cookie 后，同源请求放行，跨站请求被拦截
    const loginReq = new Request('http://localhost:3000/api/auth', {
        method: 'POST',
        headers: {
            host: 'localhost:3000',
            origin: 'http://localhost:3000',
            'content-type': 'application/json',
        },
    });
    const issued = issueWebSessionCookie(loginReq, env);
    assert.match(issued.headerValue, /HttpOnly/);
    assert.match(issued.headerValue, /SameSite=Strict/);

    const authedGet = new Request('http://localhost:3000/api/devices', {
        method: 'GET',
        headers: {
            host: 'localhost:3000',
            cookie: `${WEB_SESSION_COOKIE}=${issued.value}`,
        },
    });
    assert.equal(guardWebRequest(authedGet, { env }), null);

    // 跨站 Origin 拦截 (403)
    const crossOriginPost = new Request('http://localhost:3000/api/graphs', {
        method: 'POST',
        headers: {
            host: 'localhost:3000',
            origin: 'https://attacker.example',
            'content-type': 'application/json',
            cookie: `${WEB_SESSION_COOKIE}=${issued.value}`,
        },
    });
    assert.equal(guardWebRequest(crossOriginPost, { env, requireJsonBody: true })?.status, 403);

    // Sec-Fetch-Site: cross-site 拦截 (403)
    const secFetchCross = new Request('http://localhost:3000/api/graphs?id=1', {
        method: 'DELETE',
        headers: {
            host: 'localhost:3000',
            'sec-fetch-site': 'cross-site',
            cookie: `${WEB_SESSION_COOKIE}=${issued.value}`,
        },
    });
    assert.equal(guardWebRequest(secFetchCross, { env })?.status, 403);

    // 表单 Content-Type 拦截 (415)
    const formPost = new Request('http://localhost:3000/api/chat', {
        method: 'POST',
        headers: {
            host: 'localhost:3000',
            origin: 'http://localhost:3000',
            'content-type': 'application/x-www-form-urlencoded',
            cookie: `${WEB_SESSION_COOKIE}=${issued.value}`,
        },
    });
    assert.equal(guardWebRequest(formPost, { env, requireJsonBody: true })?.status, 415);

    // 4. 启用或轮换 WEB_AUTH_TOKEN 后，旧 Cookie 立即失效，Bearer Token 可直接认证
    const envWithToken: NodeJS.ProcessEnv = { ...env, WEB_AUTH_TOKEN: 'super-secret-web-token' };
    assert.equal(guardWebRequest(authedGet, { env: envWithToken })?.status, 401);

    const bearerReq = new Request('http://localhost:3000/api/devices', {
        method: 'GET',
        headers: {
            host: 'localhost:3000',
            authorization: 'Bearer super-secret-web-token',
        },
    });
    assert.equal(guardWebRequest(bearerReq, { env: envWithToken }), null);
});

test('Web 登录失败限流在连续失败后返回 429，成功登录后清零', () => {
    resetWebAuthStateForTests();
    const req = new Request('http://127.0.0.1:3000/api/auth', {
        method: 'POST',
        headers: { host: '127.0.0.1:3000' },
    });
    const baseNow = 1_700_000_000_000;

    for (let i = 0; i < AUTH_MAX_FAILURES; i++) {
        assert.equal(checkAuthRateLimit(req, baseNow + i * 1000), null);
        recordAuthFailure(req, baseNow + i * 1000);
    }

    const blocked = checkAuthRateLimit(req, baseNow + 5000);
    assert.equal(blocked?.status, 429);

    // 窗口过期后自动恢复
    assert.equal(checkAuthRateLimit(req, baseNow + 65_000), null);

    // 再次记录后调用 clearAuthFailures 立即恢复
    for (let i = 0; i < AUTH_MAX_FAILURES; i++) {
        recordAuthFailure(req, baseNow + 70_000 + i);
    }
    assert.equal(checkAuthRateLimit(req, baseNow + 71_000)?.status, 429);
    clearAuthFailures(req);
    assert.equal(checkAuthRateLimit(req, baseNow + 71_000), null);
});
