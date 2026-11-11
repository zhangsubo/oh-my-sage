/**
 * Web 模式服务端认证、会话管理、CSRF 与速率限制守卫
 */

import crypto from 'crypto';
import {NextResponse} from 'next/server';

export const WEB_SESSION_COOKIE = 'oh_my_sage_session';
export const WEB_SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 小时
export const WEB_MAX_SESSIONS = 32;
export const AUTH_RATE_WINDOW_MS = 60 * 1000;
export const AUTH_MAX_FAILURES = 5;

const STATE_KEY = '__oh_my_sage_web_auth_state__';
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

interface SessionEntry {
    expiresAt: number;
    webTokenDigest: string | null;
}

interface WebAuthState {
    sessions: Map<string, SessionEntry>;
    failures: Map<string, number[]>;
}

export interface GuardWebRequestOptions {
    /** 是否要求已通过 Web 会话或 Bearer Token 认证（默认 true） */
    requireAuth?: boolean;
    /** 是否要求变更请求携带 Content-Type: application/json（默认 false） */
    requireJsonBody?: boolean;
    /** 测试注入的环境变量（默认 process.env） */
    env?: NodeJS.ProcessEnv;
    /** 测试注入的当前时间戳（默认 Date.now()） */
    now?: number;
}

function getAuthState(): WebAuthState {
    const g = globalThis as Record<string, unknown>;
    if (!g[STATE_KEY]) {
        g[STATE_KEY] = {
            sessions: new Map<string, SessionEntry>(),
            failures: new Map<string, number[]>(),
        } satisfies WebAuthState;
    }
    return g[STATE_KEY] as WebAuthState;
}

export function sha256Hex(value: string): string {
    return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function timingSafeEqualString(a: string, b: string): boolean {
    const digestA = crypto.createHash('sha256').update(a, 'utf8').digest();
    const digestB = crypto.createHash('sha256').update(b, 'utf8').digest();
    return crypto.timingSafeEqual(digestA, digestB);
}

function normalizeHostnameToken(raw: string): string | null {
    const trimmed = raw.trim().toLowerCase();
    if (!trimmed) return null;
    if (trimmed === '::1' || trimmed === '[::1]') return '[::1]';
    try {
        const parsed = new URL(`http://${trimmed}`);
        if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
            return null;
        }
        return parsed.hostname.toLowerCase();
    } catch {
        return null;
    }
}

export function resolveAllowedWebHosts(env: NodeJS.ProcessEnv = process.env): Set<string> {
    const allowed = new Set<string>(['localhost', '127.0.0.1', '[::1]']);
    const extra = env.WEB_ALLOWED_HOSTS;
    if (extra) {
        for (const item of extra.split(',')) {
            const normalized = normalizeHostnameToken(item);
            if (normalized) {
                allowed.add(normalized);
            }
        }
    }
    return allowed;
}

export function isAllowedWebHost(hostHeader: string | null, env: NodeJS.ProcessEnv = process.env): boolean {
    if (!hostHeader) return false;
    const hostname = normalizeHostnameToken(hostHeader);
    if (!hostname) return false;
    return resolveAllowedWebHosts(env).has(hostname);
}

function isSameOriginAsHost(originHeader: string, hostHeader: string): boolean {
    if (originHeader === 'null') return false;
    try {
        const originUrl = new URL(originHeader);
        if (originUrl.protocol !== 'http:' && originUrl.protocol !== 'https:') {
            return false;
        }
        const expectedUrl = new URL(`${originUrl.protocol}//${hostHeader.trim()}`);
        return originUrl.host.toLowerCase() === expectedUrl.host.toLowerCase();
    } catch {
        return false;
    }
}

function parseCookies(cookieHeader: string | null): Record<string, string> {
    const result: Record<string, string> = {};
    if (!cookieHeader) return result;
    for (const part of cookieHeader.split(';')) {
        const eqIdx = part.indexOf('=');
        if (eqIdx <= 0) continue;
        const name = part.slice(0, eqIdx).trim();
        const value = part.slice(eqIdx + 1).trim();
        if (name) {
            result[name] = value;
        }
    }
    return result;
}

export function isWebAuthTokenConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
    return Boolean(env.WEB_AUTH_TOKEN && env.WEB_AUTH_TOKEN.trim().length > 0);
}

function currentWebTokenDigest(env: NodeJS.ProcessEnv = process.env): string | null {
    const configured = env.WEB_AUTH_TOKEN?.trim();
    return configured ? sha256Hex(configured) : null;
}

export function verifyWebAuthToken(candidate: unknown, env: NodeJS.ProcessEnv = process.env): boolean {
    const configured = env.WEB_AUTH_TOKEN?.trim();
    if (!configured) return true;
    if (typeof candidate !== 'string' || candidate.length === 0) return false;
    return timingSafeEqualString(candidate, configured);
}

export function extractBearerToken(request: Request): string | null {
    const authHeader = request.headers.get('authorization');
    if (!authHeader) return null;
    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : null;
}

function sweepExpiredSessions(state: WebAuthState, now: number): void {
    for (const [digest, entry] of state.sessions.entries()) {
        if (entry.expiresAt <= now) {
            state.sessions.delete(digest);
        }
    }
}

export function hasValidWebSession(
    request: Request,
    env: NodeJS.ProcessEnv = process.env,
    now: number = Date.now(),
): boolean {
    // 1. 若配置了 WEB_AUTH_TOKEN，允许直接通过 Authorization: Bearer <WEB_AUTH_TOKEN> 调用 API
    if (isWebAuthTokenConfigured(env)) {
        const bearer = extractBearerToken(request);
        if (bearer && verifyWebAuthToken(bearer, env)) {
            return true;
        }
    }

    // 2. 检查服务端签发的 HttpOnly Session Cookie
    const cookies = parseCookies(request.headers.get('cookie'));
    const rawSession = cookies[WEB_SESSION_COOKIE];
    if (!rawSession || !/^[a-f0-9]{64}$/.test(rawSession)) {
        return false;
    }

    const state = getAuthState();
    sweepExpiredSessions(state, now);

    const sessionDigest = sha256Hex(rawSession);
    const entry = state.sessions.get(sessionDigest);
    if (!entry) return false;

    // 若服务端新增或轮换了 WEB_AUTH_TOKEN，旧 Cookie 自动失效
    const expectedTokenDigest = currentWebTokenDigest(env);
    if (entry.webTokenDigest !== expectedTokenDigest) {
        state.sessions.delete(sessionDigest);
        return false;
    }

    return true;
}

export function issueWebSessionCookie(
    request: Request,
    env: NodeJS.ProcessEnv = process.env,
    now: number = Date.now(),
): { name: string; value: string; headerValue: string } {
    const state = getAuthState();
    sweepExpiredSessions(state, now);

    while (state.sessions.size >= WEB_MAX_SESSIONS) {
        const oldestKey = state.sessions.keys().next().value;
        if (!oldestKey) break;
        state.sessions.delete(oldestKey);
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    state.sessions.set(sha256Hex(rawToken), {
        expiresAt: now + WEB_SESSION_TTL_MS,
        webTokenDigest: currentWebTokenDigest(env),
    });

    const forwardedProto = request.headers.get('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase();
    const isSecure = forwardedProto === 'https' || request.url.startsWith('https://');
    const maxAgeSec = Math.floor(WEB_SESSION_TTL_MS / 1000);
    const headerValue = `${WEB_SESSION_COOKIE}=${rawToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${isSecure ? '; Secure' : ''}`;

    return {
        name: WEB_SESSION_COOKIE,
        value: rawToken,
        headerValue,
    };
}

function getRateLimitKey(request: Request): string {
    const host = request.headers.get('host') || 'local';
    return host.toLowerCase();
}

export function checkAuthRateLimit(request: Request, now: number = Date.now()): NextResponse | null {
    const state = getAuthState();
    const key = getRateLimitKey(request);
    const recent = (state.failures.get(key) || []).filter(ts => now - ts < AUTH_RATE_WINDOW_MS);
    if (recent.length === 0) {
        state.failures.delete(key);
    } else {
        state.failures.set(key, recent);
    }

    if (recent.length >= AUTH_MAX_FAILURES) {
        return NextResponse.json(
            {
                success: false,
                error: '尝试过于频繁',
                message: '认证失败次数过多，请等待 1 分钟后再试',
            },
            {status: 429, headers: {'Retry-After': '60'}},
        );
    }
    return null;
}

export function recordAuthFailure(request: Request, now: number = Date.now()): void {
    const state = getAuthState();
    const key = getRateLimitKey(request);
    const recent = (state.failures.get(key) || []).filter(ts => now - ts < AUTH_RATE_WINDOW_MS);
    recent.push(now);
    state.failures.set(key, recent);
}

export function clearAuthFailures(request: Request): void {
    const state = getAuthState();
    state.failures.delete(getRateLimitKey(request));
}

/**
 * 统一校验 Web API 请求的 Host、CSRF（Origin / Sec-Fetch-Site / Content-Type）与登录会话
 * 返回 null 表示校验通过；否则返回可直接响应的 NextResponse
 */
export function guardWebRequest(request: Request, options: GuardWebRequestOptions = {}): NextResponse | null {
    const env = options.env ?? process.env;
    const now = options.now ?? Date.now();
    const requireAuth = options.requireAuth !== false;
    const requireJsonBody = options.requireJsonBody === true;
    const method = request.method.toUpperCase();

    // 1. 校验 Host 请求头（防御 DNS Rebinding）
    const hostHeader = request.headers.get('host');
    if (!isAllowedWebHost(hostHeader, env)) {
        return NextResponse.json(
            {success: false, error: '非法 Host 请求头'},
            {status: 403},
        );
    }

    // 2. 变更类请求的跨站请求伪造（CSRF）防护
    if (MUTATING_METHODS.has(method)) {
        const secFetchSite = request.headers.get('sec-fetch-site')?.trim().toLowerCase();
        if (secFetchSite === 'cross-site') {
            return NextResponse.json(
                {success: false, error: '拒绝跨站请求'},
                {status: 403},
            );
        }

        const originHeader = request.headers.get('origin')?.trim();
        if (originHeader && !isSameOriginAsHost(originHeader, hostHeader!)) {
            return NextResponse.json(
                {success: false, error: '非法 Origin 请求头'},
                {status: 403},
            );
        }

        if (requireJsonBody) {
            const contentType = request.headers.get('content-type')?.trim().toLowerCase() || '';
            if (!contentType.startsWith('application/json')) {
                return NextResponse.json(
                    {success: false, error: 'Content-Type 必须为 application/json'},
                    {status: 415},
                );
            }
        }
    }

    // 3. 服务端登录态校验
    if (requireAuth && !hasValidWebSession(request, env, now)) {
        return NextResponse.json(
            {
                success: false,
                error: '未登录或会话已过期',
                message: '请先登录并完成认证',
            },
            {status: 401},
        );
    }

    return null;
}

/**
 * 仅供单元测试重置全局认证与限流状态
 */
export function resetWebAuthStateForTests(): void {
    const state = getAuthState();
    state.sessions.clear();
    state.failures.clear();
}
