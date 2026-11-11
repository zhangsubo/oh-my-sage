/**
 * 认证 API
 * 负责网关认证与 Web 服务端会话签发
 */

import {NextRequest, NextResponse} from 'next/server';
import {connectGateway, isGatewayConnected} from '@/server/gateway/shared';
import {
    checkAuthRateLimit,
    clearAuthFailures,
    extractBearerToken,
    guardWebRequest,
    hasValidWebSession,
    issueWebSessionCookie,
    isWebAuthTokenConfigured,
    recordAuthFailure,
    verifyWebAuthToken,
} from '@/server/security/webAuth';

export const runtime = 'nodejs';

/**
 * GET /api/auth
 * 查询当前会话认证状态与网关连接状态
 */
export async function GET(request: NextRequest) {
    const blocked = guardWebRequest(request, {requireAuth: false});
    if (blocked) return blocked;

    const connected = isGatewayConnected();
    const hasSession = hasValidWebSession(request);
    return NextResponse.json({
        success: true,
        authenticated: connected && hasSession,
        connected,
        tokenRequired: isWebAuthTokenConfigured(),
    });
}

/**
 * POST /api/auth
 * 登录并建立网关连接，签发 HttpOnly 会话 Cookie
 */
export async function POST(request: NextRequest) {
    const blocked = guardWebRequest(request, {requireAuth: false, requireJsonBody: true});
    if (blocked) return blocked;

    const rateLimited = checkAuthRateLimit(request);
    if (rateLimited) return rateLimited;

    let body: Record<string, unknown>;
    try {
        const parsed = await request.json();
        body = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
    } catch {
        return NextResponse.json({
            success: false,
            error: '请求格式错误',
            message: '请求体必须为有效的 JSON',
        }, {status: 400});
    }

    const passcode = body.passcode;
    const candidateToken = typeof body.token === 'string' && body.token.length > 0
        ? body.token
        : extractBearerToken(request);

    if (!verifyWebAuthToken(candidateToken)) {
        recordAuthFailure(request);
        return NextResponse.json({
            success: false,
            error: '访问口令错误',
            message: '请提供正确的 Web 访问口令',
        }, {status: 401});
    }

    try {
        // 若网关已连接且已配置并校验通过 WEB_AUTH_TOKEN，允许仅凭口令恢复 Web 会话
        const canReuseGateway = isGatewayConnected() && isWebAuthTokenConfigured() && (passcode === undefined || passcode === '');

        if (!canReuseGateway) {
            if (typeof passcode !== 'string' || !/^\d{6}$/.test(passcode)) {
                return NextResponse.json({
                    success: false,
                    error: '登录码格式错误',
                    message: '请提供6位数字登录码',
                }, {status: 400});
            }

            if (!process.env.GATEWAY_URL) {
                return NextResponse.json({
                    success: false,
                    error: '未配置网关地址',
                    message: '请在服务端设置 GATEWAY_URL',
                }, {status: 400});
            }

            await connectGateway(passcode);
        }

        clearAuthFailures(request);
        const sessionCookie = issueWebSessionCookie(request);

        return NextResponse.json({
            success: true,
            message: '成功连接到网关',
        }, {
            headers: {
                'Set-Cookie': sessionCookie.headerValue,
            },
        });
    } catch (error) {
        recordAuthFailure(request);
        console.error('认证失败:', error);
        const message = error instanceof Error ? error.message : '未知错误';
        return NextResponse.json({
            success: false,
            error: '认证失败',
            message,
        }, {status: /认证|登录码/.test(message) ? 401 : 502});
    }
}
