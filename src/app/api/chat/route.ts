/**
 * Chat API
 * 使用已建立的 WebSocket 连接进行对话
 */

import {NextRequest, NextResponse} from 'next/server';
import {getGateway, isGatewayConnected} from '@/server/gateway/shared';
import {Agent} from '@/server/agent/agent';
import {getModelConfigFromEnv} from '@/server/ai/model';
import {getSessionStore, isValidSessionId} from '@/server/session/store';
import {guardWebRequest} from '@/server/security/webAuth';

export const runtime = 'nodejs';

/**
 * POST /api/chat
 */
export async function POST(request: NextRequest) {
    const blocked = guardWebRequest(request, {requireJsonBody: true});
    if (blocked) return blocked;

    try {
        const body = await request.json();
        const {message, sessionId} = body ?? {};

        if (typeof message !== 'string' || !message.trim()) {
            return NextResponse.json({error: '缺少消息内容'}, {status: 400});
        }

        // 检查网关连接
        if (!isGatewayConnected()) {
            return NextResponse.json({error: '请先登录连接网关'}, {status: 400});
        }

        const store = getSessionStore();
        let resolvedSessionId: string | null = null;
        if (sessionId !== undefined && sessionId !== null && sessionId !== '') {
            if (typeof sessionId !== 'string' || !isValidSessionId(sessionId)) {
                return NextResponse.json({error: '无效的 Session ID'}, {status: 400});
            }
            const existing = await store.getSessionMeta(sessionId);
            if (!existing) {
                return NextResponse.json({error: 'Session 不存在'}, {status: 404});
            }
            resolvedSessionId = sessionId;
        }

        // 使用已建立的连接
        const gateway = getGateway()!;
        const config = getModelConfigFromEnv();
        const agent = new Agent(gateway, config);

        // 如果有 sessionId，加载历史；否则创建新 Session
        if (resolvedSessionId) {
            await agent.loadSession(resolvedSessionId);
        } else {
            const newSession = await store.createSession();
            agent.setSession(newSession.id);
        }

        const encoder = new TextEncoder();
        const stream = new ReadableStream({
            async start(controller) {
                try {
                    for await (const output of agent.run(message)) {
                        const data = JSON.stringify(output);
                        controller.enqueue(encoder.encode(`data: ${data}\n\n`));
                    }
                    controller.enqueue(encoder.encode('data: [DONE]\n\n'));
                    controller.close();
                } catch (error) {
                    const errorOutput = {type: 'error', error: String(error)};
                    controller.enqueue(encoder.encode(`data: ${JSON.stringify(errorOutput)}\n\n`));
                    controller.close();
                }
            },
        });

        return new Response(stream, {
            headers: {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
            },
        });

    } catch (error) {
        console.error('Chat API error:', error);
        return NextResponse.json({error: String(error)}, {status: 500});
    }
}

/**
 * GET /api/chat
 */
export async function GET(request: NextRequest) {
    const blocked = guardWebRequest(request);
    if (blocked) return blocked;

    return NextResponse.json({
        status: 'ok',
        connected: isGatewayConnected(),
    });
}
