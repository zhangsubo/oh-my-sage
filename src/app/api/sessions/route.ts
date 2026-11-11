/**
 * Session API
 * 管理 Session 列表
 */

import {NextRequest, NextResponse} from 'next/server';
import {getSessionStore, isValidSessionId} from '@/server/session/store';
import {guardWebRequest} from '@/server/security/webAuth';

export const runtime = 'nodejs';

/**
 * GET /api/sessions
 * 获取 Session 列表
 */
export async function GET(request: NextRequest) {
    const blocked = guardWebRequest(request);
    if (blocked) return blocked;

    try {
        const store = getSessionStore();
        const sessions = await store.listSessions();

        return NextResponse.json({
            success: true,
            sessions,
        });
    } catch (error) {
        console.error('获取 Session 列表失败:', error);
        return NextResponse.json({
            success: false,
            error: '获取 Session 列表失败',
            message: error instanceof Error ? error.message : '未知错误',
            sessions: [],
        }, {status: 500});
    }
}

/**
 * POST /api/sessions
 * 创建新 Session
 */
export async function POST(request: NextRequest) {
    const blocked = guardWebRequest(request, {requireJsonBody: true});
    if (blocked) return blocked;

    try {
        const body = await request.json().catch(() => ({}));
        const title = typeof body?.title === 'string' ? body.title : undefined;

        const store = getSessionStore();
        const session = await store.createSession(title);

        return NextResponse.json({
            success: true,
            session,
        });
    } catch (error) {
        console.error('创建 Session 失败:', error);
        return NextResponse.json({
            success: false,
            error: '创建 Session 失败',
            message: error instanceof Error ? error.message : '未知错误',
        }, {status: 500});
    }
}

/**
 * DELETE /api/sessions?id=xxx
 * 删除 Session
 */
export async function DELETE(request: NextRequest) {
    const blocked = guardWebRequest(request);
    if (blocked) return blocked;

    try {
        const {searchParams} = new URL(request.url);
        const id = searchParams.get('id');

        if (!id) {
            return NextResponse.json({
                success: false,
                error: '缺少 Session ID',
            }, {status: 400});
        }

        if (!isValidSessionId(id)) {
            return NextResponse.json({
                success: false,
                error: '无效的 Session ID',
            }, {status: 400});
        }

        const store = getSessionStore();
        const deleted = await store.deleteSession(id);
        if (!deleted) {
            return NextResponse.json({
                success: false,
                error: 'Session 不存在',
            }, {status: 404});
        }

        return NextResponse.json({
            success: true,
            message: 'Session 已删除',
        });
    } catch (error) {
        console.error('删除 Session 失败:', error);
        return NextResponse.json({
            success: false,
            error: '删除 Session 失败',
            message: error instanceof Error ? error.message : '未知错误',
        }, {status: 500});
    }
}
