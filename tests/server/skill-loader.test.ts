import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {clearSkillsCache, listResources, loadSkills, readSkillFile} from '../../src/server/skills/loader';

test('Skill 资源列表递归发现嵌套参考文件', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oh-my-sage-skill-'));
    try {
        fs.mkdirSync(path.join(root, 'references', 'patterns'), {recursive: true});
        fs.writeFileSync(path.join(root, 'SKILL.md'), 'ignored');
        fs.writeFileSync(path.join(root, 'references', 'index.md'), 'index');
        fs.writeFileSync(path.join(root, 'references', 'patterns', 'sync.md'), 'sync');

        assert.deepEqual(listResources(root).sort(), [
            'references/index.md',
            'references/patterns/sync.md',
        ]);
    } finally {
        fs.rmSync(root, {recursive: true, force: true});
    }
});

test('Skill 资源列表忽略隐藏目录并保持稳定顺序', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oh-my-sage-skill-'));
    try {
        fs.mkdirSync(path.join(root, 'references'), {recursive: true});
        fs.mkdirSync(path.join(root, '.private'), {recursive: true});
        fs.writeFileSync(path.join(root, 'z.md'), 'z');
        fs.writeFileSync(path.join(root, 'references', 'b.md'), 'b');
        fs.writeFileSync(path.join(root, 'references', 'a.md'), 'a');
        fs.writeFileSync(path.join(root, '.private', 'secret.md'), 'secret');

        assert.deepEqual(listResources(root), [
            'references/a.md',
            'references/b.md',
            'z.md',
        ]);
    } finally {
        fs.rmSync(root, {recursive: true, force: true});
    }
});

test('Skill 文件读取拒绝同前缀兄弟目录越界', () => {
    const root = fs.mkdtempSync(path.join(process.cwd(), '.agents', 'skills', 'loader-test-'));
    const sibling = `${root}-private`;
    try {
        fs.mkdirSync(sibling);
        fs.writeFileSync(path.join(root, 'SKILL.md'), [
            '---',
            'name: loader-test',
            'description: loader test',
            '---',
            'test',
        ].join('\n'));
        fs.writeFileSync(path.join(sibling, 'secret.md'), 'secret');

        clearSkillsCache();
        assert.equal(readSkillFile('loader-test', `../${path.basename(sibling)}/secret.md`), null);
    } finally {
        clearSkillsCache();
        fs.rmSync(root, {recursive: true, force: true});
        fs.rmSync(sibling, {recursive: true, force: true});
    }
});

test('Skill 文件读取拒绝符号链接越界', {skip: process.platform === 'win32'}, () => {
    const root = fs.mkdtempSync(path.join(process.cwd(), '.agents', 'skills', 'loader-link-test-'));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'oh-my-sage-outside-'));
    try {
        fs.writeFileSync(path.join(root, 'SKILL.md'), [
            '---',
            'name: loader-link-test',
            'description: loader link test',
            '---',
            'test',
        ].join('\n'));
        fs.writeFileSync(path.join(outside, 'secret.md'), 'secret');
        fs.symlinkSync(outside, path.join(root, 'linked'), 'dir');

        clearSkillsCache();
        assert.equal(readSkillFile('loader-link-test', 'linked/secret.md'), null);
    } finally {
        clearSkillsCache();
        fs.rmSync(root, {recursive: true, force: true});
        fs.rmSync(outside, {recursive: true, force: true});
    }
});

test('默认隔离宿主机 ~/.agents/skills，仅在显式开启 OH_MY_SAGE_LOAD_USER_SKILLS=true 时加载', () => {
    const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'oh-my-sage-home-'));
    const userSkillDir = path.join(fakeHome, '.agents', 'skills', 'host-private-skill');
    const prevHome = process.env.HOME;
    const prevFlag = process.env.OH_MY_SAGE_LOAD_USER_SKILLS;

    try {
        fs.mkdirSync(userSkillDir, {recursive: true});
        fs.writeFileSync(path.join(userSkillDir, 'SKILL.md'), [
            '---',
            'name: host-private-skill',
            'description: private host skill',
            '---',
            'private',
        ].join('\n'));

        process.env.HOME = fakeHome;
        delete process.env.OH_MY_SAGE_LOAD_USER_SKILLS;
        clearSkillsCache();

        const isolated = loadSkills();
        assert.equal(isolated.some(s => s.name === 'host-private-skill'), false);

        process.env.OH_MY_SAGE_LOAD_USER_SKILLS = 'true';
        clearSkillsCache();
        const optedIn = loadSkills();
        assert.equal(optedIn.some(s => s.name === 'host-private-skill'), true);
    } finally {
        if (prevHome === undefined) delete process.env.HOME;
        else process.env.HOME = prevHome;
        if (prevFlag === undefined) delete process.env.OH_MY_SAGE_LOAD_USER_SKILLS;
        else process.env.OH_MY_SAGE_LOAD_USER_SKILLS = prevFlag;
        clearSkillsCache();
        fs.rmSync(fakeHome, {recursive: true, force: true});
    }
});

test('mijia-automation 内置规则文本格式参考可在沙箱内读取', () => {
    clearSkillsCache();
    const content = readSkillFile('mijia-automation', 'references/rule-text-format.md');
    assert.ok(content && content.includes('# 规则文本格式'));
});
