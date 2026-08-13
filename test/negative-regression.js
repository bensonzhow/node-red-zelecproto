'use strict';

// 负例/健壮性回归：固化 645 与 698 的"优雅失败契约"。
// - 645：任何畸形输入不得抛异常，失败时 payload.ok === false 并给出 reason；
// - 698：任何畸形输入不得抛异常，失败时设置 msg.error 且 payload === null。
// 探测基线见 2026-08-12 回归测试重规划（一期）。

var assert = require('assert');
var fixtures698 = require('./fixtures/meter-regression.json');
var fixtures645 = require('./fixtures/meter-regression-645.json');
var proto698 = require('../698');
var proto645 = require('../645');

function runQuietly(protocol, input) {
    var originalLog = console.log;
    var originalError = console.error;
    try {
        console.log = function () {};
        console.error = function () {};
        return protocol(input);
    } finally {
        console.log = originalLog;
        console.error = originalError;
    }
}

var passed = 0;
var failed = 0;

function runCase(name, test) {
    try {
        test();
        passed += 1;
        console.log('PASS ' + name);
    } catch (error) {
        failed += 1;
        console.error('FAIL ' + name);
        console.error('  ' + error.message);
    }
}

// 调用协议函数；若抛异常则用例直接失败（负例契约的核心：任何输入都不得崩溃）
function mustNotThrow(protocol, input, label) {
    try {
        return runQuietly(protocol, input);
    } catch (error) {
        assert.fail(label + ' 不应抛异常，实际抛出: ' + error.message);
    }
}

function corrupt645Checksum(frame) {
    // 帧尾结构：... CS 16。将 CS 字节翻转，保证与正确校验和不一致
    var cs = frame.slice(-4, -2);
    return frame.slice(0, -4) + (cs === '00' ? 'FF' : '00') + frame.slice(-2);
}

function corrupt698Fcs(frame) {
    // 698 帧尾结构：... HCS(2字节) 16。破坏 HCS 触发 FCS 校验失败
    return frame.slice(0, -4) + '0000' + frame.slice(-2);
}

var good645Frame = fixtures645.decodeCases[0].frame;
var good698Frame = fixtures698.decodeCases[0].frame;

/* ===================== 645 负例契约 ===================== */

runCase('645 负例 / 空消息原样返回', function () {
    assert.strictEqual(mustNotThrow(proto645, undefined, 'undefined 消息'), undefined);
    assert.strictEqual(mustNotThrow(proto645, null, 'null 消息'), null);
});

runCase('645 负例 / 空 payload 返回 ok:false reason empty', function () {
    ['', undefined, null].forEach(function (payload) {
        var result = mustNotThrow(proto645, { mode: 'decode', payload: payload }, JSON.stringify(payload));
        assert.strictEqual(result.payload.ok, false, 'payload 应标记失败');
        assert.strictEqual(result.payload.reason, 'empty', '失败原因应为 empty');
    });
});

runCase('645 负例 / 空消息对象返回 ok:false', function () {
    var result = mustNotThrow(proto645, {}, '空消息对象');
    assert.strictEqual(result.payload.ok, false, 'payload 应标记失败');
});

runCase('645 负例 / 非字符串 payload 返回 ok:false', function () {
    [12345, { a: 1 }, true].forEach(function (payload) {
        var result = mustNotThrow(proto645, { mode: 'decode', payload: payload }, String(payload));
        assert.strictEqual(result.payload.ok, false, 'payload 应标记失败');
    });
});

runCase('645 负例 / 数组 payload 逐元素处理且不产生成功解码', function () {
    var result = mustNotThrow(proto645, { mode: 'decode', payload: [1, 2, 3] }, '数组 payload');
    assert.ok(Array.isArray(result.payload), '数组输入应返回数组结果');
    result.payload.forEach(function (item, index) {
        assert.notStrictEqual(item && item.ok, true, '第 ' + index + ' 个元素不应解码成功');
    });
});

runCase('645 负例 / 畸形帧返回 ok:false', function () {
    [
        '68AA16',           // 截断帧
        'FFFFFFFFFFFF',     // 无起始符
        '68GG16',           // 非法 hex 字符
        '68AAA16',          // 奇数长度 hex
        'FF'.repeat(100000) // 超长输入
    ].forEach(function (payload) {
        var result = mustNotThrow(proto645, { mode: 'decode', payload: payload }, payload.slice(0, 20));
        assert.strictEqual(result.payload.ok, false, 'payload 应标记失败: ' + payload.slice(0, 20));
    });
});

runCase('645 负例 / 校验和错误返回 reason cs_fail', function () {
    var result = mustNotThrow(proto645, { mode: 'decode', payload: corrupt645Checksum(good645Frame) }, '坏校验和帧');
    assert.strictEqual(result.payload.reason, 'cs_fail', '应报告校验和失败');
    assert.strictEqual(result.payload.success, false, 'success 应为 false');
});

runCase('645 负例 / 小写合法帧仍可解码成功', function () {
    var result = mustNotThrow(proto645, { mode: 'decode', payload: good645Frame.toLowerCase() }, '小写帧');
    assert.strictEqual(result.payload.ok, true, '小写帧应解码成功');
});

/* ===================== 698 负例契约 ===================== */

runCase('698 负例 / 空消息原样返回', function () {
    // 698 入口对空消息统一返回 undefined，契约是不抛异常
    assert.strictEqual(mustNotThrow(proto698, undefined, 'undefined 消息'), undefined);
    assert.strictEqual(mustNotThrow(proto698, null, 'null 消息'), undefined);
});

runCase('698 负例 / 空 payload 返回"输入为空"错误', function () {
    ['', undefined, null].forEach(function (payload) {
        var result = mustNotThrow(proto698, { mode: 'decode', payload: payload }, JSON.stringify(payload));
        assert.ok(/输入为空/.test(result.error), 'error 应为"输入为空"，实际: ' + result.error);
        assert.strictEqual(result.payload, null, 'payload 应置为 null');
    });
});

runCase('698 负例 / 空消息对象返回"输入为空"错误', function () {
    var result = mustNotThrow(proto698, {}, '空消息对象');
    assert.ok(/输入为空/.test(result.error), 'error 应为"输入为空"，实际: ' + result.error);
});

runCase('698 负例 / 非字符串 payload 返回帧格式错误', function () {
    [12345, { a: 1 }].forEach(function (payload) {
        var result = mustNotThrow(proto698, { mode: 'decode', payload: payload }, String(payload));
        assert.ok(/帧格式无法识别/.test(result.error), 'error 应报告帧格式无法识别，实际: ' + result.error);
        assert.strictEqual(result.payload, null, 'payload 应置为 null');
    });
});

runCase('698 负例 / 基本类型元素数组不抛异常', function () {
    // 批量入口约定 payload 为消息对象数组；元素为基本类型时不得崩溃
    mustNotThrow(proto698, { mode: 'decode', payload: [1, 2, 3] }, '基本类型元素数组');
});

runCase('698 负例 / 批量数组含空元素不抛异常', function () {
    // 空元素（null/undefined）不得拖垮整个批次，应原样通过
    var withNull = mustNotThrow(proto698, { mode: 'decode', payload: [null] }, '[null]');
    assert.deepStrictEqual(withNull.payload, [null], 'null 元素应原样通过');
    var withUndefined = mustNotThrow(proto698, { mode: 'decode', payload: [undefined] }, '[undefined]');
    assert.deepStrictEqual(withUndefined.payload, [undefined], 'undefined 元素应原样通过');
});

runCase('698 负例 / 混合批量中空元素不影响有效帧解码', function () {
    var result = mustNotThrow(proto698, {
        mode: 'decode',
        payload: [{ payload: good698Frame }, null, { payload: good698Frame }]
    }, '混合批量');
    assert.strictEqual(result.payload.length, 3, '应返回 3 个元素的结果');
    assert.strictEqual(result.payload[0].error, undefined, '第 1 帧应正常解码');
    assert.ok(result.payload[0].payload, '第 1 帧应解码出 payload');
    assert.strictEqual(result.payload[1], null, '空元素应原样通过');
    assert.strictEqual(result.payload[2].error, undefined, '第 3 帧应正常解码');
});

runCase('698 负例 / 长度域与帧长不匹配的帧被拒绝', function () {
    // 基于 SET-Response 合成帧：长度域 0x17 篡改为 0x18（实际帧长不变），
    // HCS/FCS 已按篡改后的长度域重算为正确值——只有长度校验能拦住它
    var tamperedFrame = '681800C30591959032000011E4148601014001020000F44616';
    var result = mustNotThrow(proto698, { mode: 'decode', payload: tamperedFrame }, '长度域不匹配帧');
    assert.ok(/长度域不匹配/.test(result.error), '应以长度域错误拒绝，实际: ' + result.error);
    assert.strictEqual(result.payload, null, 'payload 应置为 null');
});

runCase('698 负例 / 畸形帧返回帧格式错误', function () {
    [
        '68AA16',           // 截断帧
        'FFFFFFFFFFFF',     // 无起始符
        '68GG16',           // 非法 hex 字符
        '68AAA16',          // 奇数长度 hex
        'FF'.repeat(100000) // 超长输入
    ].forEach(function (payload) {
        var result = mustNotThrow(proto698, { mode: 'decode', payload: payload }, payload.slice(0, 20));
        assert.ok(/帧格式无法识别/.test(result.error), 'error 应报告帧格式无法识别: ' + payload.slice(0, 20));
        assert.strictEqual(result.payload, null, 'payload 应置为 null');
    });
});

runCase('698 负例 / FCS 校验错误返回明确错误', function () {
    var result = mustNotThrow(proto698, { mode: 'decode', payload: corrupt698Fcs(good698Frame) }, '坏 FCS 帧');
    assert.ok(/FCS校验失败/.test(result.error), 'error 应报告 FCS 校验失败，实际: ' + result.error);
    assert.strictEqual(result.payload, null, 'payload 应置为 null');
});

runCase('698 负例 / 合法帧解码不受影响', function () {
    var result = mustNotThrow(proto698, { mode: 'decode', payload: good698Frame }, '合法帧');
    assert.strictEqual(result.error, undefined, '合法帧不应有 error');
    assert.ok(result.payload, '合法帧应解码出 payload');
});

runCase('698 负例 / Buffer 输入可正常解码', function () {
    var result = mustNotThrow(proto698, { mode: 'decode', payload: Buffer.from(good698Frame, 'hex') }, 'Buffer 输入');
    assert.strictEqual(result.error, undefined, 'Buffer 输入不应有 error');
    assert.ok(result.payload, 'Buffer 输入应解码出 payload');
});

console.log('');
console.log('负例回归测试: ' + passed + ' 通过, ' + failed + ' 失败');

if (failed > 0) process.exitCode = 1;
