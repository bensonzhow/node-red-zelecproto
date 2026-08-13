'use strict';

// 往返回归：编码得到的帧必须能被解码器吃回去，且关键字段可还原。
// - 645：encode → decode 后还原通信地址（含小端反转）、数据标识 DI、控制码；
// - 698：encode → decode 后帧结构校验通过（FCS/长度），还原服务器地址与 OAD。
// 语料层只覆盖解码方向，本层专门守住编码方向的闭环。

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

function getPath(value, path) {
    return path.split('.').reduce(function (current, key) {
        return current == null ? undefined : current[key];
    }, value);
}

function deepCopy(value) {
    return JSON.parse(JSON.stringify(value));
}

// 645 地址字段按字节小端存放：解码侧 exec_addr 是字节序反转后的展示
function reverseHexPairs(hex) {
    return hex.match(/../g).reverse().join('');
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

/* ===================== 645 往返 ===================== */

fixtures645.encodeCases.forEach(function (testCase) {
    runCase('645 往返 / ' + testCase.name, function () {
        var encoded = runQuietly(proto645, deepCopy(testCase.input));
        assert.strictEqual(encoded.error, undefined, '编码不应返回 error');
        var frame = getPath(encoded, testCase.framePath || 'payload');
        assert.strictEqual(frame, testCase.expectedFrame, '编码帧发生变化');

        var decoded = runQuietly(proto645, { mode: 'decode', payload: frame });
        assert.strictEqual(decoded.payload.ok, true, '编码出的帧应能解码成功');

        var command = testCase.input.payload;
        if (command.com_exec_addr) {
            // 单播帧：解码应还原帧内原始字节与按字节反转后的展示地址
            assert.strictEqual(
                decoded.payload.addr_bytes_hex,
                command.com_exec_addr,
                '帧内地址字节与编码输入不一致'
            );
            assert.strictEqual(
                decoded.payload.exec_addr,
                reverseHexPairs(command.com_exec_addr),
                '解码地址未按 645 小端规则反转'
            );
            assert.strictEqual(decoded.payload.ctrl, 0x11, '单播读命令控制码应为 0x11');
        } else {
            // 广播帧：地址域全 AA
            assert.strictEqual(decoded.payload.addr_bytes_hex, 'AAAAAAAAAAAA', '广播地址域应为全 AA');
            assert.strictEqual(decoded.payload.ctrl, 0x13, '广播读命令控制码应为 0x13');
        }

        if (command.oad && command.oad !== 'readAddress') {
            assert.strictEqual(decoded.payload.di, command.oad, '解码 DI 与编码 OAD 不一致');
        }
    });
});

runCase('645 往返 / 批量编码数组逐帧可解码', function () {
    var commands = [
        { oad: '0001FF00', com_exec_addr: '643798000000' },
        { oad: '0400040B', com_exec_addr: '643798000000' }
    ];
    var encoded = runQuietly(proto645, { mode: 'encode', cs_mode: 'full', payload: deepCopy(commands) });
    assert.ok(Array.isArray(encoded.payload), '批量编码应返回帧数组');
    assert.strictEqual(encoded.payload.length, commands.length, '批量编码帧数与命令数不一致');

    encoded.payload.forEach(function (item, index) {
        // 批量编码结果为扩展命令对象数组，帧存放在各元素的 payload 字段
        var frame = item && item.payload;
        assert.strictEqual(typeof frame, 'string', '第 ' + index + ' 个元素应包含帧字符串');
        var decoded = runQuietly(proto645, { mode: 'decode', payload: frame });
        assert.strictEqual(decoded.payload.ok, true, '第 ' + index + ' 帧应能解码成功');
        assert.strictEqual(decoded.payload.di, commands[index].oad, '第 ' + index + ' 帧 DI 不一致');
        assert.strictEqual(
            decoded.payload.addr_bytes_hex,
            commands[index].com_exec_addr,
            '第 ' + index + ' 帧地址不一致'
        );
    });
});

runCase('645 往返 / 默认 std 校验和模式编码可解码', function () {
    // cs_mode 缺省即 std（C+L+DATA 累加），是生产默认路径；既有夹具全部显式用 full，此用例守住默认值
    var command = { oad: '0001FF00', com_exec_addr: '643798000000' };
    var stdEncoded = runQuietly(proto645, { mode: 'encode', payload: deepCopy(command) });
    var stdFrame = stdEncoded.payload.payload;
    assert.strictEqual(typeof stdFrame, 'string', '应编码出帧');

    var fullEncoded = runQuietly(proto645, { mode: 'encode', cs_mode: 'full', payload: deepCopy(command) });
    var fullFrame = fullEncoded.payload.payload;
    assert.strictEqual(stdFrame.slice(0, -4), fullFrame.slice(0, -4), 'std/full 两模式帧体应一致');
    assert.notStrictEqual(stdFrame.slice(-4), fullFrame.slice(-4), 'std/full 校验和字节应不同');

    var decoded = runQuietly(proto645, { mode: 'decode', payload: stdFrame });
    assert.strictEqual(decoded.payload.ok, true, 'std 模式帧应通过双模校验和解码成功');
    assert.strictEqual(decoded.payload.di, command.oad, 'DI 不一致');
    assert.strictEqual(decoded.payload.addr_bytes_hex, command.com_exec_addr, '地址不一致');
});

runCase('645 往返 / addr_reverse 编码地址字节序反转', function () {
    var command = { oad: '0001FF00', com_exec_addr: '643798000000' };
    var encoded = runQuietly(proto645, { mode: 'encode', cs_mode: 'full', addr_reverse: true, payload: deepCopy(command) });
    var frame = encoded.payload.payload;
    assert.ok(frame.indexOf('000000983764') >= 0, '帧内地址应为输入地址的字节反转');

    var decoded = runQuietly(proto645, { mode: 'decode', payload: frame });
    assert.strictEqual(decoded.payload.ok, true, '反转地址帧应解码成功');
    assert.strictEqual(decoded.payload.addr_bytes_hex, '000000983764', '帧内原始字节应为反转序');
    assert.strictEqual(decoded.payload.exec_addr, '643798000000', '解码再反转后应还原为原通信地址');
    assert.strictEqual(decoded.payload.di, command.oad, 'DI 不一致');
});

/* ===================== 698 往返 ===================== */

fixtures698.encodeCases.forEach(function (testCase) {
    runCase('698 往返 / ' + testCase.name, function () {
        var encoded = runQuietly(proto698, deepCopy(testCase.input));
        assert.strictEqual(encoded.error, undefined, '编码不应返回 error');
        assert.strictEqual(encoded.payload, testCase.expectedFrame, '编码帧发生变化');

        var decoded = runQuietly(proto698, { mode: 'decode', payload: encoded.payload });
        assert.strictEqual(decoded.error, undefined, '编码出的帧应通过帧结构与 FCS 校验');

        var frameInfo = decoded.decoding_details && decoded.decoding_details.frameInfo;
        assert.ok(frameInfo, '解码应输出 frameInfo');
        assert.strictEqual(frameInfo.lengthMatched, true, '帧长度域与实际长度不一致');
        assert.strictEqual(
            frameInfo.serverAddress,
            testCase.input.payload.sa,
            '解码还原的服务器地址与编码输入不一致'
        );

        var unified = decoded.decoding_details.unifiedFormat;
        var oadHex = testCase.input.payload.oadHex.toUpperCase();
        var rawData = (unified && unified.rawData) || '';
        assert.ok(rawData.indexOf(oadHex) >= 0, 'APDU 中应包含编码的 OAD ' + oadHex);
    });
});

runCase('698 往返 / apduHex 与自定义控制码编码还原已知帧', function () {
    // apduHex 直通 APDU + 自定义控制码是 698 编码的逃生通道，
    // 以广播读地址帧为目标帧：两条路径都必须逐字节复现
    var expectedFrame = fixtures698.encodeCases[0].expectedFrame;

    var viaApduHex = runQuietly(proto698, {
        mode: 'encode',
        payload: { sa: 'AAAAAAAAAAAA', saType: 1, ctrl: 0x43, apduHex: '0501004001020000', security: 'none' }
    });
    assert.strictEqual(viaApduHex.error, undefined, '编码不应返回 error');
    assert.strictEqual(viaApduHex.payload, expectedFrame, 'apduHex 路径未复现目标帧');

    var viaCustom = runQuietly(proto698, {
        mode: 'encode',
        payload: { sa: 'AAAAAAAAAAAA', saType: 1, security: 'none', customParameter: { controlCode: '43', apduHex: '0501004001020000' } }
    });
    assert.strictEqual(viaCustom.payload, expectedFrame, 'customParameter 路径未复现目标帧');

    var decoded = runQuietly(proto698, { mode: 'decode', payload: viaApduHex.payload });
    assert.strictEqual(decoded.error, undefined, '编码帧应通过帧结构与 FCS 校验');
});

console.log('');
console.log('往返回归测试: ' + passed + ' 通过, ' + failed + ' 失败');

if (failed > 0) process.exitCode = 1;
