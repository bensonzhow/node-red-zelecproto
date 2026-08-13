'use strict';

var assert = require('assert');
var fixtures698 = require('./fixtures/meter-regression.json');
var fixtures645 = require('./fixtures/meter-regression-645.json');
var samples645 = require('./fixtures/meter-regression-645-samples.json');
var samples698 = require('./fixtures/meter-regression-698-samples.json');
var proto698 = require('../698');
var proto645 = require('../645');
var normalize = require('./lib/regression-normalizer').normalize;

function getPath(value, path) {
    return path.split('.').reduce(function (current, key) {
        return current == null ? undefined : current[key];
    }, value);
}

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

function verifyExpected(result, expected) {
    Object.keys(expected).forEach(function (path) {
        assert.deepStrictEqual(
            getPath(result, path),
            expected[path],
            path + ' 回归值不一致'
        );
    });
}

function verifyStartsWith(result, expected) {
    Object.keys(expected || {}).forEach(function (path) {
        var actual = getPath(result, path);
        assert.strictEqual(typeof actual, 'string', path + ' 应为字符串');
        assert.ok(actual.startsWith(expected[path]), path + ' 前缀不一致');
    });
}

function hasMeaningfulBusinessValue(value) {
    if (value === undefined || value === null) return false;
    if (typeof value === 'string') return value.trim().length > 0;
    if (typeof value === 'number') return Number.isFinite(value); // 0 是合法业务值
    if (typeof value === 'boolean' || typeof value === 'bigint') return true; // false 也是合法业务值
    if (Buffer.isBuffer(value)) return value.length > 0;
    if (Array.isArray(value)) return value.length > 0 && value.some(hasMeaningfulBusinessValue);
    if (typeof value === 'object') {
        var keys = Object.keys(value);
        return keys.length > 0 && keys.some(function (key) {
            return hasMeaningfulBusinessValue(value[key]);
        });
    }
    return false;
}

function assertSuccessful698Value(payload, label) {
    if (!payload || payload.success !== true) return;
    assert.ok(
        Object.prototype.hasOwnProperty.call(payload, 'value'),
        label + ' 解码成功但缺少 payload.value'
    );
    assert.ok(
        hasMeaningfulBusinessValue(payload.value),
        label + ' 解码成功但 payload.value 为空'
    );
}

function assert645SampleValue(payload, label) {
    // 地址响应的业务结果是 exec_addr，协议拒绝响应则以 reason/detail 表达，二者都没有 value。
    if (payload && (payload.type === 'address_response' || payload.ok === false)) return;
    assert.ok(payload && Object.prototype.hasOwnProperty.call(payload, 'value'), label + ' 缺少 payload.value');
    assert.ok(hasMeaningfulBusinessValue(payload.value), label + ' payload.value 为空');
}

var passed = 0;
var failed = 0;
var sample645Frames = 0;
var sample698Frames = 0;

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

function runFixture(protocolName, protocol, fixtures) {
    fixtures.encodeCases.forEach(function (testCase) {
        runCase(protocolName + ' 编码 / ' + testCase.name, function () {
            var result = runQuietly(protocol, JSON.parse(JSON.stringify(testCase.input)));
            assert.strictEqual(result.error, undefined, '编码不应返回 error');
            assert.strictEqual(
                getPath(result, testCase.framePath || 'payload'),
                testCase.expectedFrame,
                '编码帧发生变化'
            );
        });
    });

    fixtures.decodeCases.forEach(function (testCase) {
        runCase(protocolName + ' 解码 / ' + testCase.name, function () {
            var result = runQuietly(protocol, { mode: 'decode', payload: testCase.frame });
            assert.strictEqual(result.error, undefined, '解码不应返回 error');
            verifyExpected(result, testCase.expected);
            verifyStartsWith(result, testCase.startsWith);
            if (protocolName === '698') {
                assertSuccessful698Value(result.payload, protocolName + ' 解码 / ' + testCase.name);
            }
        });
    });
}

runFixture('698', proto698, fixtures698);
runFixture('645', proto645, fixtures645);

function snapshot698(message) {
    return {
        payload: message.payload,
        unified: message.decoding_details.unifiedFormat,
        frameInfo: message.decoding_details.frameInfo
    };
}

function signature698(unified) {
    var error = unified.error && unified.error.name ? unified.error.name : (unified.error || '');
    return [
        unified.type || '',
        unified.responseType == null ? '' : unified.responseType,
        unified.oad || unified.omd || '',
        unified.status || '',
        error
    ].join('|');
}

runCase('698 日志类型样本 / OAD、响应形态与解码期望值', function () {
    var actualSignatures = new Set();
    var actualOads = new Set();

    assert.ok(samples698.cases.length >= 32, '698 形态样本数低于已确认基线 32');
    assert.ok(samples698.oads.length >= 30, '698 OAD 数低于已确认基线 30');
    assert.strictEqual(samples698.caseCount, samples698.cases.length, '698 样本 caseCount 不一致');
    assert.strictEqual(samples698.signatureCount, samples698.signatures.length, '698 signatureCount 不一致');
    assert.strictEqual(samples698.oadCount, samples698.oads.length, '698 oadCount 不一致');

    samples698.cases.forEach(function (testCase, index) {
        var result = runQuietly(proto698, { mode: 'decode', payload: testCase.frame });
        var unified = result.decoding_details && result.decoding_details.unifiedFormat;
        var actualSignature = unified && signature698(unified);
        var actualOad = unified && (unified.oad || unified.omd || null);
        actualSignatures.add(actualSignature);
        if (actualOad) actualOads.add(actualOad);
        assert.strictEqual(actualSignature, testCase.signature, '698 样本 #' + index + ' 响应形态变化');
        assert.strictEqual(actualOad, testCase.oad, '698 样本 #' + index + ' OAD 变化');
        assert.deepStrictEqual(
            normalize(snapshot698(result)),
            testCase.expected,
            '698 样本 #' + index + ' 解码结果变化: ' + testCase.signature + ' / ' + testCase.sourceLog + ' / ' + testCase.label
        );
        assertSuccessful698Value(result.payload, '698 样本 #' + index + ' / ' + testCase.label);
    });

    assert.deepStrictEqual(Array.from(actualSignatures).sort(), samples698.signatures, '698 响应形态清单不一致');
    assert.deepStrictEqual(Array.from(actualOads).sort(), samples698.oads, '698 OAD 清单不一致');
    sample698Frames = samples698.cases.length;
});

runCase('645 日志类型样本 / DI 与解码期望值', function () {
    var actualTypes = new Set();
    var dailyForward = new Set();
    var dailyReverse = new Set();
    var monthlyForward = new Set();
    var monthlyReverse = new Set();

    assert.ok(samples645.cases.length >= 106, '645 类型样本数低于已确认基线 106');
    assert.ok(samples645.types.length >= 106, '645 响应类型数低于已确认基线 106');
    assert.strictEqual(samples645.caseCount, samples645.cases.length, '645 样本 caseCount 不一致');
    assert.strictEqual(samples645.typeCount, samples645.types.length, '645 样本 typeCount 不一致');

    samples645.cases.forEach(function (testCase, index) {
        var result = runQuietly(proto645, { mode: 'decode', payload: testCase.frame });
        var decoded = result.payload;
        var actualType = decoded && (decoded.di || decoded.type);
        actualTypes.add(actualType);
        if (/^050601/.test(actualType)) dailyForward.add(actualType);
        if (/^050602/.test(actualType)) dailyReverse.add(actualType);
        if (/^000100/.test(actualType)) monthlyForward.add(actualType);
        if (/^000200/.test(actualType)) monthlyReverse.add(actualType);
        assert.strictEqual(actualType, testCase.type, '样本 #' + index + ' 响应类型变化');
        var normalizedDecoded = normalize(decoded);
        // mode/raw 是输入回显与帧冗余，构建样本时已剔除，比对侧保持一致
        delete normalizedDecoded.mode;
        delete normalizedDecoded.raw;
        assert.deepStrictEqual(
            normalizedDecoded,
            testCase.expected,
            '样本 #' + index + ' 解码结果变化: ' + testCase.type + ' / ' + testCase.sourceLog + ' / ' + testCase.label
        );
        assert645SampleValue(decoded, '645 样本 #' + index + ' / ' + testCase.label);
    });

    assert.deepStrictEqual(Array.from(actualTypes).sort(), samples645.types, '645 响应类型清单不一致');
    assert.strictEqual(dailyForward.size, 30, '日冻结正向 DI 应覆盖 30 次');
    assert.strictEqual(dailyReverse.size, 30, '日冻结反向 DI 应覆盖 30 次');
    assert.strictEqual(monthlyForward.size, 12, '月冻结正向 DI 应覆盖 12 月');
    assert.strictEqual(monthlyReverse.size, 12, '月冻结反向 DI 应覆盖 12 月');
    sample645Frames = samples645.cases.length;
});

console.log('');
console.log('协议回归测试: ' + passed + ' 通过, ' + failed + ' 失败');
console.log('698 日志类型样本: ' + sample698Frames + ' 种形态');
console.log('645 日志类型样本: ' + sample645Frames + ' 种类型');

if (failed > 0) process.exitCode = 1;
