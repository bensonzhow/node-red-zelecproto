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

runCase('645/698 事件电能 / formattedValue规则一致', function () {
    [
        [proto645, fixtures645, ['上一次电表清零记录', '上一次负荷开关误动作事件实际报文含动作后状态', '上一次电源异常事件', '上一次开盖明细']],
        [proto698, fixtures698, ['上一次电表清零事件', '上一次开表盖事件', '上一次计量芯片故障事件', '上一次负荷开关误动作事件']]
    ].forEach(function ([protocol, fixtures, names]) {
        names.forEach(function (name) {
            var testCase = fixtures.decodeCases.find(function (item) { return item.name === name; });
            assert.ok(testCase, name + ' 缺少回归帧');
            var payload = runQuietly(protocol, { mode: 'decode', payload: testCase.frame }).payload;
            var detail = payload.value;
            var energies = (detail.energies || []).concat(detail.associatedData || []);
            assert.ok(energies.length > 0, name + ' 缺少事件电能项');
            energies.forEach(function (energy) {
                if (energy.valid === false || !Number.isFinite(energy.value)) {
                    assert.strictEqual(
                        Object.prototype.hasOwnProperty.call(energy, 'formattedValue'),
                        false,
                        name + ' 无效电能项不应输出formattedValue'
                    );
                    return;
                }
                assert.strictEqual(
                    energy.formattedValue,
                    energy.value.toFixed(Math.abs(energy.scale)),
                    name + ' 电能格式化值不一致'
                );
            });
        });
    });
});

runCase('698 标准事件 / 返回的额外电能列不被过滤', function () {
    var apdu = '850301302B02000C002022020000201E020000202002000020240200003300020000F2052201000010220100002022010000108201000020820100005022010000602201010106000000001C07E909070C002B1C07E9090B060C11000002040A0552454C4159160016001600060001DF4B0600000000060001DF4B0600000000060000303906FFFFFFFF';
    var encoded = runQuietly(proto698, {
        mode: 'encode',
        payload: { sa: '123456789012', ctrl: 0xC3, apduHex: apdu, security: 'none' }
    });
    var detail = runQuietly(proto698, { mode: 'decode', payload: encoded.payload }).payload.value;
    var extraEnergy = detail.associatedData.find(function (item) { return item.rawOad === '00502201'; });
    var invalidEnergy = detail.associatedData.find(function (item) { return item.rawOad === '00602201'; });

    assert.strictEqual(detail.associatedData.length, 6, '额外电能列应进入associatedData');
    assert.ok(extraEnergy, '第一象限无功电能列不应被过滤');
    assert.strictEqual(extraEnergy.value, 123.45, '额外电能值不一致');
    assert.strictEqual(extraEnergy.formattedValue, '123.45', '额外电能格式化值不一致');
    assert.strictEqual(extraEnergy.unit, 'kvarh', '额外电能单位不一致');
    assert.strictEqual(invalidEnergy.value, null, '全F电能值应判为无效');
    assert.strictEqual(invalidEnergy.rawData, '06FFFFFFFF', '698无效电能应保留A-XDR原始值');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(invalidEnergy, 'formattedValue'), false, '无效电能不应输出formattedValue');
    assert.strictEqual(detail.startForwardActive, 1226.99, '旧顶层兼容字段不应变化');
});

runCase('645 标准事件 / 协议固定电能字段完整解析', function () {
    [
        ['上一次负荷开关误动作事件实际报文含动作后状态', 4],
        ['上一次电源异常事件', 2]
    ].forEach(function ([name, count]) {
        var testCase = fixtures645.decodeCases.find(function (item) { return item.name === name; });
        var detail = runQuietly(proto645, { mode: 'decode', payload: testCase.frame }).payload.value;
        assert.strictEqual(detail.associatedData.length, count, name + ' 电能字段数量不符合645固定结构');
    });
    var coverCase = fixtures645.decodeCases.find(function (item) { return item.name === '上一次开盖明细'; });
    var coverDetail = runQuietly(proto645, { mode: 'decode', payload: coverCase.frame }).payload.value;
    assert.strictEqual(coverDetail.energies.length, 12, '645开盖前后12项电能应全部解析');
});

runCase('645 040005FF / 标准状态字1～7', function () {
    var frame = 'FEFEFEFE68123456789012689112323833373433363538373A393C3B3E3D403F2216';
    var result = runQuietly(proto645, { mode: 'decode', payload: frame }).payload;

    assert.strictEqual(result.ok, true, '标准状态字数据块应解码成功');
    assert.strictEqual(result.di, '040005FF', 'DI 不一致');
    assert.strictEqual(result.value.word1.rawValue, 0x0001, '状态字1不一致');
    assert.strictEqual(result.value.word4.rawValue, 0x0607, '状态字4不一致');
    assert.strictEqual(result.value.word7.rawValue, 0x0C0D, '状态字7不一致');
    assert.strictEqual(result.value.word7.statusWordHex, '0C0D', '状态字7 HEX 不一致');
    assert.strictEqual(result.value.word7.binary, '0000110000001101', '状态字7二进制不一致');
    assert.strictEqual(result.value.words.length, 7, '状态字数组应包含7项');
    assert.strictEqual(result.value.words[6], result.value.word7, 'words与word7应引用同一结果');
    assert.strictEqual(result.value.word8, null, '标准数据块不应包含密钥状态字');
});

runCase('645 040005FF / 国网扩展密钥状态字8', function () {
    var frame = 'FEFEFEFE68123456789012689116323833373433363538373A393C3B3E3D403FAB8967450616';
    var result = runQuietly(proto645, { mode: 'decode', payload: frame }).payload;

    assert.strictEqual(result.ok, true, '扩展状态字数据块应解码成功');
    assert.strictEqual(result.value.word7.rawValue, 0x0C0D, '状态字7不一致');
    assert.strictEqual(result.value.word8.rawValue, 0x12345678, '密钥状态字不一致');
    assert.strictEqual(result.value.word8.hexValue, '12345678', '密钥状态字 HEX 不一致');
    assert.strictEqual(result.value.word8.keys['密钥更新密钥有效'], true, '密钥状态位不一致');
});

runCase('698 20140200 / 状态字1～7与645总读结构对齐', function () {
    var frame = '683700C3059195903200001122EA8501012014020001010704108000041040000410C000041020000410A000041060000410E00000004B1216';
    var result = runQuietly(proto698, { mode: 'decode', payload: frame }).payload;
    var result645 = runQuietly(proto645, {
        mode: 'decode',
        payload: 'FEFEFEFE68123456789012689112323833373433363538373A393C3B3E3D403F2216'
    }).payload;

    assert.strictEqual(result.success, true, '698状态字数组应解码成功');
    assert.strictEqual(result.dataType, '电表运行状态(数组)', '状态字数组数据类型不一致');
    assert.strictEqual(result.value.word1.rawValue, 1, '状态字1不一致');
    assert.strictEqual(result.value.word4.rawValue, 4, '状态字4不一致');
    assert.strictEqual(result.value.word7.rawValue, 7, '状态字7不一致');
    assert.strictEqual(result.value.word7.statusWordHex, '0007', '状态字7 HEX 不一致');
    assert.strictEqual(result.value.word7.binary, '0000000000000111', '状态字7二进制应与645一致');
    assert.strictEqual(result.value.words.length, 7, '状态字数组应包含7项');
    assert.strictEqual(result.value.words[6], result.value.word7, 'words与word7应引用同一结果');
    assert.deepStrictEqual(
        Object.keys(result.value.word7).sort(),
        Object.keys(result645.value.word7).sort(),
        '698与645的单个状态字字段应一致'
    );
});

runCase('698 20140207 / 单独读取状态字7', function () {
    var frame = '681D00C30591959032000011201F85010120140207010410E0000000DF2C16';
    var result = runQuietly(proto698, { mode: 'decode', payload: frame });

    assert.strictEqual(result.payload.success, true, '状态字7应解码成功');
    assert.strictEqual(result.payload.metadata.oad, '20140207', 'OAD 不一致');
    assert.strictEqual(result.payload.dataType, '电表运行状态字7（合相故障状态）', '数据类型不一致');
    assert.strictEqual(result.payload.value.rawValue, 7, '状态字7不一致');
    assert.strictEqual(result.decoding_details.unifiedFormat.objectInfo.oad, '20140207', '状态字7元数据缺失');
});

runCase('698 20140204～07 / 状态字数据类型映射完整', function () {
    [
        ['20140204', '电表运行状态字4（A相故障状态）'],
        ['20140205', '电表运行状态字5（B相故障状态）'],
        ['20140206', '电表运行状态字6（C相故障状态）'],
        ['20140207', '电表运行状态字7（合相故障状态）']
    ].forEach(function ([oad, dataType]) {
        var encoded = runQuietly(proto698, {
            mode: 'encode',
            payload: { sa: '123456789012', ctrl: 0xC3, apduHex: '850101' + oad + '010410E0000000', security: 'none' }
        });
        var result = runQuietly(proto698, { mode: 'decode', payload: encoded.payload }).payload;
        assert.strictEqual(result.success, true, oad + ' 应解码成功');
        assert.strictEqual(result.dataType, dataType, oad + ' 数据类型不一致');
    });
});

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
