'use strict';

var assert = require('assert');

function loadNode(wrapper, dependency, implementation) {
    var dependencyPath = require.resolve('../' + dependency);
    var wrapperPath = require.resolve('../' + wrapper);
    var originalDependency = require.cache[dependencyPath];
    var originalWrapper = require.cache[wrapperPath];
    require.cache[dependencyPath] = { id: dependencyPath, filename: dependencyPath, loaded: true, exports: implementation };
    delete require.cache[wrapperPath];
    var register;
    var RED = {
        nodes: {
            createNode: function (node) {
                node.on = function (event, handler) {
                    if (event === 'input') {
                        node._input = handler;
                    }
                };
                node.error = function (error, msg) { node._error = [error, msg]; };
            },
            registerType: function (name, constructor) { register = constructor; }
        }
    };
    require(wrapperPath)(RED);
    require.cache[dependencyPath] = originalDependency;
    if (originalWrapper) {
        require.cache[wrapperPath] = originalWrapper;
    } else {
        delete require.cache[wrapperPath];
    }
    return register;
}

function run(name, test) {
    try {
        test();
        console.log('PASS ' + name);
    } catch (error) {
        console.error('FAIL ' + name + ': ' + error.message);
        process.exitCode = 1;
    }
}

run('zelecproto success sends and completes', function () {
    var nodeType = loadNode('zelecproto', '645', function (msg) { return msg; });
    var node = {};
    nodeType.call(node, {});
    var sent;
    var completed = false;
    node._input({ proto: '645' }, function (msg) { sent = msg; }, function () { completed = true; });
    assert.strictEqual(sent.proto, '645');
    assert.strictEqual(sent._proto, undefined);
    assert.strictEqual(completed, true);
    assert.strictEqual(node._error, undefined);
});

run('zelecproto failure reports error and cleans marker', function () {
    var failure = new Error('645 failure');
    var nodeType = loadNode('zelecproto', '645', function () { throw failure; });
    var node = {};
    nodeType.call(node, {});
    var sent = false;
    var completed;
    var msg = { proto: '645' };
    node._input(msg, function () { sent = true; }, function (error) { completed = error; });
    assert.strictEqual(sent, false);
    assert.strictEqual(completed, failure);
    assert.strictEqual(node._error[0], failure);
    assert.strictEqual(node._error[1], msg);
    assert.strictEqual(msg._proto, undefined);
});

run('zeleble success sends and completes', function () {
    var nodeType = loadNode('zeleble', 'ble', function (msg) { return msg; });
    var node = {};
    nodeType.call(node, {});
    var sent;
    var completed = false;
    node._input({ payload: 'ok' }, function (msg) { sent = msg; }, function () { completed = true; });
    assert.strictEqual(sent.payload, 'ok');
    assert.strictEqual(completed, true);
});

run('zeleble failure reports error and does not send', function () {
    var failure = new Error('BLE failure');
    var nodeType = loadNode('zeleble', 'ble', function () { throw failure; });
    var node = {};
    nodeType.call(node, {});
    var sent = false;
    var completed;
    var msg = { payload: 'bad' };
    node._input(msg, function () { sent = true; }, function (error) { completed = error; });
    assert.strictEqual(sent, false);
    assert.strictEqual(completed, failure);
    assert.strictEqual(node._error[0], failure);
    assert.strictEqual(node._error[1], msg);
});
