'use strict';

// 规范化为"可存入 JSON 夹具"的等价结构：
// - Buffer → { bufferHex }
// - 对象中值为 undefined 的键丢弃（与 JSON.stringify 一致，否则夹具往返后比对不对称）
// - 数组中 undefined 元素转 null（同 JSON 语义）
// - 解码时刻 timestamp 不属于协议报文内容，剔除
function normalize(value) {
    if (Buffer.isBuffer(value)) {
        return { bufferHex: value.toString('hex').toUpperCase() };
    }
    if (Array.isArray(value)) {
        return value.map(function (item) {
            return item === undefined ? null : normalize(item);
        });
    }
    if (value && typeof value === 'object') {
        return Object.keys(value).sort().reduce(function (result, key) {
            if (key === 'timestamp') return result;
            if (value[key] === undefined) return result;
            result[key] = normalize(value[key]);
            return result;
        }, {});
    }
    return value;
}

module.exports = {
    normalize: normalize
};
