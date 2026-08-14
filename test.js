
var proto645 = require("./645");
var proto698 = require("./698");

let msg = {};
function isGarbledOriginal(val, opts = {}) {
    const { expect = "auto" } = opts;
    if (val === null || val === undefined) return false;

    let s = (typeof val === "string") ? val : String(val);
    s = s.trim();
    if (s === "") return false;

    // 1. 包含替换字符 (U+FFFD)
    if (/[]/.test(s)) return true;

    // 2. 包含非法控制字符
    if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(s)) return true;

    // 3. 协议全F为无效值/填充值，不属于通信乱码
    if (/^f+$/i.test(s.replace(/\s+/g, ""))) return false;

    // 4. 明确期望是数字 → 只有在这里才进行数字合法性校验
    if (expect === "number") {
        const normalized = s.replace(/,/g, "");
        if (!/^[-+]?\d+(\.\d+)?$/.test(normalized)) return true;
        return !Number.isFinite(Number(normalized));
    }

    // 5. 明确期望是14位日期时间
    if (expect === "datetime14") {
        if (!/^\d{14}$/.test(s)) return true;
        if (/^0{14}$/.test(s)) return false; // 全0表示无事件记录，不属于乱码
        const yyyy = +s.slice(0, 4), MM = +s.slice(4, 6), dd = +s.slice(6, 8);
        const HH = +s.slice(8, 10), mm = +s.slice(10, 12), ss = +s.slice(12, 14);
        if (yyyy < 2000 || yyyy > 2100) return true;
        if (MM < 1 || MM > 12) return true;
        if (dd < 1 || dd > 31) return true;
        if (HH < 0 || HH > 23) return true;
        if (mm < 0 || mm > 59) return true;
        if (ss < 0 || ss > 59) return true;
        return false;
    }

    // 6. 明确期望是645协议的12位日期时间：YYMMDDhhmmss
    if (expect === "datetime12") {
        if (!/^\d{12}$/.test(s)) return true;
        if (/^0{12}$/.test(s)) return false; // 全0表示无事件记录，不属于乱码
        const MM = +s.slice(2, 4), dd = +s.slice(4, 6);
        const HH = +s.slice(6, 8), mm = +s.slice(8, 10), ss = +s.slice(10, 12);
        if (MM < 1 || MM > 12) return true;
        if (dd < 1 || dd > 31) return true;
        if (HH < 0 || HH > 23) return true;
        if (mm < 0 || mm > 59) return true;
        if (ss < 0 || ss > 59) return true;
        return false;
    }

    // 7. 自动模式(auto)：作为普通字符串，只要不是上面那些乱码特征，就是合法的
    // 不再进行任何数字相关的误判拦截

    return false;
}




// console.log(JSON.stringify(proto698(msg)));
// console.log(proto698(msg));






// msg.payload=[
//     {
//         barcode:'1',
//         payload : '68 77 80 36 36 00 00 68 91 6E 34 34 63 36 59 4B 34 56 35 4A CC CC 33 33 77 34 33 33 33 33 33 33 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 EB 16',
//         proto : 645
//     }
// ]

// let nmsg = proto645(msg);
// let rawValue = nmsg.payload[0];
// console.log(rawValue);
// console.log(isGarbledOriginal(rawValue.eventTimeRaw, { expect: "datetime12" }));



// msg.payload=[
//     {
//         barcode:'1',
//         payload : '68 77 80 36 36 00 00 68 91 6E 34 34 63 36 59 4B 34 56 35 4A CC CC 33 33 77 34 33 33 33 33 33 33 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 EB 16',
//         proto : 645
//     }
// ]

// nmsg = proto645(msg);
// rawValue = nmsg.payload[0];
// console.log(rawValue);
// console.log(isGarbledOriginal(rawValue.eventTimeRaw, { expect: "datetime12" }));



msg.payload = [
    {
        barcode: '1',
        payload: '68 43 19 27 40 14 00 68 91 20 32 38 33 37 3F 33 33 33 33 B5 33 33 33 33 33 33 33 37 33 33 33 33 33 33 33 33 33 33 33 33 33 33 52 16',
        proto: 645
    }
]

nmsg = proto645(msg);
console.log(JSON.stringify(nmsg));
// rawValue = nmsg.payload[0];
// console.log(rawValue);
// console.log(isGarbledOriginal(rawValue.eventTimeRaw, { expect: "datetime12" }));

// msg.payload=[
//     {
//         barcode:'1',
//         payload : '68 45 00 C3 05 20 43 07 00 15 19 11 9D 08 90 00 2C 85 03 01 50 04 02 00 01 00 00 20 02 00 01 01 01 05 06 00 00 00 00 06 00 00 00 00 06 00 00 00 00 06 00 00 00 00 06 00 00 00 00 00 00 01 00 04 41 83 7F C3 FC 0E 16',
//         proto : 698
//     }
// ]

// console.log(JSON.stringify(proto698(msg)));

// msg.payload=[
//     {
//         barcode:'1',
//         payload : '68 45 00 C3 05 20 43 07 00 15 19 11 9D 08 90 00 2C 85 03 01 50 04 02 00 01 00 00 10 02 00 01 01 01 05 06 00 1D 41 AD 06 00 00 00 00 06 00 1A 00 8B 06 00 00 00 00 06 00 03 41 21 00 00 01 00 04 61 98 DF F4 E9 03 16',
//         proto : 698
//     }
// ]

// console.log(JSON.stringify(proto698(msg)));
// console.log(proto698(msg));
