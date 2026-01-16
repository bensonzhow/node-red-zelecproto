/**
 * 国网多芯物联表《蓝牙通信及脉冲检定说明手册(0224)》协议
 * 帧格式：Start(7E7E7E5A) + L(1B) + OAD(1B) + DATA(N) + CS(1B) + End(7EA5)
 * 其中 L = 6 + N（即 OAD+DATA+CS 共字节数 + 固定偏移；见示例长度规律）
 * CS = 从起始 7E 开始到 DATA 最后一字节为止的逐字节求和低 8 位
 * 参考：起止符、示例帧、命令/应答与数据域、波特率枚举、脉冲类型与模式等。
 */

const START = Buffer.from([0x7E, 0x7E, 0x7E, 0x5A]);
const END = Buffer.from([0x7E, 0xA5]);

// —— 命令码（请求）/ 应答命令码（高位加 0x80） ——
// 0x00 复位转换器；0x01 连接表；0x02 待测表进入检定/切换项；0x03 转换器进入/退出检定
// 0x04 设置485波特率；0x05 读管理单元版本；0x06 读蓝牙模块版本；0x07 检定预处理；0x08 查询预处理状态
const OAD = {
    RESET: 0x00,
    CONNECT_METER: 0x01,
    METER_TEST: 0x02,
    CONV_TEST: 0x03,
    SET_BAUD: 0x04,
    VER_MCU: 0x05,
    VER_BLE: 0x06,
    PREPARE: 0x07,
    PREPARE_Q: 0x08,
};

// 结果码（各应答常见约定：00成功/01失败或超时/02参数非法/03授权非法）
const RESULT = {
    OK: 0x00, FAIL_OR_TIMEOUT: 0x01, BAD_PARAM: 0x02, AUTH_FAIL: 0x03
};

// 脉冲类型（检定模式数据域里使用）
const PULSE = {
    SEC: 0x00, DEMAND: 0x01, TARIFF: 0x02, HARMO_P: 0x03, HARMO_R: 0x04, REACTIVE: 0x05, ACTIVE: 0x06, EXIT: 0xFF
};

// 检定通信模式：普通(0x00) / 脉冲跟随(0x01)
const MODE = { NORMAL: 0x00, FOLLOW: 0x01 };

// 485 波特率枚举
const BAUD = { "2400": 0x00, "4800": 0x01, "9600": 0x02, "19200": 0x03, "38400": 0x04, "57600": 0x05 };

// —— 工具函数 ——

// 计算 1 字节 CS（从第一个 0x7E 起，累加至 DATA 末尾；不含 CS 与帧尾）
function calcCS(bufNoEndNoCS) {
    let sum = 0;
    for (const b of bufNoEndNoCS) sum = (sum + b) & 0xFF;
    return sum;
}
// —— 新增：从 barCode 派生 6位显示地址（示例策略：请按你C#真实逻辑替换）——
function deriveAddrAscii6FromBarCode(barCode) {
    // 占位策略：优先使用 payload.addrAscii6；若无，就“示例”回退为 "654321"
    // 你可改成：取条码中的某段、或外部映射查询等
    return "654321";
}
// BCD 地址（字符串如 '112233445566'）→ 低字节在前的 6 字节（例：66 55 44 33 22 11）
function addrStrTo6LE(addr12) {
    if (!/^[0-9A-Fa-f]{12}$/.test(addr12)) throw new Error("通信地址应为12位HEX/BCD字符串");
    const be = Buffer.from(addr12, 'hex');        // BE: 11 22 33 44 55 66
    return Buffer.from([...be].reverse());        // LE: 66 55 44 33 22 11
}

// 构帧：START + L + OAD + DATA + CS + END
function buildFrame(oad, dataBuf = Buffer.alloc(0)) {
    const len = 6 + dataBuf.length;               // L=6+N（示例规律）
    const head = Buffer.concat([START, Buffer.from([len, oad]), dataBuf]);
    const cs = Buffer.from([calcCS(head)]);
    return Buffer.concat([head, cs, END]);
}

// 解析一帧；返回 {oad,isResp,len,data,cs,ok, result?}
function parseFrame(buf) {
    // 基本边界检查
    if (buf.length < 4 + 1 + 1 + 1 + 2) throw new Error("帧过短");
    if (!buf.slice(0, 4).equals(START)) throw new Error("起始符错误");
    if (!buf.slice(-2).equals(END)) throw new Error("结束符错误");
    const len = buf[4];
    const oad = buf[5];
    const dataEndExclusive = 4 /*start*/ + 1 /*L*/ + 1 /*OAD*/ + (len - 6); // DATA 末尾位置（不含）
    const data = buf.slice(6, 6 + (len - 6)); // N = len-6
    const cs = buf[6 + (len - 6)];            // CS 紧随 DATA
    const partForCS = buf.slice(0, 6 + (len - 6)); // 计算 CS 的区间（含 START/L/OAD/DATA，不含CS/END）
    const ok = (calcCS(partForCS) === cs);

    const isResp = (oad & 0x80) === 0x80;
    const oadReq = isResp ? (oad & 0x7F) : oad;

    const obj = { len, oad, isResp, oadReq, data, cs, ok };

    // 应答帧通用 result 提取（大多数应答第1字节是结果码）
    if (isResp && data.length >= 1) obj.result = data[0];

    return obj;
}


// 解析 C# 风格的 itemContent: "01|06|01|00|01|01|09D0"
// 规则：前6段为单字节HEX或十进制字符串 -> 1B；第7段为16bit数值的HEX字符串 -> 小端两字节
/**
 * 通用 itemContent 解析器（无需判断段数）
 *
 * 语法（对每一段）：
 *  - 纯HEX/DEC： "01"、"9"、"09D0"、"255"、"0x1A"
 *  - 可选长度：  "09D0:2"  表示用 2 字节编码该值
 *  - 可选端序：  "@le" / "@be"（默认规则见下）
 *
 * 默认规则：
 *  - HEX 长度 ≤2    → 1 字节
 *  - HEX 长度 ==4   → 2 字节，小端（LE）← 为兼容 0x02 的 09D0→D0 09
 *  - HEX 长度 >4 且为偶数 → 直接按字节对切分拼接（BE），若加 @le 则按字节对反转
 *  - 纯十进制       → 1 字节（或用 :N 指定长度，长度>1 时默认 LE，可用 @be 改为 BE）
 */
function buildDataFromItemContent(itemContent) {
    if (!itemContent) throw new Error("itemContent 为空");
    const parts = String(itemContent)
        .split('|')
        .map(s => s.trim())
        .filter(s => s.length > 0);

    const out = [];

    for (let i = 0; i < parts.length; i++) {
        let seg = parts[i];

        // 提取端序与长度标注（可选）
        let endian = null;      // null=按默认规则, 'le' | 'be'
        let sizeBytes = null;   // null=按默认规则, 否则固定字节数

        // 端序标注：@le / @be
        const endianMatch = seg.match(/@(le|be)$/i);
        if (endianMatch) {
            endian = endianMatch[1].toLowerCase();
            seg = seg.slice(0, seg.length - endianMatch[0].length);
        }

        // 固定长度标注：:N
        const lenMatch = seg.match(/:(\d+)$/);
        if (lenMatch) {
            sizeBytes = parseInt(lenMatch[1], 10);
            seg = seg.slice(0, seg.length - lenMatch[0].length);
            if (!(sizeBytes > 0)) throw new Error(`itemContent 段${i + 1} 长度无效: ${lenMatch[0]}`);
        }

        // 支持 0x 前缀；识别十进制
        let isDec = /^[0-9]+$/.test(seg);
        let hex = seg
            .replace(/^0x/i, '')
            .toUpperCase()
            .replace(/_/g, ''); // 容忍下划线分隔

        if (!/^[0-9A-F]+$/.test(hex)) {
            if (isDec) {
                // 十进制：转数值
                const val = parseInt(seg, 10);
                if (Number.isNaN(val) || val < 0) throw new Error(`itemContent 段${i + 1} 非法十进制: ${seg}`);
                if (sizeBytes == null) {
                    // 默认 1 字节
                    if (val > 0xFF) throw new Error(`itemContent 段${i + 1} 超过1字节范围，请用 :N 指定长度`);
                    out.push(val & 0xFF);
                } else {
                    // 按长度编码，默认 LE，可用 @be 指定大端
                    let v = val >>> 0;
                    const tmp = [];
                    for (let k = 0; k < sizeBytes; k++) {
                        tmp.push(v & 0xFF);
                        v >>>= 8;
                    }
                    if (endian === 'be') tmp.reverse();
                    out.push(...tmp);
                }
                continue;
            }
            throw new Error(`itemContent 段${i + 1} 非法：${parts[i]}`);
        }

        // HEX：若位数为奇数则左补0
        if (hex.length % 2 === 1) hex = '0' + hex;

        if (sizeBytes != null) {
            // 强制长度
            const buf = [];
            const val = BigInt('0x' + hex);
            // 按长度与端序编码
            if (endian === 'be') {
                // BE: 高位在前
                for (let k = sizeBytes - 1; k >= 0; k--) {
                    const byte = Number((val >> BigInt(8 * k)) & 0xFFn);
                    buf.push(byte);
                }
            } else {
                // 默认 LE
                for (let k = 0; k < sizeBytes; k++) {
                    const byte = Number((val >> BigInt(8 * k)) & 0xFFn);
                    buf.push(byte);
                }
            }
            out.push(...buf);
            continue;
        }

        // 未指定长度：按默认规则
        if (hex.length <= 2) {
            // 1B
            out.push(parseInt(hex, 16) & 0xFF);
        } else if (hex.length === 4) {
            // 2B，默认 LE（与 0x02 的 09D0 → D0 09 对齐）
            const v = parseInt(hex, 16);
            if (endian === 'be') {
                out.push((v >> 8) & 0xFF, v & 0xFF);
            } else {
                out.push(v & 0xFF, (v >> 8) & 0xFF);
            }
        } else {
            // 多字节偶数位 HEX：默认按 BE 逐字节拼接；若 @le 则按字节对反转
            const bytes = hex.match(/../g).map(h => parseInt(h, 16));
            if (endian === 'le') bytes.reverse();
            out.push(...bytes);
        }
    }

    return Buffer.from(out);
}

// 依据 meterNo 计算最后2字节： (2492 + meterNo*20) -> 16bit 小端
function tail2FromMeterNo(meterNo) {
    const n = (2492 + (meterNo | 0) * 20) & 0xFFFF;
    return Buffer.from([n & 0xFF, (n >>> 8) & 0xFF]); // LE: 低->高
}

// —— 编码器 ——
// 传入 msg.payload 形如：
// { action:'encode', oad:'connect', addr:'112233445566' }
// { action:'encode', oad:'conv_test', ch:1, pulse: 'SEC', power:4, mode:'FOLLOW' }
// { action:'encode', oad:'set_baud', baud: '38400' } 等
function encode(payload) {
    // const oad = (payload.action || payload.oad || '').toLowerCase();
    const which = (payload.oad || '').toLowerCase();

    switch (which) {
        case 'reset':
            // 0x00 复位转换器，请求无数据；应答 0x80 + 结果码
            return buildFrame(OAD.RESET);

        // 旧：6字节LE
        // 新：优先 barCode/addrAscii6 的 12字节格式；否则回退旧法
        case 'connect': {
            const ascii6 = payload.addrAscii6;
            const barCode = payload.barCode;

            if (ascii6 && barCode) {
                if (!/^[0-9A-Za-z]{6}$/.test(ascii6)) throw new Error("connect: addrAscii6 需为6位可显示字符");
                const head6 = addrStrTo6LE(barCode.substring(barCode.length - 13, barCode.length - 13 + 12));
                const tail6 = Buffer.from(ascii6, 'ascii'); // 6字节 ASCII，如 "654321"
                return buildFrame(OAD.CONNECT_METER, Buffer.concat([head6, tail6]));
            }

            // 兼容旧入参：addr=12位HEX（BCD），走 6字节LE
            if (payload.addr) {
                const addr6 = addrStrTo6LE(payload.addr);
                return buildFrame(OAD.CONNECT_METER, addr6);
            }

            throw new Error("connect: 请提供 barCode/addrAscii6 或 addr(12HEX)");
        }

        case 'meter_test': {
            // 优先 itemContent（与 C# 完全等价）
            if (payload.itemContent) {
                const data = buildDataFromItemContent(payload.itemContent);
                return buildFrame(OAD.METER_TEST, data);
            }
            // 次选：meterNo 按公式生成末尾2字节；其余 6 字节来自参数（默认给出与 C# 示例相同的字段值）
            if (payload.meterNo != null) {
                const slot = (payload.slot ?? 0x01) & 0xFF; // 01
                const pulse = (typeof payload.pulse === 'string')
                    ? ({ SEC: 0, DEMAND: 1, TARIFF: 2, HARMO_P: 3, HARMO_R: 4, REACTIVE: 5, ACTIVE: 6, EXIT: 0xFF }[payload.pulse] ?? 0x06)
                    : (payload.pulse ?? 0x06) & 0xFF; // 06 (ACTIVE)
                const power = (payload.power ?? 0x01) & 0xFF; // 01
                const mode = (typeof payload.mode === 'string')
                    ? ({ NORMAL: 0, FOLLOW: 1 }[payload.mode.toUpperCase()] ?? 0)
                    : (payload.mode ?? 0x00) & 0xFF; // 00
                const rfu1 = (payload.rfu1 ?? 0x01) & 0xFF; // 01
                const rfu2 = (payload.rfu2 ?? 0x01) & 0xFF; // 01
                const head6 = Buffer.from([slot, pulse, power, mode, rfu1, rfu2]);
                const tail2 = tail2FromMeterNo(payload.meterNo);
                return buildFrame(OAD.METER_TEST, Buffer.concat([head6, tail2]));
            }
            // 兜底：保持你之前的4字节实现以兼容老设备
            const PULSE = { SEC: 0, DEMAND: 1, TARIFF: 2, HARMO_P: 3, HARMO_R: 4, REACTIVE: 5, ACTIVE: 6, EXIT: 0xFF };
            const MODE = { NORMAL: 0, FOLLOW: 1 };
            const slot = payload.slot ?? 1;
            const pulse = typeof payload.pulse === 'string' ? PULSE[payload.pulse] : payload.pulse;
            const power = payload.power ?? 0;
            const mode = typeof payload.mode === 'string' ? MODE[payload.mode.toUpperCase()] : payload.mode;
            if (pulse == null || mode == null) throw new Error("meter_test: 需给出 pulse 与 mode");
            const data = Buffer.from([slot & 0xFF, pulse & 0xFF, power & 0xFF, mode & 0xFF]);
            return buildFrame(OAD.METER_TEST, data);
        }

        case 'conv_test': {
            if (payload.itemContent) {
                const data = buildDataFromItemContent(payload.itemContent);
                return buildFrame(OAD.CONV_TEST, data);
            }
            if (payload.meterNo != null) {
                const slot = (payload.slot ?? 0x01) & 0xFF;
                const pulse = (typeof payload.pulse === 'string')
                    ? ({ SEC: 0, DEMAND: 1, TARIFF: 2, HARMO_P: 3, HARMO_R: 4, REACTIVE: 5, ACTIVE: 6, EXIT: 0xFF }[payload.pulse] ?? 0x06)
                    : (payload.pulse ?? 0x06) & 0xFF;
                const power = (payload.power ?? 0x01) & 0xFF;
                const mode = (typeof payload.mode === 'string')
                    ? ({ NORMAL: 0, FOLLOW: 1 }[payload.mode.toUpperCase()] ?? 0)
                    : (payload.mode ?? 0x00) & 0xFF;
                const rfu1 = (payload.rfu1 ?? 0x01) & 0xFF;
                const rfu2 = (payload.rfu2 ?? 0x01) & 0xFF;
                const head6 = Buffer.from([slot, pulse, power, mode, rfu1, rfu2]);
                const tail2 = tail2FromMeterNo(payload.meterNo);
                return buildFrame(OAD.CONV_TEST, Buffer.concat([head6, tail2]));
            }
            const PULSE = { SEC: 0, DEMAND: 1, TARIFF: 2, HARMO_P: 3, HARMO_R: 4, REACTIVE: 5, ACTIVE: 6, EXIT: 0xFF };
            const MODE = { NORMAL: 0, FOLLOW: 1 };
            const slot = payload.slot ?? 1;
            const pulse = typeof payload.pulse === 'string' ? PULSE[payload.pulse] : payload.pulse;
            const power = payload.power ?? 0;
            const mode = typeof payload.mode === 'string' ? MODE[payload.mode.toUpperCase()] : payload.mode;
            if (pulse == null || mode == null) throw new Error("conv_test: 需给出 pulse 与 mode");
            const data = Buffer.from([slot & 0xFF, pulse & 0xFF, power & 0xFF, mode & 0xFF]);
            return buildFrame(OAD.CONV_TEST, data);
        }

        case 'set_baud': {
            // 0x04 设置RS485波特率：DATA=1B（枚举 00..05），上电/初始化默认9600
            const key = String(payload.baud || '').trim();
            const code = BAUD[key];
            if (code == null) throw new Error("set_baud: 波特率仅支持 2400/4800/9600/19200/38400/57600");
            return buildFrame(OAD.SET_BAUD, Buffer.from([code]));
        }

        case 'ver_mcu':
            // 0x05 读管理单元固件版本（应答 4字节：HW(2)+SW(2)，低字节在前）
            return buildFrame(OAD.VER_MCU);

        case 'ver_ble':
            // 0x06 读蓝牙模块固件版本（应答同上）
            return buildFrame(OAD.VER_BLE);

        case 'prepare':
            // 0x07 蓝牙检定预处理（说明：需随后轮询 0x08 获取最终状态）
            return buildFrame(OAD.PREPARE);

        case 'prepare_q':
            // 0x08 查询预处理状态（应答：00成功/01失败/02处理中）
            return buildFrame(OAD.PREPARE_Q);

        default:
            throw new Error("未知 oad：" + which);
    }
}

// —— 解码器 ——
// 输入：Buffer 或 HEX 字符串
function decode(input) {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input).replace(/\s+/g, ''), 'hex');
    const frame = parseFrame(buf);

    const info = {
        ok: frame.ok,
        len: frame.len,
        oadHex: '0x' + frame.oad.toString(16).padStart(2, '0'),
        isResp: frame.isResp,
        oadReq: frame.oadReq,
        dataHex: frame.data.toString('hex').toUpperCase(),
        csHex: '0x' + frame.cs.toString(16).padStart(2, '0'),
    };

    // 针对常见应答附加解析
    if (frame.isResp) {
        // 统一结果码
        info.result = frame.result;

        switch (frame.oadReq) {
            case OAD.RESET:
            case OAD.CONNECT_METER:
            case OAD.CONV_TEST:
            case OAD.SET_BAUD:
            case OAD.PREPARE:
                // 这些应答通常只有 1B 结果
                break;

            case OAD.VER_MCU:
            case OAD.VER_BLE:
                if (frame.data.length >= 4) {
                    const hw = frame.data.readUInt16LE(0); // Vx.y → x=高字节？文档示例如 V1.0 => 0x0100
                    const sw = frame.data.readUInt16LE(2);
                    info.hwVer = `V${(hw >> 8)}.${(hw & 0xFF)}`;
                    info.swVer = `V${(sw >> 8)}.${(sw & 0xFF)}`;
                }
                break;

            case OAD.PREPARE_Q:
                // 00成功/01失败/02处理中
                break;
        }
    } else {
        // 请求帧的常见数据解析
        switch (frame.oadReq) {
            case OAD.CONNECT_METER:
                if (frame.data.length === 12 &&
                    frame.data[0] === 0x99 && frame.data[1] === 0x04 && frame.data[2] === 0x00 &&
                    frame.data[3] === 0x00 && frame.data[4] === 0x50 && frame.data[5] === 0x01) {
                    // 新版 12 字节格式
                    const ascii6 = frame.data.slice(6, 12).toString('ascii');
                    info.addrAscii6 = ascii6; // 如 "654321"
                    info.connectFmt = "12B(BLE)";
                } else if (frame.data.length === 6) {
                    // 旧版 6 字节LE
                    const le = Buffer.from(frame.data);
                    const be = Buffer.from([...le].reverse());
                    info.addr = be.toString('hex').toUpperCase();
                    info.connectFmt = "6B(LE)";
                }
                break;
            case OAD.METER_TEST:
            case OAD.CONV_TEST:
                if (frame.data.length === 4) {
                    info.slot = frame.data[0];
                    info.pulse = frame.data[1];
                    info.power = frame.data[2];
                    info.mode = frame.data[3];
                }
                break;
            case OAD.SET_BAUD:
                info.baudCode = frame.data[0];
                break;
        }
    }

    return info;
}

// —— 主入口 ——
// 入参规范：
// 1) 编码：msg.payload = { action:'encode', oad:'connect', addr:'112233445566' }
//    返回 Buffer（也可改为 HEX 字符串）
// 2) 解码：msg.payload = <Buffer|HEX字符串>
// 主执行逻辑
function batchMsgBle(msg) {
    try {
        const pdata = msg.payload;
        if (msg.mode == 'encode') {

            if (Array.isArray(pdata)) {
                let out = pdata.map((pd) => {
                    pd.payload = encode(pd)
                    return pd
                })
                msg.payload = out;
            } else {
                pdata.payload = encode(pdata);
                msg.payload = pdata;
            }
        } else {
            if (Array.isArray(pdata)) {
                let out = pdata.map((pd) => {
                    return decode(pd)
                })
                msg.payload = out;
            } else {
                const out = decode(pdata);
                msg.payload = out;
            }
        }
        return msg;
    } catch (err) {
        // console.log(err.message, msg);
        msg.error = err.message;
        return msg;
    }
}

module.exports = batchMsgBle;
module.exports.batchMsgBle = batchMsgBle;