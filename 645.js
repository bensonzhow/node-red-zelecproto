// 放在文件顶部，供全局复用
const __HEX__ = Array.from({ length: 256 }, (_, n) =>
    (n < 16 ? '0' : '') + n.toString(16).toUpperCase()
);




/******************** 编码：build645Frame（含读地址命令） ********************/
function build645Frame(i, reverseAddr, csMode) {
    const oad = (i.payload && i.payload.oad) ? i.payload.oad : i.oad;

    // —— 特殊：读通信地址命令（无 DATA）——
    if (oad === 'readAdress' || oad === 'readAddress') {
        return buildReadAddressFrame(i, reverseAddr, csMode);
    }

    const addrRaw = (i.com_exec_addr || i.addr || 'AAAAAAAAAAAA').toUpperCase().replace(/\s+/g, '');
    if (addrRaw.length !== 12) throw new Error('com_exec_addr 必须是 6 字节(12个HEX字符)');

    // 地址字节
    let addrBytes = hexToBytes(addrRaw);
    if (reverseAddr) addrBytes = addrBytes.slice().reverse();


    // 检查是否为加密报文
    if (i.payload && i.payload.isEncrypted) {
        return buildEncrypted645Frame(i, addrBytes, reverseAddr, csMode);
    }


    // OAD 加密：倒序 + 每字节 +0x33
    const cmdEx = encryptOAD(oad); // "xx xx xx xx"
    const dataBytes = hexToBytes(cmdEx.replace(/\s+/g, ''));

    // 帧体：68 A0..A5 68 C L DATA CS 16
    const C = 0x11;            // 读命令
    const L = 0x04;            // 数据长度
    const frameNoCS = [0x68, ...addrBytes, 0x68, C, L, ...dataBytes];
    const cs = calc645CSForBytes(frameNoCS, csMode);
    const csHex = cs.toString(16).toUpperCase().padStart(2, '0');

    // 为兼容你原用法：最终 HEX 串不含空格，前导 FE×4 + 帧体 + CS + 16
    const fullHex = (`FE FE FE FE ${bytesToHex(frameNoCS)} ${csHex} 16`).replace(/\s+/g, '');
    let _payload = i.payload || {}
    return Object.assign(i, _payload, {
        com_exec_addr: bytesToHex(addrBytes).replace(/\s+/g, ''), // 按当前编码顺序（倒序与否）给出
        cmdEx,                       // 加密后的 OAD（调试用）
        payload: fullHex             // 最终 645 帧（HEX 串，无空格）
    });
}

/**
 * 读取地址
 */
function buildReadAddressFrame(i, reverseAddr, csMode) {
    // 读地址命令：C=0x13, L=0x00, 无 DATA
    // 下行目的地址通常用广播地址 'AA AA AA AA AA AA'
    const addrRaw = 'AAAAAAAAAAAA';
    let addrBytes = hexToBytes(addrRaw);
    if (reverseAddr) addrBytes = addrBytes.slice().reverse();

    const C = 0x13;
    const L = 0x00;

    const frameNoCS = [0x68, ...addrBytes, 0x68, C, L];
    const cs = calc645CSForBytes(frameNoCS, csMode);
    const csHex = cs.toString(16).toUpperCase().padStart(2, '0');

    const fullHex = (`FE FE FE FE ${bytesToHex(frameNoCS)} ${csHex} 16`).replace(/\s+/g, '');
    let _payload = i.payload || {}
    return Object.assign(i, _payload, {
        com_exec_addr: bytesToHex(addrBytes).replace(/\s+/g, ''),
        payload: fullHex
    });
}
/**
 * 构建加密报文
 * {
        com_exec_addr: '398766010000',
        cs_mode: 'full',
        payload: {
            oad: '070000FF',
            des: '数据回抄',
            code: '03',
            tag: 'dataReadback',
            isEncrypted: true,
            operatorCode: '00000000',
            cipherText: '8071B9EAE918ACB0', // 密文
            randomNumber: '43E19E3BD45E172B', // 随机数
            diversifier: '6CBA993433333333',  // 分散因子
            controlCode: 0x03 // 添加控制码设置
        }
    }
 */
function buildEncrypted645Frame(i, addrBytes, reverseAddr, csMode) {
    const payload = i.payload;

    // 加密报文的数据域结构
    let dataBytes = [];
    const isControlFrame = !!(payload && payload.password);

    if (isControlFrame) {
        if (payload.password) {
            dataBytes.push(...encodeControlSegment(payload.password, { pad: 4 }));
        }
        if (payload.operatorCode) {
            dataBytes.push(...encodeControlSegment(payload.operatorCode, { pad: 4 }));
        }
        if (payload.cipherText) {
            dataBytes.push(...encodeControlSegment(payload.cipherText, {
                reverse: payload.cipherReverse !== false,
                apply33: payload.cipherNeeds33 !== false
            }));
        }
        if (payload.extraData) {
            dataBytes.push(...encodeControlSegment(payload.extraData, {
                reverse: payload.extraReverse !== false,
                apply33: payload.extraNeeds33 !== false
            }));
        }
    } else {
        if (!payload.oad) throw new Error('加密报文需要提供数据标识 oad');
        // 数据标识（OAD）
        const oadBytes = hexToBytes(encryptOAD(payload.oad).replace(/\s+/g, ''));
        dataBytes.push(...oadBytes);

        // 操作者代码（通常为 4 字节）
        if (payload.operatorCode) {
            const opCodeBytes = hexToBytes(payload.operatorCode);
            // 操作者代码也需要 +0x33 处理
            const encryptedOpCode = opCodeBytes.map(b => (b + 0x33) & 0xFF);
            dataBytes.push(...encryptedOpCode);
        }

        // 根据不同的加密类型处理数据
        if (payload.authData) {
            // 身份认证数据：密文 + 随机数 + 分散因子
            const authDataBytes = hexToBytes(payload.authData.replace(/\s+/g, ''));
            dataBytes.push(...authDataBytes);
        } else if (payload.cipherText) {
            // 密文数据

            const cipherHex = payload.cipherText.replace(/\s+/g, '');
            const reversedCipher = reverseHexBytes(cipherHex); // 反转字节序
            const cipherBytes = hexToBytes(reversedCipher).map(b => (b + 0x33) & 0xFF);
            dataBytes.push(...cipherBytes);
            // const cipherBytes = hexToBytes(payload.cipherText.replace(/\s+/g, ''));
            // dataBytes.push(...cipherBytes);
            // 随机数
            if (payload.randomNumber) {
                const randHex = payload.randomNumber.replace(/\s+/g, '');
                const reversedRand = reverseHexBytes(randHex);
                const randBytes = hexToBytes(reversedRand).map(b => (b + 0x33) & 0xFF);
                dataBytes.push(...randBytes);
            }

            // if (payload.randomNumber) {
            //     const randomBytes = hexToBytes(payload.randomNumber.replace(/\s+/g, ''));
            //     dataBytes.push(...randomBytes);
            // }

            // 分散因子
            if (payload.diversifier) {
                const divHex = payload.diversifier.replace(/\s+/g, '');
                const reversedDiv = reverseHexBytes(divHex);
                const divBytes = hexToBytes(reversedDiv).map(b => (b + 0x33) & 0xFF);
                dataBytes.push(...divBytes);
            }
            // if (payload.diversifier) {
            //     const divBytes = hexToBytes(payload.diversifier.replace(/\s+/g, ''));
            //     dataBytes.push(...divBytes);
            // }
        }
    }

    // 帧体：68 A0..A5 68 C L DATA CS 16
    const C = payload.controlCode || 0x11;  // 控制码，默认为读数据
    const L = dataBytes.length;             // 数据长度
    const frameNoCS = [0x68, ...addrBytes, 0x68, C, L, ...dataBytes];
    const cs = calc645CSForBytes(frameNoCS, csMode);
    const csHex = cs.toString(16).toUpperCase().padStart(2, '0');

    // 为兼容你原用法：最终 HEX 串不含空格，前导 FE×4 + 帧体 + CS + 16
    const fullHex = (`FE FE FE FE ${bytesToHex(frameNoCS)} ${csHex} 16`).replace(/\s+/g, '');
    let _payload = i.payload || {}
    return Object.assign(i, _payload, {
        com_exec_addr: bytesToHex(addrBytes).replace(/\s+/g, ''), // 按当前编码顺序（倒序与否）给出
        payload: fullHex             // 最终 645 帧（HEX 串，无空格）
    });
}
function encodeControlSegment(hexStr, { pad = undefined, reverse = true, apply33 = true } = {}) {
    if (!hexStr) return [];
    let clean = hexStr.replace(/\s+/g, '').toUpperCase();
    if (pad) clean = clean.padStart(pad * 2, '0');
    if (clean.length % 2 !== 0) throw new Error('控制段必须是偶数个HEX字符');
    const bytes = [];
    if (reverse) {
        for (let i = clean.length; i > 0; i -= 2) {
            bytes.push(parseInt(clean.slice(i - 2, i), 16));
        }
    } else {
        for (let i = 0; i < clean.length; i += 2) {
            bytes.push(parseInt(clean.slice(i, i + 2), 16));
        }
    }
    if (!apply33) return bytes;
    return bytes.map(b => (b + 0x33) & 0xFF);
}
// 辅助函数：反转 hex 字符串的字节序
function reverseHexBytes(hex) {
    const clean = hex.toUpperCase();
    if (clean.length % 2 !== 0) throw new Error('Invalid hex');
    const bytes = [];
    for (let i = clean.length - 2; i >= 0; i -= 2) {
        bytes.push(clean[i], clean[i + 1]);
    }
    return bytes.join('');
}

/******************** 解码：batchMsg（返回统一对象，含 exec_addr/di/value 等） ********************/
function decode645(_msg) {
    // 创建一个全新的对象，不依赖于传入的 _msg 对象
    const result = {};
    
    // 复制原始消息的非 payload 属性
    for (const key in _msg) {
        if (_msg.hasOwnProperty(key) && key !== 'payload') {
            result[key] = _msg[key];
        }
    }
    
    // ===== 工具 =====
    function calc645Checksum(u8) {
        let s = 0;
        for (let i = 0; i < u8.length; i++) s = (s + u8[i]) & 0xFF;
        return s;
    }
    function bcdAddr12FromLE(addr6) {
        // 帧内地址：小端字节序（低位在前） → 显示需倒序
        const rev = Array.from(addr6).reverse();
        return Buffer.from(rev).toString('hex').toUpperCase(); // 12位
    }
    function minus33(arr) { return arr.map(v => (v - 0x33) & 0xFF); }
    function bytesToIntBE(a) { return parseInt(Buffer.from(a).toString('hex')); }

    // ===== 取入参并清洗 =====
    // 允许传 {put:'...'} 或 {payload:'...'}，优先 put
    let put = ((_msg.payload && _msg.payload.put) || _msg.put || _msg.payload || '').toString();
    if (!put) return Object.assign(result, { ok: false, reason: 'empty' });

    // 去前导 FE…FE（最多4个），并去空格
    put = f_stripLeadingFE(put.replace(/\s+/g, '')).toUpperCase();

    const buf = hexStringToBuffer(put);
    if (!buf || buf.length < 12) return Object.assign(result, { ok: false, reason: 'too_short', raw: put });

    // ===== 基本结构：68 AA(6) 68 CTRL LEN DATA(n) CS 16 =====
    // 容错：定位到第一个 0x68
    let p0 = 0;
    while (p0 < buf.length && buf[p0] !== 0x68) p0++;
    if (p0 + 12 > buf.length) return Object.assign(result, { ok: false, reason: 'no_head68', raw: put });

    // 第二个 0x68 在地址后
    const p68_2 = p0 + 7;
    if (buf[p0] !== 0x68 || buf[p68_2] !== 0x68) return Object.assign(result, { ok: false, reason: 'bad_68_pair', raw: put });

    // 读出地址区（A0..A5）
    const addrBytes = buf.subarray(p0 + 1, p0 + 7);
    const exec_addr = bcdAddr12FromLE(addrBytes);          // 解析后 12 位
    const addr_bytes_hex = bytesToHex(addrBytes).replace(/\s+/g, '');          // 帧中原始顺序（小端）

    // CTRL / LEN / DATA / CS / 16
    const ctrl = buf[p68_2 + 1];
    const len = buf[p68_2 + 2];
    const pDataStart = p68_2 + 3;
    const pDataEnd = pDataStart + len; // 不包含
    const pCS = pDataEnd;
    const pEnd = pDataEnd + 1;

    if (len < 0 || pEnd >= buf.length) return Object.assign(result, { ok: false, reason: 'len_oob', exec_addr, raw: put });
    if (buf[pEnd] !== 0x16) return Object.assign(result, { ok: false, reason: 'no_end16', exec_addr, raw: put });

    // —— CS 双模校验：std（第二个68后）与 full（第一个68起）任一通过即可 ——
    const cs_frame = buf[pCS];
    const cs_std = calc645Checksum(buf.subarray(p68_2 + 1, pCS));
    const cs_full = calc645Checksum(buf.subarray(p0, pCS));
    const cs_ok = (cs_std === cs_frame) || (cs_full === cs_frame);
    if (!cs_ok) {
        return Object.assign(result, {
            success: false, reason: 'cs_fail',
            cs_frame: cs_frame.toString(16).toUpperCase().padStart(2, '0'),
            cs_std: cs_std.toString(16).toUpperCase().padStart(2, '0'),
            cs_full: cs_full.toString(16).toUpperCase().padStart(2, '0'),
            exec_addr, raw: put
        });
    }

    const dataRaw = Array.from(buf.subarray(pDataStart, pDataEnd));
    // ===== 控制确认/错误帧 =====
    if (len === 0 && ctrl === 0x9C) {
        return Object.assign(result, {
            ok: true,
            type: "control_ack",
            exec_addr,
            addr_bytes_hex,
            ctrl,
            len,
            description: "控制命令执行成功 (0x9C)",
            success: cs_ok,
            raw: put
        });
    }

    if (ctrl === 0xDC) {
        const detail = minus33(dataRaw);
        return Object.assign(result, {
            ok: true,
            type: "control_ack_ext",
            exec_addr,
            addr_bytes_hex,
            ctrl,
            len,
            statusBytes: bytesToHex(detail).replace(/\s+/g, ""),
            success: true,
            raw: put
        });
    }

    if (ctrl === 0xDA) {
        const detail = minus33(dataRaw);
        return Object.assign(result, {
            ok: false,
            type: "control_error",
            exec_addr,
            addr_bytes_hex,
            ctrl,
            len,
            reason: "unauthorized_or_password_error",
            detail: detail.length ? detail[0].toString(16).toUpperCase().padStart(2, "0") : null,
            data: bytesToHex(detail).replace(/\s+/g, ""),
            raw: put
        });
    }

    if (ctrl === 0xD1) {
        const errRaw = minus33(dataRaw);
        return Object.assign(result, {
            ok: false,
            type: "control_error",
            exec_addr,
            addr_bytes_hex,
            ctrl,
            len,
            reason: "control_rejected",
            detail: errRaw.length ? errRaw[0].toString(16).toUpperCase().padStart(2, "0") : null,
            data: bytesToHex(errRaw).replace(/\s+/g, ""),
            raw: put
        });
    }
    // ===== 读地址响应：CTRL=0x93 且 LEN=0x06 =====
    if (ctrl === 0x93 && len === 0x06) {
        const addrMinus33 = minus33(dataRaw);
        const addr_from_data = bcdAddr12FromLE(Uint8Array.from(addrMinus33));
        return Object.assign(result, {
            ok: true,
            type: 'address_response',
            exec_addr,                 // 帧头解析出的地址
            addr_from_data,            // DATA-0x33 解析出的地址
            same: addr_from_data === exec_addr,
            ctrl, len,
            addr_bytes_hex,
            success: cs_ok,
            raw: put
        });
    }

    // ===== 普通数据响应：DATA-0x33，首4字节(倒序)为 DI =====
    const arrPush = minus33(dataRaw);
    let di = '';
    if (arrPush.length >= 4) di = Buffer.from(arrPush.slice(0, 4).reverse()).toString('hex').toUpperCase();

    // 动态判定是否为 "日冻结/结算日冻结" 的 DI（不再限定 30 天，可到 62 等任意 1B 日号）
    function isDailyFreezeDI(di) {
        // 645 常见日冻结：050601dd（正向）、050602dd（反向）；dd 为 1B 日号（01~3E/3F/…，扩展都能兜住）
        return /^05060[12][0-9A-F]{2}$/i.test(di || '');
    }
    function isSettlementFreezeDI(di) {
        // 结算日冻结（部分表厂）：000100dd（正向）、000200dd（反向）
        return /^(000100|000200)[0-9A-F]{2}$/i.test(di || '');
    }


    //判定为组合电量
    function isTootalDI(di) {
        let arr = ['0000FF00', '0001FF00', '0002FF00']
        return arr.includes(di)
    }


    // —— 常用分支（保留你的原分支，增加越界保护）——
    function buildDays(prefix) {
        let a = [];
        for (let i = 0; i < 30; i++) a.push(`${prefix}${(i + 1).toString(16).toUpperCase().padStart(2, '0')}`);
        return a;
    }
    const arrDays = buildDays('050601'); // 日冻结正向
    const arrDaysFX = buildDays('050602'); // 日冻结反向
    const arrDaysZX = buildDays('000100'); // 结算正向总电能
    const arrDaysJSR = buildDays('000200'); // 结算反向总电能
    const arrPub = ['04000B01', '04000B02', '04000B03']; // A/B/C 相电流（瞬时）

    let value = '';
    try {
        // // —— 读数据"请求帧"：CTRL=0x11 且 LEN=0x04，仅含 DI，无数值 ——
        // if (ctrl === 0x11 && len === 0x04 && arrPush.length === 4) {
        //     return Object.assign(_msg, {
        //         ok: true,
        //         type: 'read_request',
        //         exec_addr,
        //         addr_bytes_hex,
        //         ctrl, len, di,
        //         success: cs_ok,
        //         raw: put,
        //         value: null
        //     });
        // }
        if (di === '03110000' && arrPush.length >= 3) {
            value = bytesToIntBE(arrPush.slice(-3).reverse());
        } else if (di == '04000401') {
            //通信地址解析
            value = Buffer.from(arrPush.slice(-6).reverse()).toString('hex').toUpperCase()
        } else if (di === '03370000' && arrPush.length >= 7) {
            // 电源异常事件总次数（3字节无符号数）
            value = bytesToIntBE(arrPush.slice(-3).reverse());
        } else if (di === '04000105' && arrPush.length >= 2) {
            value = bytesToIntBE(arrPush.slice(-2).reverse());
        } else if (di === '03300100' && arrPush.length >= 3) {
            value = bytesToIntBE(arrPush.slice(-3).reverse());
        } else if (di === '01013003' && arrPush.length >= 106) {
            value = Buffer.from(arrPush.slice(-106).reverse()).toString('hex').toUpperCase();
        } else if (['02020100', '02020200', '02020300'].includes(di) && arrPush.length >= 3) {
            value = bytesToIntBE(arrPush.slice(-3).reverse());
        } else if (['02010100', '02010200', '02010300'].includes(di) && arrPush.length >= 3) {
            value = bytesToIntBE(arrPush.slice(-3).reverse());
        } else if (di === '02030000' && arrPush.length >= 3) {
            //读瞬时功率
            // value = Math.round((bytesToIntBE(arrPush.slice(-3).reverse()) * 0.0001) *1e4)/1e4;
            value = bytesToIntBE(arrPush.slice(-3).reverse())
        } else if (di === '02060000' && arrPush.length >= 2) {
            value = bytesToIntBE(arrPush.slice(-2).reverse());
        } else if (di === '02030100' && arrPush.length >= 4) {
            value = bytesToIntBE(arrPush.slice(-4).reverse());
        }
        else if (di === '040005FF' && arrPush.length >= 6) {
            // 运行状态数据块：常见为 2+2+2+4 = 10字节（状态字1/2/3 + 密钥状态字）
            // 也有表只回部分：例如只回 1/2/3（6字节），或 1/2/3/8 之外还带厂商私有扩展。
            const data = arrPush.slice(4); // 去掉DI
            const statusBlockHex = Buffer.from(data).toString("hex").toUpperCase();
            let off = 0;
            const left = () => data.length - off;
            const readU16LE = () => {
                if (left() < 2) return null;
                const lo = data[off] & 0xFF, hi = data[off + 1] & 0xFF;
                off += 2;
                return (hi << 8) | lo;
            };
            const readU32LE = () => {
                if (left() < 4) return null;
                const b0 = data[off] & 0xFF,
                    b1 = data[off + 1] & 0xFF,
                    b2 = data[off + 2] & 0xFF,
                    b3 = data[off + 3] & 0xFF;
                off += 4;
                return (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) >>> 0; // 无符号
            };
            const bin16 = (v) => (v >>> 0).toString(2).padStart(16, '0');
            const bin32 = (v) => (v >>> 0).toString(2).padStart(32, '0');
            const bit = (v, n) => ((v >>> n) & 1);

            // —— 状态字1（与你现有的 04000501 保持一致）——
            const w1 = readU16LE();
            const word1 = (w1 === null) ? null : {
                rawValue: w1,
                rawBlockHex: statusBlockHex,
                binary: bin16(w1),
                keys: {
                    '停电抄表电池欠压': !!bit(w1, 3),
                    '时钟电池欠压': !!bit(w1, 2),
                    '有功功率方向反向': !!bit(w1, 4),
                    '无功功率方向反向': !!bit(w1, 5),
                    '控制回路错误': !!bit(w1, 8),
                    'ESAM错误': !!bit(w1, 9),
                    '内部程序错误': !!bit(w1, 12),
                    '存储器故障或损坏': !!bit(w1, 13),
                    '透支状态': !!bit(w1, 14),
                    '时钟故障': !!bit(w1, 15)
                }
            };

            // —— 状态字2（与你现有的 04000502 保持一致）——
            const w2 = readU16LE();
            const dir = (b) => (b ? '反向' : '正向');
            const word2 = (w2 === null) ? null : {
                rawValue: w2,
                binary: bin16(w2),
                fields: {
                    'A相有功功率方向': dir(bit(w2, 0)),
                    'B相有功功率方向': dir(bit(w2, 1)),
                    'C相有功功率方向': dir(bit(w2, 2)),
                    'A相无功功率方向': dir(bit(w2, 4)),
                    'B相无功功率方向': dir(bit(w2, 5)),
                    'C相无功功率方向': dir(bit(w2, 6))
                }
            };

            // —— 状态字3（与你现有的 04000503 保持一致）——
            const w3 = readU16LE();
            const supplyBits = (w3 === null) ? 0 : ((w3 >> 1) & 0b11);
            const supplyMode = (
                supplyBits === 0 ? '主电源' :
                    supplyBits === 1 ? '辅助电源' :
                        supplyBits === 2 ? '电池供电' : '保留'
            );
            const meterTypeBits = (w3 === null) ? 0 : ((w3 >> 8) & 0b11);
            const meterType = (
                meterTypeBits === 0 ? '非预付费表' :
                    meterTypeBits === 1 ? '电量型预付费表' :
                        meterTypeBits === 2 ? '电费型预付费表' : '保留'
            );
            const word3 = (w3 === null) ? null : {
                rawValue: w3,
                binary: bin16(w3),
                fields: {
                    当前运行时段套数: (bit(w3, 0) ? '第二套' : '第一套'),
                    供电方式: supplyMode,
                    编程允许状态: (bit(w3, 3) ? '有效' : '失效'),
                    继电器状态: (bit(w3, 4) ? '断' : '通'),
                    当前运行时区套数: (bit(w3, 5) ? '第二套' : '第一套'),
                    继电器命令状态: (bit(w3, 6) ? '断' : '通'),
                    预跳闸报警状态: (bit(w3, 7) ? '有' : '无'),
                    电能表类型: meterType,
                    当前运行分时费率套数: (bit(w3, 10) ? '第二套' : '第一套'),
                    当前阶梯套数: (bit(w3, 11) ? '第二套' : '第一套'),
                    保电状态: (bit(w3, 12) ? '保电' : '非保电')
                }
            };

            // —— 密钥状态字（与你现有的 04000508 保持一致，32位）——
            const w8 = readU32LE();
            const word8 = (w8 === null) ? null : {
                rawValue: w8,
                hexValue: w8.toString(16).toUpperCase().padStart(8, '0'),
                binary: bin32(w8),
                keys: {
                    '主控密钥有效': !!bit(w8, 0),
                    '身份认证密钥有效': !!bit(w8, 1),
                    '密钥协商密钥有效': !!bit(w8, 2),
                    '密钥更新密钥有效': !!bit(w8, 3),
                    '传输密钥有效': !!bit(w8, 4),
                    '保护密钥有效': !!bit(w8, 5),
                    '广播认证密钥有效': !!bit(w8, 6),
                    '主控密钥不可恢复': !!bit(w8, 7)
                }
            };

            const out = { word1, word2, word3, word8 };
            if (left() > 0) {
                out.extraRaw = bytesToHex(data.slice(off)).replace(/\s+/g, ''); // 厂商私有扩展原样保留
            }
            value = out;
        }

        else if (di === '04000501' && arrPush.length >= 6) {
            // arrPush = DATA-0x33 后的数组
            const lo = arrPush[4] & 0xFF;     // 低字节
            const hi = arrPush[5] & 0xFF;     // 高字节
            const v = (hi << 8) | lo;        // 16 位状态字，bit0 为最低位
            const bin = v.toString(2).padStart(16, '0');

            value = {
                rawValue: v, binary: bin,
                keys: {
                    '停电抄表电池欠压': !!(v & (1 << 3)),    // bit3: 0=正常, 1=欠压
                    '时钟电池欠压': !!(v & (1 << 2)),        // bit2: 0=正常, 1=欠压
                    '有功功率方向反向': !!(v & (1 << 4)),    // bit4: 0=正向, 1=反向
                    '无功功率方向反向': !!(v & (1 << 5)),    // bit5: 0=正向, 1=反向
                    '控制回路错误': !!(v & (1 << 8)),        // bit8: 0=正常, 1=错误
                    'ESAM错误': !!(v & (1 << 9)),           // bit9: 0=正常, 1=错误
                    '内部程序错误': !!(v & (1 << 12)),       // bit12: 0=正常, 1=错误
                    '存储器故障或损坏': !!(v & (1 << 13)),   // bit13: 0=正常, 1=故障
                    '透支状态': !!(v & (1 << 14)),          // bit14: 0=正常, 1=透支
                    '时钟故障': !!(v & (1 << 15))           // bit15: 0=正常, 1=故障
                }
            };
        } else if (di === '04000502' && arrPush.length >= 6) {
            // 运行状态字2（方向类）：A/B/C 相有功与无功功率方向（0=正向，1=反向）
            const lo = arrPush[4] & 0xFF;
            const hi = arrPush[5] & 0xFF;
            const v = (hi << 8) | lo;
            const bin = v.toString(2).padStart(16, '0');

            const bit = (n) => ((v >> n) & 0x1);
            const dir = (b) => (b ? '反向' : '正向');

            value = {
                rawValue: v,
                binary: bin,
                fields: {
                    'A相有功功率方向': dir(bit(0)),
                    'B相有功功率方向': dir(bit(1)),
                    'C相有功功率方向': dir(bit(2)),
                    'A相无功功率方向': dir(bit(4)),
                    'B相无功功率方向': dir(bit(5)),
                    'C相无功功率方向': dir(bit(6))
                }
            };
        } else if (di === '04000503' && arrPush.length >= 6) {
            // 运行状态字3（操作类）
            const lo = arrPush[4] & 0xFF;
            const hi = arrPush[5] & 0xFF;
            const v = (hi << 8) | lo;
            const bin = v.toString(2).padStart(16, '0');

            const supplyBits = (v >> 1) & 0b11; // bit2-bit1
            const supplyMode = (
                supplyBits === 0 ? '主电源' :
                    supplyBits === 1 ? '辅助电源' :
                        supplyBits === 2 ? '电池供电' : '保留'
            );

            const meterTypeBits = (v >> 8) & 0b11; // bit9-bit8
            const meterType = (
                meterTypeBits === 0 ? '非预付费表' :
                    meterTypeBits === 1 ? '电量型预付费表' :
                        meterTypeBits === 2 ? '电费型预付费表' : '保留'
            );

            value = {
                rawValue: v,
                binary: bin,
                fields: {
                    当前运行时段套数: (v & 0x1) ? '第二套' : '第一套',               // bit0
                    供电方式: supplyMode,                                          // bit2-bit1
                    编程允许状态: (v & (1 << 3)) ? '有效' : '失效',                   // bit3
                    继电器状态: (v & (1 << 4)) ? '断' : '通',                        // bit4（线路实际工作状态）
                    当前运行时区套数: (v & (1 << 5)) ? '第二套' : '第一套',           // bit5
                    继电器命令状态: (v & (1 << 6)) ? '断' : '通',                    // bit6（远程拉闸命令）
                    预跳闸报警状态: (v & (1 << 7)) ? '有' : '无',                    // bit7
                    电能表类型: meterType,                                          // bit9-bit8
                    当前运行分时费率套数: (v & (1 << 10)) ? '第二套' : '第一套',      // bit10
                    当前阶梯套数: (v & (1 << 11)) ? '第二套' : '第一套',              // bit11
                    保电状态: (v & (1 << 12)) ? '保电' : '非保电'                    // bit12
                }
            };
        }
        // else if (['0000FF00', '0001FF00', '0002FF00'].includes(di) && arrPush.length > 4) {
        //     const data = arrPush.slice(4); const result = [];
        //     for (let i = 0; i < data.length; i += 4) { result.push(bytesToIntBE(data.slice(i, i + 4).reverse())); }
        //     value = result;
        // }
        else if (di === '04000508' && arrPush.length >= 4) {
            const b4 = Buffer.from(arrPush.slice(-4).reverse());
            const v = b4.readUInt32BE(0);
            value = {
                rawValue: v,
                hexValue: v.toString(16).toUpperCase().padStart(8, '0'),
                binary: v.toString(2).padStart(32, '0'),
                keys: {
                    '主控密钥有效': !!(v & (1 << 0)), '身份认证密钥有效': !!(v & (1 << 1)), '密钥协商密钥有效': !!(v & (1 << 2)),
                    '密钥更新密钥有效': !!(v & (1 << 3)), '传输密钥有效': !!(v & (1 << 4)), '保护密钥有效': !!(v & (1 << 5)),
                    '广播认证密钥有效': !!(v & (1 << 6)), '主控密钥不可恢复': !!(v & (1 << 7))
                }
            };
        } else if (di === '04000102' && arrPush.length >= 3) {
            value = Buffer.from(arrPush.slice(-3).reverse()).toString('hex').toUpperCase(); // "HHMMSS"
        } else if (di === '04000101' && arrPush.length >= 8) {
            const s = '20' + Buffer.from(arrPush.slice(4).reverse()).toString('hex').toUpperCase();
            value = s.slice(0, 8);
        } else if (di === '03300101' && arrPush.length >= 10) {
            value = '20' + Buffer.from(arrPush.slice(4, 10).reverse()).toString('hex').toUpperCase();
        } else if (di === '03300D00' && arrPush.length >= 4) {
            value = bytesToIntBE(arrPush.slice(4).reverse());
        }
        else if ((isDailyFreezeDI(di) || isSettlementFreezeDI(di) || isTootalDI(di)) && arrPush.length >= 8) {
            // else if ((arrDays.includes(di) || arrDaysFX.includes(di) || arrDaysZX.includes(di) || arrDaysJSR.includes(di)) && arrPush.length >= 8) {
            // const energyNum = bytesToIntBE(arrPush.slice(4, 8).reverse());
            // value = Math.round(energyNum / 100 * 100) / 100;
            // DATA-0x33 后：DI(4) + 5×(4B 小端 BCD) = 24B LEN → 与 698 的日冻结 record 风格一致
            // DATA-0x33 后:  DI(4) + N×(4B 小端BCD)；常见为 5 组（总/尖/峰/平/谷），也有只回 1 组"总"的情况
            const afterDI = arrPush.slice(4);
            const labels = ['总', '尖', '峰', '平', '谷'];


            // 0000FF00 / 0001FF00 / 0002FF00：乱码模式
            const isTotalBlock = isTootalDI(di);

            // 4B 小端 BCD → 十进制（2 小数位，单位 kWh）
            function parseEnergyLE4(b4) {

                // const val = bcdLEToInt(b4);     // 例如 "00 63 24 02"（LE BCD）→ 解析为整数，再 /100
                // return Math.round((val / 100) * 100) / 100;
                //--fixed 
                if (isTotalBlock) {
                    // 乱码模式：4 字节先按大端转 hex 字符串，再插入小数点
                    const beBytes = Array.from(b4).reverse(); // 小端 => 大端
                    let hexStr = bytesToHex(beBytes).replace(/\s+/g, '').toLowerCase(); // 8 位 hex
                    hexStr = hexStr.padStart(8, '0');          // 防守一下
                    return hexStr.slice(0, 6) + '.' + hexStr.slice(6);   // "142942.59"
                } else {
                    // 原来日冻结/结算日逻辑：小端 BCD → 十进制，保留 2 位小数
                    const val = bcdLEToInt(b4);
                    return Math.round((val / 100) * 100) / 100;
                }
            }

            const totalGroups = Math.floor(afterDI.length / 4);       // 能解析的 4B 组数
            const parseCount = Math.min(5, Math.max(1, totalGroups)); // 至少解析 1 组，最多 5 组
            const items = [];

            for (let i = 0; i < parseCount; i++) {
                const seg = afterDI.slice(i * 4, i * 4 + 4);
                items.push({
                    label: labels[i] || `项${i + 1}`,
                    rawBCD: bytesToHex(seg),
                    value: parseEnergyLE4(seg),
                    unit: 'kWh',
                    scale: -2
                });
            }

            // 如设备回了超过 5 组（极少见）或多余字节，挂个 extra 方便排查，不影响主结果
            const extraStart = parseCount * 4;
            if (afterDI.length > extraStart) {
                result.extraRaw = bytesToHex(afterDI.slice(extraStart)).replace(/\s+/g, '');
            }

            value = items.map(it => it.value);          // 与你 698 解析保持一致：value 返回纯数值数组
            result.payload = { data: items, value };             // 附带明细（含 rawBCD）
        } else if (di === '04000402' && arrPush.length >= 8) {
            value = Buffer.from(arrPush.slice(4).reverse()).toString('hex').toUpperCase();
        } else if (arrPub.includes(di) && arrPush.length >= 8) {
            const v = bytesToIntBE(arrPush.slice(4, 8).reverse());
            value = Math.round(v / 100 * 100) / 100;
        } else if (di === '070000FF' && arrPush.length >= 16) {
            // 身份认证（数据标识 070000FF）：随机数2(4B) + ESAM序列号(8B) + 可能的附加字段
            const dataBytes = arrPush.slice(4);
            const asBigEndianHex = (segment) => {
                if (!segment || segment.length === 0) return '';
                return Buffer.from(segment.slice().reverse()).toString('hex').toUpperCase();
            };
            const random2Bytes = dataBytes.slice(0, 4);
            const esamBytes = dataBytes.slice(4, 12);
            const extraBytes = dataBytes.slice(12);
            value = {
                type: 'identity_auth',
                random2: asBigEndianHex(random2Bytes),   // 与 C# 相同：按大端显示
                esam: asBigEndianHex(esamBytes),
                extraData: extraBytes.length ? Buffer.from(extraBytes).toString('hex').toUpperCase() : null,
                rawMinus33: bytesToHex(arrPush).replace(/\s+/g, '')
            };
        } else if (di === '04000409' && arrPush.length >= 7) {
            // 有功脉冲常数：DI(4) + N3(3字节BCD，小端)
            const dataBytes = arrPush.slice(4, 7); // LE：低字节在前
            const val = bcdLEToInt(dataBytes);
            value = {
                rawValue: val,
                unit: 'imp/kWh',
                description: `有功脉冲常数: ${val} imp/kWh`,
                bcdData: bcdDigitsStrLE(dataBytes) // 例如 "000400" → "400"
            };
        } else if ((di === '02800008' || di === '02800009') && arrPush.length >= 6) {
            // 02800008: 时钟电池电压，02800009: 停电抄表电池电压
            // C# 解析为2字节，保留2位小数 → V
            const n = bytesToIntBE(arrPush.slice(-2).reverse());
            const v = n / 100.0;
            value = {
                rawValue: n,
                voltage: v,
                unit: 'V',
                description: `${di === '02800008' ? '时钟电池电压' : '停电抄表电池电压'}: ${v.toFixed(2)}V`
            };
        } else if (di === '0400040A' && arrPush.length >= 7) {
            // 无功脉冲常数：DI(4) + N3(3字节BCD，小端)
            const dataBytes = arrPush.slice(4, 7); // LE：低字节在前
            const val = bcdLEToInt(dataBytes);
            value = {
                rawValue: val,
                unit: 'imp/kvarh',
                description: `无功脉冲常数: ${val} imp/kvarh`,
                bcdData: bcdDigitsStrLE(dataBytes)
            };
        } else if (di === '03300D01' && arrPush.length >= 16) {
            value = parseCoverOpenLast645(arrPush);
        } else {
            // 未匹配的DI，返回去偏移(−0x33)后的原始数据，便于排查/厂商私有解析
            value = {
                rawMinus33: bytesToHex(arrPush).replace(/\s+/g, ''),           // 含DI(4B) + 数据
                di,
                data: bytesToHex(arrPush.slice(4)).replace(/\s+/g, ''),        // 纯数据部分（不含DI）
                note: '未识别DI，已返回去0x33的原始数据'
            };
        }
    } catch (e) {
        return Object.assign(result, { ok: false, reason: 'decode_exception', exec_addr, di, ctrl, len, raw: put, err: String(e) });
    }

    return Object.assign(result, {
        ok: true,
        type: 'data_response',
        exec_addr,
        addr_bytes_hex,
        ctrl, len, di, value,
        success: cs_ok,
        raw: put
    });
}

/******************** 通用工具 ********************/
function calc645CSForBytes(frameNoCS, csMode) {
    // frameNoCS = [68, A0..A5, 68, C, L, ...DATA]
    if (csMode === 'full') {
        // 从第一个 0x68 起（含）一直累加到 CS 前
        return calc645Checksum(frameNoCS);
    }
    // 'std'：从第二个 0x68 后开始（C+L+DATA）
    let second68 = -1, seen = 0;
    for (let i = 0; i < frameNoCS.length; i++) {
        if (frameNoCS[i] === 0x68) { seen++; if (seen === 2) { second68 = i; break; } }
    }
    const part = frameNoCS.slice(second68 + 1);
    return calc645Checksum(part);

    function calc645Checksum(arr) {
        let sum = 0;
        for (let i = 0; i < arr.length; i++) sum = (sum + arr[i]) & 0xFF;
        return sum & 0xFF;
    }
}

function encryptOAD(oadStr) {
    const clean = oadStr.replace(/\s+/g, '').toUpperCase();
    if (clean.length !== 8) throw new Error("数据标识必须是4字节（8个十六进制字符）");
    let bytes = [];
    for (let i = 0; i < 8; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
    const entagd = bytes.reverse().map(b => (b + 0x33) & 0xFF);
    return entagd.map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
}

function decryptOAD(entagdStr) {
    const clean = entagdStr.replace(/\s+/g, '').toUpperCase();
    if (clean.length !== 8) throw new Error("加密标识必须是4字节（8个十六进制字符）");
    let bytes = [];
    for (let i = 0; i < 8; i += 2) bytes.push(parseInt(clean.slice(i, i + 2), 16));
    const detagd = bytes.map(b => (b - 0x33 + 256) & 0xFF).reverse();
    return detagd.map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
}

function hexToBytes(hexStr) {
    const clean = hexStr.replace(/\s+/g, '').toUpperCase();
    if (!clean || clean.length % 2 !== 0) throw new Error('HEX 长度必须为偶数');
    const out = [];
    for (let i = 0; i < clean.length; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));
    return out;
}
// function bytesToHex(bytes) {
//     return bytes.map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ');
// }

function bytesToHex(bytes) {
    const a = Array.isArray(bytes) ? bytes : Array.from(bytes || []);
    let out = '';
    for (let i = 0; i < a.length; i++) {
        const v = (a[i] | 0) & 0xFF;   // 强制为 0..255
        out += __HEX__[v];             // 查表确保两位HEX
        if (i !== a.length - 1) out += ' ';
    }
    return out;
}
function hexStringToBuffer(hexStr) {
    const clean = hexStr.replace(/\s+/g, '');
    if (!clean || clean.length % 2 !== 0) return null;
    return Buffer.from(clean, 'hex');
}
// 只剔除前导 FE…FE（最多4个）
function f_stripLeadingFE(hex) {
    const s = hex.replace(/\s+/g, '').toUpperCase();
    return s.replace(/^(FE){1,4}/, '');
}

// 【新增】BCD(小端) → 整数：bytes[0] 是最低两位(个/十)，bytes[1] 是百/千 ...
function bcdLEToInt(bytes) {
    let m = 1, val = 0;
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i] & 0xFF;
        const lo = b & 0x0F;         // 个
        const hi = (b >> 4) & 0x0F;  // 十
        if (lo > 9 || hi > 9) throw new Error('BCD 半字节越界');
        val += lo * m; m *= 10;
        val += hi * m; m *= 10;
    }
    return val;
}
// 【新增】把 BCD(小端) 转成"正常阅读顺序"的数字字符串（去前导 0）
function bcdDigitsStrLE(bytes) {
    let s = '';
    for (let i = bytes.length - 1; i >= 0; i--) {
        const b = bytes[i] & 0xFF;
        s += ((b >> 4) & 0x0F).toString();
        s += (b & 0x0F).toString();
    }
    s = s.replace(/^0+/, '') || '0';
    return s;
}


// === 开盖明细专用工具 ===

// 单字节 BCD → 十进制（0x25 -> 25）
function bcdByteToDec(b) {
    const hi = (b >> 4) & 0x0F, lo = b & 0x0F;
    if (hi > 9 || lo > 9) return NaN;
    return hi * 10 + lo;
}

// 解析 6B/7B BCD 时间（顺序：秒 分 时 日 月 年 [周]），返回 {formatted,...}
function parseTimeBCD6or7(bytes) {
    if (!(bytes && (bytes.length === 6 || bytes.length === 7))) return null;
    const ss = bcdByteToDec(bytes[0]);
    const mm = bcdByteToDec(bytes[1]);
    const hh = bcdByteToDec(bytes[2]);
    const DD = bcdByteToDec(bytes[3]);
    const MM = bcdByteToDec(bytes[4]);
    const YY = bcdByteToDec(bytes[5]);
    if ([ss, mm, hh, DD, MM, YY].some(v => isNaN(v))) return null;
    if (ss > 59 || mm > 59 || hh > 23 || DD < 1 || DD > 31 || MM < 1 || MM > 12) return null;
    const YYYY = 2000 + YY;
    const pad = n => String(n).padStart(2, '0');
    return {
        year: YYYY, month: pad(MM), day: pad(DD),
        hour: pad(hh), minute: pad(mm), second: pad(ss),
        formatted: `${YYYY}-${pad(MM)}-${pad(DD)} ${pad(hh)}:${pad(mm)}:${pad(ss)}`
    };
}

// 解析“上一次开盖明细”（DI=03300D01）：arrPush = DATA-0x33 后的数组
function parseCoverOpenLast645(arrPush) {
    // 结构：DI(4) + 发生时刻(6B) + 结束时刻(6B) + 能量(4项，小端 BCD，长度可为4B/5B/6B)
    const data = arrPush.slice(4);           // 去掉 DI
    if (data.length < 12) {
        return { type: 'cover_open_record', ok: false, reason: 'data_too_short', rawData: bytesToHex(data).replace(/\s+/g, '') };
    }

    // 1) 时间（优先按 6B+6B）
    const startTimeBytes = data.slice(0, 6);
    const endTimeBytes = data.slice(6, 12);
    const start = parseTimeBCD6or7(startTimeBytes);
    const end = parseTimeBCD6or7(endTimeBytes);

    // 2) 能量段起始偏移
    let off = 12;

    // 3) 能量长度自适应检测（4×4B / 4×5B / 4×6B）
    function isAllBCDNibbles(bs) {
        for (let i = 0; i < bs.length; i++) {
            const b = bs[i] & 0xFF, hi = (b >> 4) & 0x0F, lo = b & 0x0F;
            if (hi > 9 || lo > 9) return false;
        }
        return true;
    }
    function parseEnergiesFlexible(bytes) {
        const labels = ['开盖前正向有功总', '开盖前反向有功总', '开盖后正向有功总', '开盖后反向有功总'];

        // 尝试 4B×4（scale=2）
        if (bytes.length >= 16 && isAllBCDNibbles(bytes.slice(0, 16))) {
            const out = [];
            for (let i = 0; i < 4; i++) {
                const seg = bytes.slice(i * 4, i * 4 + 4);
                const val = bcdLEToInt(seg);
                out.push({ label: labels[i], rawValue: val, kwh: val / 100, unit: 'kWh', bcdData: bcdDigitsStrLE(seg), bytes: bytesToHex(seg) });
            }
            return { list: out, used: 16, scale: 2 };
        }
        // 尝试 5B×4（scale=3）
        if (bytes.length >= 20 && isAllBCDNibbles(bytes.slice(0, 20))) {
            const out = [];
            for (let i = 0; i < 4; i++) {
                const seg = bytes.slice(i * 5, i * 5 + 5);
                const val = bcdLEToInt(seg);
                out.push({ label: labels[i], rawValue: val, kwh: val / 1000, unit: 'kWh', bcdData: bcdDigitsStrLE(seg), bytes: bytesToHex(seg) });
            }
            return { list: out, used: 20, scale: 3 };
        }
        // 尝试 6B×4（scale=4）
        if (bytes.length >= 24 && isAllBCDNibbles(bytes.slice(0, 24))) {
            const out = [];
            for (let i = 0; i < 4; i++) {
                const seg = bytes.slice(i * 6, i * 6 + 6);
                const val = bcdLEToInt(seg);
                out.push({ label: labels[i], rawValue: val, kwh: val / 10000, unit: 'kWh', bcdData: bcdDigitsStrLE(seg), bytes: bytesToHex(seg) });
            }
            return { list: out, used: 24, scale: 4 };
        }
        return { list: [], used: 0, scale: null };
    }

    const energiesBytes = data.slice(off);
    const parsed = parseEnergiesFlexible(energiesBytes);

    return {
        type: 'cover_open_record',
        ok: true,
        di: '03300D01',
        startTime: start ? start.formatted : null,
        endTime: end ? end.formatted : null,
        startTimeDetail: start,
        endTimeDetail: end,
        energies: parsed.list,          // 按顺序：前正、前反、后正、后反
        scale: parsed.scale,            // 小数位（2/3/4）
        rawData: bytesToHex(data).replace(/\s+/g, ''),
        note: '按 6B时间 + 4×小端 BCD 能量 自适应解析'
    };
}



function batchMsgMain(msg) {
    /******************** 入口：根据 msg.mode / msg.action 选择 encode / decode ********************/
    const MODE = String(msg.mode || msg.action || 'decode').toLowerCase();

    // 可选：地址是否在“编码”时倒序（有些 645 实装要求）；解码固定按帧内小端规则处理
    const ADDR_REVERSE = !!msg.addr_reverse;

    // 可选：编码时 CS 模式：'std'（从第二个68后 C+L+DATA） | 'full'（从第一个68起至 CS 前）
    // 解码侧会双模自动通过，无需设置
    const CS_MODE = (msg.cs_mode === 'full' ? 'full' : 'std');

    if (MODE === 'encode') {
        const isArr = Array.isArray(msg.payload);
        const arrCmds = isArr ? msg.payload : [msg.payload];
        const frames = arrCmds
            .filter(i => i && (i.payload?.oad || i.oad))
            .map(i => build645Frame(i, ADDR_REVERSE, (i.cs_mode || CS_MODE)));

        msg.payload = isArr ? frames : frames[0];
        return msg;
    }

    /******************** decode：解码 645 响应（统一返回对象，含 exec_addr 等） ********************/
    const dataIn = msg.payload;

    if (Array.isArray(dataIn)) {
        msg.payload = dataIn.map(_msg => decode645(_msg));
    } else {
        const decodedResult = decode645(msg);
        msg.payload = decodedResult;

    }
    return msg;
}


module.exports = batchMsgMain;
module.exports.batchMsg645 = batchMsgMain;
