
var proto645 = require("./645");
var proto698 = require("./698");

let msg = {};
msg.payload = 'FE FE FE FE 68 30 00 C3 05 60 80 63 00 15 19 11 38 1D 90 00 17 85 01 01 30 1B 07 00 01 01 01 02 02 00 02 02 06 00 00 00 00 00 00 00 01 00 04 4C 3E EE F6 B3 CA 16'
// msg.payload = 'FE FE FE FE 68 30 00 C3 05 77 59 63 00 15 19 11 59 0F 90 00 17 85 01 01 30 1B 07 00 01 01 01 02 02 00 02 02 06 00 00 00 00 00 00 00 01 00 04 B2 F3 8B 23 F2 7C 16'
// msg.payload = 'FE FE FE FE 68 33 00 C3 05 77 59 63 00 15 19 11 EA F1 90 00 1A 85 01 01 30 13 0A 00 01 01 01 02 02 00 02 02 1C 07 E3 07 17 00 02 2B 00 00 00 01 00 04 30 B1 C0 6E 47 F6 16'
msg.proto = 698
msg.mode = 'decode'



console.log(JSON.stringify(proto698(msg)));
console.log(proto698(msg));