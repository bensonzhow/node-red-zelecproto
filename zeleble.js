module.exports = function (RED) {
    "use strict";
    var protoBle = require("./ble");

    function zeleble(n) {
        RED.nodes.createNode(this, n);
        var node = this;    

        this.on("input", function (msg, send, done) {
            msg = protoBle(msg);
            send(msg);
            done();
        });
        this.on('close', () => {

        });

    }
    RED.nodes.registerType("zeleble", zeleble);

}
