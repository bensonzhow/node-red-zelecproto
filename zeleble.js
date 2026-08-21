module.exports = function (RED) {
    "use strict";
    var protoBle = require("./ble");

    function zeleble(n) {
        RED.nodes.createNode(this, n);
        var node = this;    

        this.on("input", function (msg, send, done) {
            try {
                msg = protoBle(msg);
                send(msg);
                done();
            } catch (err) {
                node.error(err, msg);
                done(err);
            }
        });
        this.on('close', () => {

        });

    }
    RED.nodes.registerType("zeleble", zeleble);

}
