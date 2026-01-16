module.exports = function (RED) {
    "use strict";
    
    var proto645 = require("./645");
    var proto698 = require("./698");

    function zbatchproto(n) {
        RED.nodes.createNode(this, n);
        var node = this;
        

        this.on("input", function (msg, send, done) {
            send(msg);
            done();
        });
        this.on('close', () => {

        });

    }
    RED.nodes.registerType("zbatchproto", zbatchproto);

}
