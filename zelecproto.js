module.exports = function (RED) {
    "use strict";
    var proto645 = require("./645");
    var proto698 = require("./698");

    function zelecproto(n) {
        RED.nodes.createNode(this, n);
        var node = this;    

        this.on("input", function (msg, send, done) {
            try {
                var proto = msg.customProto || msg.proto;
                if(proto == "645"){
                    msg = proto645(msg);
                }else if(proto == "698"){
                    msg = proto698(msg);
                }

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
    RED.nodes.registerType("zelecproto", zelecproto);

}
