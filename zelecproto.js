module.exports = function (RED) {
    "use strict";
    var proto645 = require("./645");
    var proto698 = require("./698");

    function zelecproto(n) {
        RED.nodes.createNode(this, n);
        var node = this;    

        this.on("input", function (msg, send, done) {
            msg._proto = msg.customProto || msg.proto
            if(msg._proto == "645"){
                msg = proto645(msg);
            }else if(msg._proto == "698"){
                msg = proto698(msg);
            }
            delete msg._proto
            
            send(msg);

            done();
        });
        this.on('close', () => {

        });

    }
    RED.nodes.registerType("zelecproto", zelecproto);

}
