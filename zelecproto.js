module.exports = function (RED) {
    "use strict";
    var events = require("events");
    var _zemitter = new events.EventEmitter();

    function Zlog(n) {
        RED.nodes.createNode(this, n);
        var node = this;
        if (!RED.settings.functionGlobalContext.zemitter) {
            RED.settings.functionGlobalContext.zemitter = _zemitter;
        }
        _zemitter.on('zlog', function (msg) {
            node.send(msg);
        })

        this.on("input", function (msg, send, done) {
            send(msg);
            done();
        });
        this.on('close', () => {
            _zemitter.removeAllListeners();
        });

    }
    RED.nodes.registerType("zlog", Zlog);

}
