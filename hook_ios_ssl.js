function hookSSLwrite() {
    var resolver = new ApiResolver('module');
    
    var patterns = [
        'exports:*libboringssl.dylib!SSL_write*',
        'exports:*libboringssl.dylib!SSL_send*'
    ];
    
    var targets = [];
    patterns.forEach(p => {
        targets = targets.concat(resolver.enumerateMatches(p));
    });

    targets.forEach(function (match) {
        var funcName = match.name.split('!').pop();
        
        Interceptor.attach(match.address, {
            onEnter: function (args) {
                try {
                    var buf = args[1];
                    var len = args[2].toInt32();
                    if (len <= 0) return;

                    var str = buf.readUtf8String(Math.min(len, 1024));
                    if (str) {
                        var isHttp = /^(GET|POST|PUT|DELETE|CONNECT) /i.test(str) || str.indexOf("Host:") !== -1;
                        
                        if (isHttp) {
                            var firstLine = str.split('\r\n')[0] || "";
                            var hostMatch = str.match(/Host:\s*([^\r\n]+)/i);
                            var domain = hostMatch ? hostMatch[1] : "unknown-host";
                            var time = new Date().toLocaleTimeString();
                            
                            console.log(`[${time}] ✅ [${funcName}] ${domain.padEnd(25)} | 🚀 ${firstLine}`);
                        }
                    }
                } catch (e) {
                    var time = new Date().toLocaleTimeString();
                    var hex = hexdump(args[1], { length: 16, header: false, ansi: false }).split('\n')[0];
                    console.error(`[${time}] [!] ${funcName} 解析失败: ${e.message} | 原始数据: ${hex}`);
                }
            }
        });
    });
}

function downgradeQUIC() {
    var resolver = new ApiResolver('module');

    var syscalls = [];
    try {
        syscalls = resolver.enumerateMatches('exports:libsystem_kernel.dylib!*send*msg*');
        syscalls = syscalls.concat(resolver.enumerateMatches('exports:libsystem_kernel.dylib!*sendto*'));
    } catch (e) { }

    syscalls.forEach(function (match) {
        Interceptor.attach(match.address, {
            onEnter: function (args) { 
                this.isBlocked = true; 
            },
            onLeave: function (retval) { if (this.isBlocked) retval.replace(ptr("0x100")); }
        });
    });

    var nwMatches = [];
    try {
        nwMatches = resolver.enumerateMatches('exports:libnetwork.dylib!*udp*');
        nwMatches = nwMatches.concat(resolver.enumerateMatches('exports:libnetwork.dylib!nw_protocol_stack_*'));
    } catch (e) { }

    nwMatches.forEach(function (match) {
        var name = match.name.toLowerCase();
        if (name.indexOf("create") !== -1 || name.indexOf("add") !== -1 || name.indexOf("copy") !== -1) {
            Interceptor.attach(match.address, {
                onLeave: function (retval) {
                    try {
                        if (retval && !retval.isNull()) {
                            retval.replace(ptr(0));
                        }
                    } catch (e) { }
                }
            });
        }
    });
}

setImmediate(function () {
    downgradeQUIC();
    hookSSLwrite();
});
