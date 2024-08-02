function log_msg(message) {
    console.log('['+__name+'] '+message)
}

function test() {
    var ViewController = ObjC.classes.ViewController
    Interceptor.attach(ViewController['+ functionTest:x3:x4:x5:x6:x7:stack1:stack2:stack3:stack4:stack5:'].implementation, {
        onEnter: function (args) {
            log_msg('stack1: ' + args[8])
            log_msg('stack2: ' + args[9])
            log_msg('stack3: ' + args[10])
            log_msg('stack4: ' + args[11])
            log_msg('stack5: ' + args[12])
        },
        onLeave: function (retval) {

        }
    });
}

function main() {
    if (ObjC.available) {
        test()
    }
}

setImmediate(main);