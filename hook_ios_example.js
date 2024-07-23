function log_msg(message) {
    console.log('['+__name+'] '+message)
}

function example() {
    var clazz = ObjC.classes.ClassName

    Interceptor.attach(clazz['- methodName:'].implementation, {
        onEnter: function (args) {
            // Tips: args[0] is id object, args[1] is SEL object, the real first parameter is args[2]
            log_msg('Hook -[ClassName methodName:]')
        },
        onLeave: function (retval) {

        }
    });
}

function main() {
    if (ObjC.available) {
        example()
    }
}

setImmediate(main);