function test() {
    var ViewController = ObjC.classes.ViewController
    Interceptor.attach(ViewController['+ functionTest:x3:x4:x5:x6:x7:stack1:stack2:stack3:stack4:stack5:'].implementation, {
        onEnter: function (args) {
            console.log('stack1: ' + args[8])
            console.log('stack2: ' + args[9])
            console.log('stack3: ' + args[10])
            console.log('stack4: ' + args[11])
            console.log('stack5: ' + args[12])
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