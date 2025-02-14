function hook_native_asset() {
    Interceptor.attach(Module.findExportByName("libandroid.so", "AAssetManager_open"), {
        onEnter: function(args) {
            this.fileName = ptr(args[1]).readCString();
        },
    
        onLeave:function(retval) {
            if (retval != 0) {
                console.log(`file://android_asset/${this.fileName}`)
            }
        }
    });
}

function hook_java_asset() {
    let AssetManager = Java.use("android.content.res.AssetManager");
    AssetManager["open"].overload("java.lang.String", "int").implementation = function (fileName, accessMode) {
        console.log(`file://android_asset/${fileName}`);
        return this["open"](fileName, accessMode);
    };
    AssetManager["openFd"].overload("java.lang.String").implementation = function (fileName) {
        console.log(`file://android_asset/${fileName}`);
        return this["openFd"](fileName);
    };
}

function hook_native_fopen() {
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            let path = args[0];
            let path_str = `${path.readCString()}`
            if (path_str.startsWith('/data') || path_str.startsWith('/storage') || path_str.startsWith('/sdcard')) {
                console.log(`file://${path_str}`);
            }
        },
        onLeave:function(retval) {}
    });
}

function main() {
    hook_native_asset();
    hook_native_fopen();
    if (Java.available) {
        Java.perform(function() {
            hook_java_asset();
        });
    }
}

setImmediate(main);