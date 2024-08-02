function hook_native_asset() {
    Interceptor.attach(Module.findExportByName("libandroid.so", "AAssetManager_open"), {
        onEnter: function(args) {
            this.fileName = ptr(args[1]).readCString();
        },
    
        onLeave:function(retval) {
            if (retval != 0) {
                log_msg(`${this.fileName}`)
            }
        }
    });
}

function hook_java_asset() {
    let AssetManager = Java.use("android.content.res.AssetManager");
    AssetManager["open"].overload("java.lang.String", "int").implementation = function (fileName, accessMode) {
        console.log(`${fileName}`);
        return this["open"](fileName, accessMode);
    };
    AssetManager["openFd"].overload("java.lang.String").implementation = function (fileName) {
        console.log(`${fileName}`);
        return this["openFd"](fileName);
    };
}

function main() {
    hook_native_asset();
    if (Java.available) {
        Java.perform(function() {
            hook_java_asset();
        });
    }
}

setImmediate(main);