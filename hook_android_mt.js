function printStackTrace() {
    var stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
    for (var i = 0; i < stackTrace.length; i++) {
        console.log("  " + (i + 1) + ". " + stackTrace[i].toString());
    }
}

function hook_record() {
    let PugImplEnum = Java.use("com.meitu.pug.core.PugImplEnum");
    PugImplEnum["printAndRecord"].implementation = function (level, tag, msg, obj, args) {
        console.log(`[ ${tag} ] ${msg}, ${obj}, ${args}`);
        this["printAndRecord"](level, tag, msg, obj, args);
    };
}


function main() {
    if (Java.available) {
        Java.perform(function () {
            hook_record();
        });
    }
}

setImmediate(main);