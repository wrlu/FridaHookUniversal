function log_msg(message) {
    console.log('['+__identifier+'] '+message)
}

function loaddex(dexPath, targetClassName, targetMethod) {
    let activityThreadObj = Java.use('android.app.ActivityThread').currentActivityThread()
    let classLoaderObj = activityThreadObj.getClass().getClassLoader()
    
    let dexClassLoaderObj = Java.use('dalvik.system.DexClassLoader').$new(dexPath, null, null, classLoaderObj)
    let ppsTaskClass = dexClassLoaderObj.findClass(targetClassName)
    ppsTaskClass.getDeclaredMethod(targetMethod, null).invoke(null, null)
}

function main() {
    let dexPath = 'test.dex'
    let targetClassName = 'com.wrlus.Example'
    let targetMethod = 'directCall'
    if (Java.available) {
        loaddex(dexPath, targetClassName, targetMethod)
    }
}

setImmediate(main)