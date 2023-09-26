function log_msg(message) {
    console.log('['+__identifier+'] '+message)
}

// __int64 __fastcall android::SurfaceFlinger::onTransact(android::SurfaceFlinger *this, signed int, const android::Parcel *, android::Parcel *, unsigned int)
function hook_onTransact() {
    let lib_elf_name = "libsurfaceflinger.so"
    let target_func_name = "_ZN7android14SurfaceFlinger10onTransactEjRKNS_6ParcelEPS1_j"
    let target_func_offset = 0x11EAD0
    // let target_func_addr = Module.findExportByName(lib_elf_name , target_func_name)
    // let base_addr = Module.getBaseAddress(lib_elf_name)
    let base_addr = 0x7ad9919000
    log_msg("Target ELF base address = " + base_addr)
    let target_func_addr = new NativePointer(base_addr + target_func_offset)
    log_msg("Target function address = " + target_func_addr)
    
    Interceptor.attach(target_func_addr, {
        onEnter: function(args) {
            log_msg("hook on enter")
        },
    
        onLeave:function(retval) {
            log_msg("hook on leave")
        }
    })
}

function process() {
    log_msg('This is just an example')
}

function main() {
    if (Java.available) {
        Java.perform(function() {
            // process()
            // hook_onTransact()
        })
    }
}

setImmediate(main);