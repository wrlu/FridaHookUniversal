function log_msg(message) {
    console.log('['+__identifier+'] '+message)
}

function hook_gl() {
    // Mali GPU devices (Google Tensor, MTK, Samsung Exynos, Hisilicon before kirin9000 and etc.)
    let mali_gles_elf = "libGLES_mali.so";
    // Qualcomm Adreno GPU devices.
    let adreno_gles_elf = "libGLESv2_adreno.so";
    Interceptor.attach(Module.findExportByName(mali_gles_elf, "glShaderSource"), {
        onEnter: function(args) {
            log_msg("OpenGL glShaderSource")
        },
    
        onLeave:function(retval) {
            
        }
    });
}

function main() {
    hook_gl()
}

setImmediate(main);