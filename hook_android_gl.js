function hook_gl() {
    // Mali GPU devices (Google Tensor, MTK, Samsung Exynos, Hisilicon before kirin9000 and etc).
    let mali_gles_elf = "libGLES_mali.so";
    // Qualcomm Adreno GPU devices.
    let adreno_gles_elf = "libGLESv2_adreno.so";
    let gles_elf = mali_gles_elf
    
    let glGetProgramiv = new NativeFunction(Module.findExportByName(gles_elf, "glGetProgramiv"), 'void', ['pointer', 'int', 'pointer'])
    let glGetAttachedShaders = new NativeFunction(Module.findExportByName(gles_elf, "glGetAttachedShaders"), 'void', ['pointer', 'int', 'pointer', 'pointer'])
    let glGetShaderiv = new NativeFunction(Module.findExportByName(gles_elf, "glGetShaderiv"), 'void', ['uint', 'int', 'pointer'])
    let glGetShaderSource = new NativeFunction(Module.findExportByName(gles_elf, "glGetShaderSource"), 'void', ['uint', 'int', 'pointer', 'pointer'])
    let glUseProgram = Module.findExportByName(gles_elf, "glUseProgram")

    Interceptor.attach(glUseProgram, {
        onEnter: function(args) {
            let program = args[0]
            // 1. Get shader count in program.
            let shaderCountPointer = Memory.alloc(8)
            glGetProgramiv(program, 0x8b85 /* GL_ATTACHED_SHADERS */, shaderCountPointer)
            var shaderCount = shaderCountPointer.readInt()
            // 2. Alloc memory for attached shaders.
            let realShaderCountPointer = Memory.alloc(8)
            let attachedShadersPointer = Memory.alloc(Process.pointerSize)
            for (var i = 0; i < shaderCount; i++) {
                attachedShadersPointer.add(i * Process.pointerSize)
                attachedShadersPointer.writeUInt(0)
            }
            // 3. Get attached shaders
            glGetAttachedShaders(program, shaderCount, realShaderCountPointer, attachedShadersPointer)
            var realShaderCount = realShaderCountPointer.readInt()
            for (var i = 0; i < realShaderCount; i++) {
                // 4. Get each shader source length.
                let attachedShader = Memory.readUInt(attachedShadersPointer.add(i * Process.pointerSize))
                let shaderSourceLenPointer = Memory.alloc(Process.pointerSize)
                glGetShaderiv(attachedShader, 0x8b88 /* GL_SHADER_SOURCE_LENGTH */, shaderSourceLenPointer)
                var shaderSourceLen = shaderSourceLenPointer.readInt()
                if (shaderSourceLen != 0) {
                    // 5. Alloc memory for each shader source.
                    let realShaderSourceLenPointer = Memory.alloc(Process.pointerSize)
                    let shaderSourcePointer = Memory.alloc(shaderSourceLen)
                    // 6. Get shader source.
                    glGetShaderSource(attachedShader, shaderSourceLen, realShaderSourceLenPointer, shaderSourcePointer)
                    let shaderSource = shaderSourcePointer.readCString()
                    send(shaderSource)
                }
            }
        },
        onLeave: function(retval) {}
    })
}

function main() {
    hook_gl()
}

setImmediate(main);