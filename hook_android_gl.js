function hook_gl_shader() {
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

function parseFormat(value) {
    if (value == 0x1908)
        return 'GL_RGBA'
    if (value == 0x1909)
        return 'GL_LUMINANCE'
    if (value == 0x8814)
        return 'GL_RGBA32F'
    return value
}

function parseType(value) {
    if (value == 0x1401)
        return 'GL_UNSIGNED_BYTE'
    if (value == 0x1406)
        return 'GL_FLOAT'
    return value
}

function parseTarget(value) {
    if (value == 0x0DE1)
        return 'GL_TEXTURE_2D'
    return value
}

function getFormatSize(formatName) {
    if (formatName == 'GL_RGBA' || formatName == 'GL_RGBA32F') {
        return 4
    } else if (formatName == 'GL_LUMINANCE') {
        return 1
    }
    return 3
}

function hook_gl_texture() {
    // Mali GPU devices (Google Tensor, MTK, Samsung Exynos, Hisilicon before kirin9000 and etc).
    let mali_gles_elf = "libGLES_mali.so";
    // Qualcomm Adreno GPU devices.
    let adreno_gles_elf = "libGLESv2_adreno.so";
    let gles_elf = mali_gles_elf

    let glTexImage2D = Module.findExportByName(gles_elf, "glTexImage2D")
    Interceptor.attach(glTexImage2D, {
        onEnter: function(args) {
            let target = args[0]
            let level = args[1]
            let internalformat = args[2]
            let width = args[3]
            let height = args[4]
            let border = args[5]
            let format = args[6]
            let type = args[7]
            let data = args[8]

            let formatName = parseFormat(format)
            let formatSize = getFormatSize(formatName)
            let size = width * height * formatSize
            console.log(`glTexImage2D: target=${parseTarget(target)}, internalformat=${parseFormat(internalformat)}, width=${Number(width)}, height=${Number(height)}, type=${parseType(type)}, data=${data}`)
            let textureData = data.readByteArray(size)
            send(`glTexImage2D:{"width": "${Number(width)}", "height": "${Number(height)}", "format": "${parseFormat(format)}", "type": "${parseType(type)}"}`, textureData)

        },
        onLeave: function(retval) {}
    })
}

function main() {
    // hook_gl_shader()
    // hook_gl_texture()
}

setImmediate(main);