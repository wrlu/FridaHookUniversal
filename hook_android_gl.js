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
    value = parseInt(value, 16)
    const formatMap = {
        0x1903: 'GL_ALPHA',
        0x1907: 'GL_RGB',
        0x1908: 'GL_RGBA',
        0x1909: 'GL_LUMINANCE',
        0x8814: 'GL_RGBA32F',
        0x8815: 'GL_RGB32F',
        0x881a: 'GL_RGBA16F',
        0x881b: 'GL_RGB16F'
    };
    return formatMap[value] || value;
}

function parseType(value) {
    value = parseInt(value, 16)
    const typeMap = {
        0x1400: 'GL_BYTE',
        0x1401: 'GL_UNSIGNED_BYTE',
        0x1402: 'GL_SHORT',
        0x1403: 'GL_UNSIGNED_SHORT',
        0x1404: 'GL_INT',
        0x1405: 'GL_UNSIGNED_INT',
        0x1406: 'GL_FLOAT',
        0x140B: 'GL_UNSIGNED_BYTE_3_3_2',
        0x140C: 'GL_UNSIGNED_BYTE_2_3_3_REV',
        0x140D: 'GL_UNSIGNED_SHORT_5_6_5',
        0x140E: 'GL_UNSIGNED_SHORT_5_6_5_REV',
        0x140F: 'GL_UNSIGNED_SHORT_4_4_4_4',
        0x1410: 'GL_UNSIGNED_SHORT_4_4_4_4_REV',
        0x1411: 'GL_UNSIGNED_SHORT_5_5_5_1',
        0x1412: 'GL_UNSIGNED_SHORT_1_5_5_5_REV',
        0x8033: 'GL_UNSIGNED_INT_8_8_8_8',
        0x8034: 'GL_UNSIGNED_INT_8_8_8_8_REV',
        0x8035: 'GL_UNSIGNED_INT_10_10_10_2',
        0x8036: 'GL_UNSIGNED_INT_2_10_10_10_REV',
        0x8D61: 'GL_HALF_FLOAT'
    };
    return typeMap[value] || value;
}

function parseTarget(value) {
    value = parseInt(value, 16)
    const targetMap = {
        0xde1: 'GL_TEXTURE_2D'
    };
    return targetMap[value] || value;
}

function getTypeByteSize(typeName) {
    const typeByteSizes = {
        'GL_BYTE': 1,
        'GL_UNSIGNED_BYTE': 1,
        'GL_SHORT': 2,
        'GL_UNSIGNED_SHORT': 2,
        'GL_INT': 4,
        'GL_UNSIGNED_INT': 4,
        'GL_FLOAT': 4,
        'GL_HALF_FLOAT': 2
    };
    return typeByteSizes[typeName] || 0;
}

function getFormatSize(formatName) {
    const formatSizes = {
        'GL_RGBA': 4,
        'GL_RGBA32F': 4,
        'GL_RGBA16F': 4,
        'GL_LUMINANCE': 1,
        'GL_RGB': 3,
        'GL_RGB32F': 3,
        'GL_RGB16F': 3
    };
    return formatSizes[formatName] || 0;
}

function calculateDataSize(formatName, typeName, width, height) {
    if (formatName == 'GL_RGBA16F' && typeName == 'GL_FLOAT') {
        typeName = 'GL_HALF_FLOAT'
    }
    const formatSize = getFormatSize(formatName);
    const typeByteSize = getTypeByteSize(typeName);
    return width * height * formatSize * typeByteSize;
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
            let internalformatName = parseFormat(internalformat)
            let typeName = parseType(type)         
            const size = calculateDataSize(internalformatName, typeName, width, height);
            console.log(`glTexImage2D: target=${parseTarget(target)}, format=${formatName}, internalformat=${internalformatName}, width=${Number(width)}, height=${Number(height)}, type=${typeName}, data=${data}`)
            let textureData = data.readByteArray(size)
            send(`glTexImage2D:{"width": ${Number(width)}, "height": ${Number(height)}, "format": "${formatName}", "internalformat": "${internalformatName}", "type": "${typeName}"}`, textureData)

        },
        onLeave: function(retval) {}
    })

    let glTexSubImage2D = Module.findExportByName(gles_elf, "glTexSubImage2D")
    Interceptor.attach(glTexSubImage2D, {
        onEnter: function(args) {
            let target = args[0]
            let level = args[1]
            let xoffset = args[2]
            let yoffset = args[3]
            let width = args[4]
            let height = args[5]
            let format = args[6]
            let type = args[7]
            let data = args[8]

            let formatName = parseFormat(format)
            console.log(format)
            let typeName = parseType(type)
            const size = calculateDataSize(formatName, typeName, width, height);
            console.log(`glTexSubImage2D: target=${parseTarget(target)}, xoffset=${Number(xoffset)}, yoffset=${Number(yoffset)}, width=${Number(width)}, height=${Number(height)}, format=${formatName}, type=${typeName}, data=${data}`)
            let textureData = data.readByteArray(size)
            send(`glTexSubImage2D:{"xoffset": ${Number(xoffset)}, "yoffset": ${Number(yoffset)}, "width": ${Number(width)}, "height": ${Number(height)}, "format": "${formatName}", "type": "${typeName}"}`, textureData)
        },
        onLeave: function(retval) {}
    })
}

function main() {
    hook_gl_shader()
    hook_gl_texture()
}

setImmediate(main);