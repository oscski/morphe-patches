package app.morphe.patches.all.misc.screenshot

import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patches.all.misc.transformation.IMethodCall
import app.morphe.patches.all.misc.transformation.filterMapInstruction35c
import app.morphe.util.findMutableMethodOf
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction22c
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction35c
import com.android.tools.smali.dexlib2.iface.reference.FieldReference
import com.android.tools.smali.dexlib2.iface.reference.MethodReference

private const val EXTENSION_CLASS_DESCRIPTOR_PREFIX =
    "Lapp/morphe/extension/all/misc/screenshot/removerestriction/RemoveScreenshotRestrictionPatch"
private const val EXTENSION_CLASS_DESCRIPTOR = "$EXTENSION_CLASS_DESCRIPTOR_PREFIX;"

private const val WINDOW_CLASS = "Landroid/view/Window;"
private const val LAYOUT_PARAMS_CLASS = "Landroid/view/WindowManager\$LayoutParams;"

@Suppress("unused")
val removeScreenshotRestrictionPatch = bytecodePatch(
    name = "Remove screenshot restriction",
    description = "Removes the restriction of taking screenshots in apps that normally wouldn't allow it.",
    default = false,
) {
    extendWith("extensions/all/misc/screenshot/remove-screenshot-restriction.mpe")

    execute {
        classDefForEach { classDef ->
            // Skip the extension class itself to avoid infinite recursion.
            if (classDef.type.startsWith(EXTENSION_CLASS_DESCRIPTOR_PREFIX)) return@classDefForEach

            val mutableClass by lazy { mutableClassDefBy(classDef) }

            classDef.methods.forEach { method ->
                val implementation = method.implementation ?: return@forEach

                val mutableMethod by lazy { mutableClass.findMutableMethodOf(method) }

                val windowCallIndices = mutableListOf<Int>()
                val layoutParamsIputIndices = mutableListOf<Int>()

                implementation.instructions.forEachIndexed { index, instruction ->
                    when (instruction.opcode) {
                        Opcode.INVOKE_VIRTUAL -> {
                            val ref = (instruction as Instruction35c).reference as? MethodReference
                                ?: return@forEachIndexed
                            if (ref.definingClass == WINDOW_CLASS &&
                                (ref.name == "addFlags" || ref.name == "setFlags")
                            ) windowCallIndices.add(index)
                        }
                        Opcode.IPUT -> {
                            val ref = (instruction as Instruction22c).reference as? FieldReference
                                ?: return@forEachIndexed
                            if (ref.definingClass == LAYOUT_PARAMS_CLASS &&
                                ref.name == "flags" &&
                                ref.type == "I"
                            ) layoutParamsIputIndices.add(index)
                        }
                        else -> return@forEachIndexed
                    }
                }

                if (windowCallIndices.isEmpty() && layoutParamsIputIndices.isEmpty()) return@forEach

                // Replace Window#addFlags / Window#setFlags with extension stubs.
                windowCallIndices.asReversed().forEach { index ->
                    val instruction = implementation.instructions.elementAt(index) as Instruction35c
                    val entry = filterMapInstruction35c<MethodCall>(
                        EXTENSION_CLASS_DESCRIPTOR_PREFIX,
                        classDef,
                        instruction,
                        index,
                    ) ?: return@forEach
                    val (methodType, instruction35c, instructionIndex) = entry
                    methodType.replaceInvokeVirtualWithExtension(
                        EXTENSION_CLASS_DESCRIPTOR,
                        mutableMethod,
                        instruction35c,
                        instructionIndex,
                    )
                }

                // Strip FLAG_SECURE from direct IPUT writes to LayoutParams#flags.
                layoutParamsIputIndices.asReversed().forEach { index ->
                    val instruction = implementation.instructions.elementAt(index) as Instruction22c
                    val register = instruction.registerA
                    mutableMethod.addInstructions(
                        index,
                        "and-int/lit16 v$register, v$register, -0x2001",
                    )
                }
            }
        }
    }
}

// Information about method calls we want to replace.
@Suppress("unused")
private enum class MethodCall(
    override val definedClassName: String,
    override val methodName: String,
    override val methodParams: Array<String>,
    override val returnType: String,
) : IMethodCall {
    AddFlags(
        "Landroid/view/Window;",
        "addFlags",
        arrayOf("I"),
        "V",
    ),
    SetFlags(
        "Landroid/view/Window;",
        "setFlags",
        arrayOf("I", "I"),
        "V",
    ),
}
