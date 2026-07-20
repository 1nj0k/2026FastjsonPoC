import com.alibaba.fastjson.JSON;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.beans.EventHandler;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * 本机 Fastjson 1.2.83 漏洞演示服务。
 * POST /api/parse  -> 反序列化 DualDto 并触发 RCE
 */
public class VulnServer {
    public static class DualDto {
        public ProcessBuilder pb;
        public InvocationHandler handler;
    }

    public static void main(String[] args) throws Exception {
        int port = 18080;
        boolean autoPort = true;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
            autoPort = false;
        }

        HttpServer server = null;
        int tries = autoPort ? 20 : 1;
        BindException last = null;
        for (int i = 0; i < tries; i++) {
            int p = port + i;
            try {
                server = HttpServer.create(new InetSocketAddress("127.0.0.1", p), 0);
                port = p;
                break;
            } catch (BindException e) {
                last = e;
            }
        }
        if (server == null) {
            throw last != null ? last : new BindException("no free port");
        }

        server.createContext("/", VulnServer::handleIndex);
        server.createContext("/api/parse", VulnServer::handleParse);
        server.createContext("/health", VulnServer::handleHealth);
        server.setExecutor(null);
        server.start();

        System.out.println("[+] Fastjson 1.2.83 vuln server started");
        System.out.println("[+] listen : http://127.0.0.1:" + port);
        System.out.println("[+] parse  : POST http://127.0.0.1:" + port + "/api/parse");
        System.out.println("[+] health : GET  http://127.0.0.1:" + port + "/health");
        System.out.println("[*] 另开终端执行: python3 poc/exploit.py --url http://127.0.0.1:" + port + "/api/parse");
        System.out.println("[*] Ctrl+C 停止服务");
    }

    private static void handleIndex(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            write(ex, 405, "text/plain; charset=utf-8", "method not allowed\n");
            return;
        }
        write(ex, 200, "text/plain; charset=utf-8",
                "Fastjson 1.2.83 local vuln demo\n"
                        + "POST /api/parse\n"
                        + "GET  /health\n");
    }

    private static void handleHealth(HttpExchange ex) throws IOException {
        write(ex, 200, "application/json; charset=utf-8",
                "{\"status\":\"ok\",\"fastjson\":\"1.2.83\"}\n");
    }

    private static void handleParse(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            write(ex, 405, "application/json; charset=utf-8",
                    "{\"ok\":false,\"error\":\"POST only\"}\n");
            return;
        }

        String json = readBody(ex.getRequestBody());
        System.out.println("[*] json=" + json);

        Map<String, Object> resp = new HashMap<String, Object>();
        try {
            DualDto dto = JSON.parseObject(json, DualDto.class);
            if (dto == null || dto.pb == null || dto.handler == null) {
                throw new IllegalArgumentException("need both pb and handler");
            }

            Field target = EventHandler.class.getDeclaredField("target");
            target.setAccessible(true);
            target.set(dto.handler, dto.pb);

            Runnable runner = (Runnable) Proxy.newProxyInstance(
                    VulnServer.class.getClassLoader(),
                    new Class[]{Runnable.class},
                    dto.handler
            );
            runner.run();

            resp.put("ok", true);
            resp.put("msg", "RCE triggered");
            resp.put("command", dto.pb.command());
            write(ex, 200, "application/json; charset=utf-8", JSON.toJSONString(resp) + "\n");
            System.out.println("[+] RCE ok, command=" + dto.pb.command());
        } catch (Throwable t) {
            resp.put("ok", false);
            resp.put("error", t.getClass().getSimpleName() + ": " + t.getMessage());
            write(ex, 500, "application/json; charset=utf-8", JSON.toJSONString(resp) + "\n");
            System.out.println("[-] " + t);
        }
    }

    private static String readBody(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) >= 0) {
            bos.write(buf, 0, n);
        }
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void write(HttpExchange ex, int code, String ctype, String body) throws IOException {
        byte[] data = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", ctype);
        ex.sendResponseHeaders(code, data.length);
        OutputStream os = ex.getResponseBody();
        os.write(data);
        os.close();
    }
}
