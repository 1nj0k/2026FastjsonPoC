import com.alibaba.fastjson.annotation.JSONType;

@JSONType
public class POC {
    static {
        System.out.println("POC <clinit> EXECUTED");
        try {
            new java.io.File(System.getProperty("poc.pwnedFile", "PWNED")).createNewFile();
        } catch (Throwable ignored) {
            // Keep the control class side-effect best-effort.
        }
    }
}
