import com.alibaba.fastjson.JSON;

public class FatRunner {
    public static void main(String[] args) {
        String payload = args[0];
        System.out.println("[FatRunner] ParserConfig classloader = "
                + com.alibaba.fastjson.parser.ParserConfig.class.getClassLoader());
        try {
            Object parsed = JSON.parse(payload);
            System.out.println("[FatRunner] parsed -> " + describe(parsed));
        } catch (Throwable throwable) {
            System.out.println("[FatRunner] threw: " + throwable);
        }
    }

    private static String describe(Object value) {
        if (value == null) {
            return "null";
        }
        return value.getClass().getName() + " " + value;
    }
}
