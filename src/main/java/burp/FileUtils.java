package burp;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class FileUtils {

    public static String[] parseCSVLine(String line) {
        List<String> result = new ArrayList<>();
        boolean inQuotes = false;
        StringBuilder currentField = new StringBuilder();

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);

            if (c == '"') {
                // 处理转义的引号 (""表示一个引号)
                if (i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    currentField.append('"');
                    i++; // 跳过下一个引号
                } else {
                    // 切换引号状态
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                // 找到字段分隔符，当不在引号内时
                result.add(currentField.toString());
                currentField = new StringBuilder();
            } else {
                // 普通字符
                currentField.append(c);
            }
        }

        // 添加最后一个字段
        result.add(currentField.toString());

        return result.toArray(new String[0]);
    }


    public static void exportToJsonFile(String filePath, List<RequestResponseInfo> dataToExport) throws IOException {
        log.info("开始导出数据，类型: json, 路径: {}", filePath);
        JSONArray jsonArray = new JSONArray();
        for (RequestResponseInfo info : dataToExport) {
            JSONObject obj = new JSONObject();
            obj.put("id", info.getId());
            obj.put("url", info.getUrl());
            obj.put("method", info.getMethod());
            obj.put("status", info.getStatusCode());
            obj.put("requestHeaders", info.getRequestHeaders() != null ? info.getRequestHeaders() : "");
            obj.put("requestBody", info.getRequestBody() != null ? info.getRequestBody() : "");
            obj.put("responseBody", info.getResponseBody() != null ? info.getResponseBody() : "");
            jsonArray.add(obj);
        }
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                Files.newOutputStream(Paths.get(filePath)), StandardCharsets.UTF_8))) {
            // 写入 UTF-8 BOM
            writer.write('\uFEFF');
            // 美化格式输出 JSON
            writer.write(jsonArray.toJSONString(JSONWriter.Feature.PrettyFormat));
        }
        log.info("✅ JSON 导出完成:{} ", filePath);
    }

    /**
     * 转义CSV字段中的特殊字符，确保CSV格式正确
     * 同时移除所有换行符，确保每行只包含一个请求记录
     *
     * @param field 要转义的字段内容
     * @return 转义后的字段内容
     */
    public static String escapeCsvField(String field) {
        if (field == null) {
            return "";
        }

        // 首先移除所有换行符和回车符，确保内容不会换行
        // 使用更可靠的替换方式，处理各种可能的换行符组合
        field = field.replace("\r\n", " ")
                .replace("\n\r", " ")
                .replace("\r", " ")
                .replace("\n", " ")
                .replace("\u2028", " ")  // 行分隔符
                .replace("\u2029", " "); // 段落分隔符

        // 移除制表符，防止格式混乱
        field = field.replace("\t", " ");

        // 如果字段包含逗号、引号或其他可能导致CSV解析问题的字符，需要用引号包围并转义内部引号
        if (field.contains(",") || field.contains("\"") || field.contains(";")) {
            return "\"" + field.replace("\"", "\"\"") + "\"";
        }
        return field;
    }


    /**
     * 尝试用不同编码读取文件内容，解决中文乱码问题
     *
     * @param filePath 文件路径
     * @return 文件内容，按行分割
     * @throws IOException 文件读取异常
     */
    public static String[] readFileWithMultipleEncodings(String filePath) throws IOException {
        // 尝试不同的编码
        Charset[] charsets = {StandardCharsets.UTF_8, Charset.forName("GBK"), Charset.forName("GB18030")};

        String content = null;
        IOException lastException = null;

        // 首先尝试直接读取文件的前几个字节检测BOM
        byte[] bom = new byte[4];
        try (FileInputStream fis = new FileInputStream(filePath)) {
            int read = fis.read(bom, 0, 4);
            if (read >= 3 && bom[0] == (byte) 0xEF && bom[1] == (byte) 0xBB && bom[2] == (byte) 0xBF) {
                // UTF-8 with BOM
                log.info("检测到UTF-8 BOM标记，使用UTF-8编码读取");
                try {
                    content = readFileWithEncoding(filePath, StandardCharsets.UTF_8, true);
                    return content.split("\n");
                } catch (IOException e) {
                    log.warn("使用UTF-8(BOM)读取失败，尝试其他编码", e);
                }
            }
        } catch (IOException e) {
            log.warn("检测BOM失败", e);
        }

        // 如果BOM检测失败，依次尝试不同编码读取文件
        for (Charset charset : charsets) {
            try {
                content = readFileWithEncoding(filePath, charset, false);

                // 检测内容是否有乱码特征
                if (containsGarbledText(content)) {
                    log.info("使用 " + charset.name() + " 编码读取可能存在乱码，尝试其他编码");
                    continue;
                }

                // 如果没有明显乱码，使用此编码读取的内容
                log.info("成功使用编码 " + charset.name() + " 读取文件");
                break;
            } catch (IOException e) {
                lastException = e;
                log.warn("使用 " + charset.name() + " 读取失败", e);
            }
        }

        // 如果所有编码都失败，抛出最后一个异常
        if (content == null && lastException != null) {
            throw lastException;
        }

        // 返回按行分割的内容
        return content != null ? content.split("\n") : new String[0];
    }

    /**
     * 使用指定编码读取文件内容
     *
     * @param filePath 文件路径
     * @param charset  字符集
     * @param skipBom  是否跳过BOM标记
     * @return 文件内容
     * @throws IOException 文件读取异常
     */
    private static String readFileWithEncoding(String filePath, Charset charset, boolean skipBom) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(filePath), charset))) {
            String line;
            boolean firstLine = true;
            while ((line = reader.readLine()) != null) {
                // 如果是第一行且需要跳过BOM，则检查并移除BOM
                if (firstLine && skipBom && line.startsWith("\uFEFF")) {
                    line = line.substring(1);
                }
                firstLine = false;

                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    /**
     * 检测文本是否包含乱码特征
     *
     * @param text 要检测的文本
     * @return 是否包含乱码
     */
    private static boolean containsGarbledText(String text) {
        if (text == null || text.isEmpty()) {
            return false;
        }

        // 检查常见的乱码特征
        if (text.contains("") || text.contains("锘") || text.contains("鈥")) {
            return true;
        }

        // 检查连续的无意义字符组合
        if (text.matches(".*[锘垮簭鍙嗚瘉閿欓敊]{5,}.*")) {
            return true;
        }

        // 统计不可打印字符的比例
        int nonPrintable = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
                nonPrintable++;
            }
        }

        // 如果不可打印字符比例过高，认为是乱码
        return nonPrintable > text.length() * 0.1;
    }
}
