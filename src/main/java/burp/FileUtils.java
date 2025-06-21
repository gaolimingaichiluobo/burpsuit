package burp;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class FileUtils {

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
}
