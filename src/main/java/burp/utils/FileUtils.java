package burp.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import burp.model.RequestResponseInfo;
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

}
