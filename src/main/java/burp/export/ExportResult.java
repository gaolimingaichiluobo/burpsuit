package burp.export;

import burp.result.AuthTestResult;
import burp.result.CsrfTestResult;
import burp.result.PrivilegeEscalationResult;
import burp.result.UnsafeMethodTestResult;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;


@Slf4j
public class ExportResult {

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
     * 将未授权测试结果导出到CSV文件
     *
     * @param filePath 导出文件路径
     * @throws IOException 文件写入异常
     */
    public static void exportAuthTestResultsToCSV(String filePath,List<AuthTestResult> authTestResults) throws IOException {
        log.info("开始导出未授权测试结果，路径: {}", filePath);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            // CSV标题行
            writer.write("URL,状态码,测试结果");
            writer.newLine();

            // 写入数据
            for (AuthTestResult result : authTestResults) {
                StringBuilder line = new StringBuilder();
                line.append(escapeCsvField(result.getUrl())).append(",");
                line.append(result.getStatusCode()).append(",");

                String resultText;
                if (result.isVulnerable()) {
                    resultText = "存在未授权访问漏洞";
                } else if (result.isNeedsConfirmation()) {
                    resultText = "需要人工确认";
                } else {
                    resultText = "安全";
                }
                line.append(escapeCsvField(resultText));

                writer.write(line.toString());
                writer.newLine();
            }
        }
        log.info("未授权测试结果导出完成");
    }
    /**
     * 将CSRF测试结果导出为CSV文件
     */
    public static void exportCsrfTestResultsToCSV(String filePath,List<CsrfTestResult> csrfTestResults) throws IOException {
        log.info("开始导出CSRF测试结果，路径: " + filePath);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            // CSV标题行
            writer.write("ID,URL,状态码,测试结果,修改的Referer\n");

            // 写入数据行
            for (CsrfTestResult result : csrfTestResults) {
                StringBuilder sb = new StringBuilder();
                sb.append(result.getId()).append(",");
                sb.append(escapeCsvField(result.getUrl())).append(",");
                sb.append(result.getStatusCode()).append(",");

                String testResult;
                if (result.isVulnerable()) {
                    testResult = "存在CSRF漏洞";
                } else if (result.isNeedsConfirmation()) {
                    testResult = "需要确认";
                } else {
                    testResult = "安全";
                }

                sb.append(escapeCsvField(testResult)).append(",");
                sb.append(escapeCsvField(result.getModifiedReferer())).append("\n");

                writer.write(sb.toString());
            }
        }
        log.info("CSRF测试结果导出完成");
    }
    /**
     * 将不安全HTTP方法测试结果导出为CSV文件
     */
    public static void exportUnsafeMethodTestResultsToCSV(String filePath, List<UnsafeMethodTestResult> unsafeMethodTestResults) throws IOException {
        log.info("开始导出不安全HTTP方法测试结果，路径: " + filePath);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            // CSV标题行
            writer.write("ID,URL,原始方法,修改方法,状态码,测试结果\n");

            // 写入数据行
            for (UnsafeMethodTestResult result : unsafeMethodTestResults) {
                StringBuilder sb = new StringBuilder();
                sb.append(result.getId()).append(",");
                sb.append(escapeCsvField(result.getUrl())).append(",");
                sb.append(escapeCsvField(result.getOriginalMethod())).append(",");
                sb.append(escapeCsvField(result.getModifiedMethod())).append(",");
                sb.append(result.getStatusCode()).append(",");

                String testResult;
                if (result.isVulnerable()) {
                    testResult = "存在不安全请求漏洞";
                } else if (result.isNeedsConfirmation()) {
                    testResult = "需要确认";
                } else {
                    testResult = "安全";
                }

                sb.append(escapeCsvField(testResult)).append("\n");

                writer.write(sb.toString());
            }
        }
        log.info("不安全HTTP方法测试结果导出完成");
    }
    /**
     * 将越权测试结果导出到CSV文件
     *
     * @param filePath 导出文件路径
     * @throws IOException 文件写入异常
     */
    public static void exportPrivilegeEscalationResultsToCSV(String filePath, List<PrivilegeEscalationResult> privilegeEscalationResults) throws IOException {
        log.info("开始导出越权测试结果，路径: " + filePath);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            // CSV标题行
            writer.write("URL,测试类型,测试内容,原始会话,测试会话,原始状态码,测试状态码,测试结果");
            writer.newLine();

            // 写入数据
            for (PrivilegeEscalationResult result : privilegeEscalationResults) {
                StringBuilder line = new StringBuilder();
                // 使用已过滤的URL进行导出
                line.append(escapeCsvField(result.getUrl())).append(",");
                line.append(escapeCsvField(result.getTestType())).append(",");
                line.append(escapeCsvField(result.getParamName())).append(",");

                if (result.getOriginalSession() != null) {
                    line.append(escapeCsvField(result.getOriginalSession().getName())).append(",");
                } else {
                    line.append(",");
                }

                if (result.getModifiedSession() != null) {
                    line.append(escapeCsvField(result.getModifiedSession().getName())).append(",");
                } else {
                    line.append(",");
                }

                line.append(result.getOriginalStatusCode()).append(",");
                line.append(result.getModifiedStatusCode()).append(",");

                String resultText;
                if (result.isVulnerable()) {
                    resultText = "存在越权漏洞";
                } else if (result.isNeedsConfirmation()) {
                    resultText = "需要人工确认";
                } else {
                    resultText = "安全";
                }
                line.append(escapeCsvField(resultText));

                writer.write(line.toString());
                writer.newLine();
            }
        }
        log.info("越权测试结果导出完成");
    }
}
