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

import static burp.FileUtils.escapeCsvField;

@Slf4j
public class ExportResult {

    /**
     * 将未授权测试结果导出到CSV文件
     *
     * @param filePath 导出文件路径
     * @throws IOException 文件写入异常
     */
    public static void exportAuthTestResultsToCSV(String filePath,List<AuthTestResult> authTestResults) throws IOException {
        log.info("开始导出未授权测试结果，路径: " + filePath);
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
