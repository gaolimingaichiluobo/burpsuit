package burp.model;


import burp.result.AuthTestResult;
import lombok.extern.slf4j.Slf4j;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * 未授权测试结果表格模型
 */
@Slf4j
public class AuthTestTableModel extends AbstractTableModel {
    private final String[] columnNames = {"选择", "序号", "URL", "状态码", "测试结果", "判定原因"};
    private final List<AuthTestResult> authTestResults;

    public AuthTestTableModel(List<AuthTestResult> authTestResults) {
        this.authTestResults = authTestResults;
    }

    @Override
    public int getRowCount() {
        return authTestResults.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        if (column == 0) return Boolean.class;
        if (column == 2) return String.class;
        if (column == 1 || column == 3) return Integer.class;
        return String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 0; // 只有选择列可编辑
    }

    @Override
    public Object getValueAt(int row, int column) {
        AuthTestResult result = authTestResults.get(row);
        switch (column) {
            case 0:
                return result.isSelected();
            case 1:
                // 使用行索引+1作为序号，而不是依赖对象中存储的ID
                return row + 1;
            case 2:
                return result.getUrl();
            case 3:
                return result.getStatusCode();
            case 4:
                if (result.isVulnerable()) {
                    return "存在未授权访问漏洞";
                } else if (result.isNeedsConfirmation()) {
                    return "需要人工确认";
                } else {
                    return "安全";
                }
            case 5:
                return result.getResultReson();
            default:
                return "";
        }
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        if (column == 0 && value instanceof Boolean && row >= 0 && row < authTestResults.size()) {
            AuthTestResult result = authTestResults.get(row);
            result.setSelected((Boolean) value);
            fireTableCellUpdated(row, column);
            log.info("设置测试结果 " + result.getId() + " 的选中状态为: " + value);
        }
    }
}