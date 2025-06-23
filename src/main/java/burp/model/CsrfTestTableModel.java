package burp.model;


import burp.result.CsrfTestResult;
import lombok.extern.slf4j.Slf4j;

import javax.swing.table.AbstractTableModel;
import java.util.List;

@Slf4j
/**
 * CSRF测试表格模型
 */
public class CsrfTestTableModel extends AbstractTableModel {
    private final String[] columnNames = {"选择", "序号", "URL", "状态码", "测试结果", "修改的Referer", "判定原因"};

    private final List<CsrfTestResult> csrfTestResults;

    public CsrfTestTableModel(List<CsrfTestResult> csrfTestResults) {
        this.csrfTestResults = csrfTestResults;
    }

    @Override
    public int getRowCount() {
        return csrfTestResults.size();
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
        if (column == 0) {
            return Boolean.class;
        } else if (column == 1 || column == 3) {
            return Integer.class;
        } else {
            return String.class;
        }
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 0;
    }

    @Override
    public Object getValueAt(int row, int column) {
        CsrfTestResult result = csrfTestResults.get(row);
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
                    return "存在CSRF漏洞";
                } else if (result.isNeedsConfirmation()) {
                    return "需要确认";
                } else {
                    return "安全";
                }
            case 5:
                return result.getModifiedReferer();
            case 6:
                return result.getResultReson();
            default:
                return "";
        }
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        if (column == 0 && value instanceof Boolean) {
            CsrfTestResult result = csrfTestResults.get(row);
            result.setSelected((Boolean) value);
            fireTableCellUpdated(row, column);
            log.info("设置测试结果 " + result.getId() + " 的选中状态为: " + value);
        }
    }
}