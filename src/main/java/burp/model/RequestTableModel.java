package burp.model;

import burp.RequestResponseInfo;
import lombok.extern.slf4j.Slf4j;

import javax.swing.table.AbstractTableModel;
import java.util.List;

@Slf4j
// 表格模型
public class RequestTableModel extends AbstractTableModel {
    private final String[] columnNames = {"选择", "序号", "URL", "方法", "状态码"};

    private final List<RequestResponseInfo> capturedData;

    public RequestTableModel(List<RequestResponseInfo> capturedData) {
        this.capturedData = capturedData;
    }

    /**
     * 获取表格行数
     *
     * @return 表格行数
     */
    @Override
    public int getRowCount() {
        return capturedData.size();
    }

    /**
     * 获取表格列数
     *
     * @return 表格列数
     */
    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    /**
     * 获取列名
     *
     * @param column 列索引
     * @return 列名
     */
    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    /**
     * 获取列的数据类型
     *
     * @param column 列索引
     * @return 列的数据类型
     */
    @Override
    public Class<?> getColumnClass(int column) {
        if (column == 0) return Boolean.class;
        if (column == 1 || column == 4) return Integer.class;
        return String.class;
    }

    /**
     * 判断单元格是否可编辑
     *
     * @param row    行索引
     * @param column 列索引
     * @return 如果可编辑则返回true，否则返回false
     */
    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 0; // 只有选择列可编辑
    }

    /**
     * 获取单元格的值
     *
     * @param row    行索引
     * @param column 列索引
     * @return 单元格的值
     */
    @Override
    public Object getValueAt(int row, int column) {
        if (row < 0 || row >= capturedData.size()) {
            return null; // 防止索引越界
        }

        RequestResponseInfo info = capturedData.get(row);
        switch (column) {
            case 0:
                return info.isSelected();
            case 1:
                return info.getId();
            case 2:
                return info.getUrl();
            case 3:
                return info.getMethod();
            case 4:
                return info.getStatusCode();
            default:
                return null;
        }
    }

    /**
     * 设置单元格的值
     *
     * @param value  要设置的值
     * @param row    行索引
     * @param column 列索引
     */
    @Override
    public void setValueAt(Object value, int row, int column) {
        if (column == 0 && value instanceof Boolean && row >= 0 && row < capturedData.size()) {
            RequestResponseInfo info = capturedData.get(row);
            info.setSelected((Boolean) value);
            fireTableCellUpdated(row, column);
            log.info("设置记录 " + info.getId() + " 的选中状态为: " + value);
        }
    }
}