package burp;

/**
 * 此接口用于表示临时文件
 */
public interface ITempFile
{
    /**
     * 获取此临时文件的绝对路径
     * 
     * @return 临时文件的绝对路径
     */
    String getAbsolutePath();
    
    /**
     * 删除此临时文件
     */
    void delete();
} 