package burp;

/**
 * 此接口用于自定义Intruder工具的有效载荷处理
 */
public interface IIntruderPayloadProcessor
{
    /**
     * 获取处理器名称
     * 
     * @return 处理器名称
     */
    String getProcessorName();
    
    /**
     * 处理Intruder有效载荷
     * 
     * @param currentPayload 当前有效载荷
     * @param originalPayload 原始有效载荷
     * @param baseValue 基础值
     * @return 处理后的有效载荷
     */
    byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue);
} 