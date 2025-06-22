package burp.http;

import burp.IHttpRequestResponse;
import burp.IHttpService;

/**
 * 虚拟HTTP请求响应实现类
 */
public class DummyHttpRequestResponse implements IHttpRequestResponse {
    private byte[] request;
    private byte[] response;
    private IHttpService httpService;

    public DummyHttpRequestResponse(byte[] request, byte[] response, IHttpService httpService) {
        this.request = request;
        this.response = response;
        this.httpService = httpService;
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}