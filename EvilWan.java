package burp;

import java.io.IOException;
import java.net.URI;
import java.util.List;

import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, IHttpListener {

    private static final String WS_PROTOCOL = "ws://";
    private static final String WSS_PROTOCOL = "wss://";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private WebSocketClient wsClient;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("WebSocket URL Changer");

        callbacks.registerExtensionStateListener(this);
        callbacks.registerHttpListener(this);
    }

    @Override
    public void extensionUnloaded() {
        if (wsClient != null) {
            wsClient.close();
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest && (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER)) {
            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);

            // Check if the request is a POST request
            if (requestInfo.getMethod().equals("POST")) {
                // Get the request body bytes
                byte[] requestBytes = messageInfo.getRequest();
                int bodyOffset = requestInfo.getBodyOffset();
                byte[] requestBody = new byte[requestBytes.length - bodyOffset];
                System.arraycopy(requestBytes, bodyOffset, requestBody, 0, requestBody.length);

                // Convert the request body bytes to a string
                String requestBodyString = callbacks.getHelpers().bytesToString(requestBody);

                // Replace the URL in the request body
                String newRequestBodyString = requestBodyString.replaceAll("http://example.com", "https://www.msn.com");

                // Convert the modified request body string back to bytes
                byte[] newRequestBody = callbacks.getHelpers().stringToBytes(newRequestBodyString);

                // Update the request with the modified request body
                messageInfo.setRequest(callbacks.getHelpers().buildHttpMessage(requestInfo.getHeaders(), newRequestBody));
            }
        }
    }
}
