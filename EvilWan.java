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
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            List<String> upgradeHeader = messageInfo.getResponseHeaders().getHeaders("Upgrade");
            if (upgradeHeader != null && upgradeHeader.size() > 0 && upgradeHeader.get(0).equalsIgnoreCase("websocket")) {
                String host = helpers.analyzeRequest(messageInfo).getUrl().getHost();
                URI uri = URI.create(messageInfo.getHttpService().getProtocol() + "://" + host);
                wsClient = new WebSocketClient(uri) {

                    @Override
                    public void onOpen(ServerHandshake handshakedata) {
                        callbacks.printOutput("WebSocket connection established");
                    }

                    @Override
                    public void onMessage(String message) {
                        callbacks.printOutput("Received message from WebSocket server: " + message);
                    }

                    @Override
                    public void onClose(int code, String reason, boolean remote) {
                        callbacks.printOutput("WebSocket connection closed");
                    }

                    @Override
                    public void onError(Exception ex) {
                        callbacks.printError(ex.getMessage());
                    }
                };
                wsClient.connect();

                String request = new String(messageInfo.getRequest());
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                int bodyOffset = requestInfo.getBodyOffset();

                // Replace the URL in the WebSocket request
                String newRequest = request.substring(0, bodyOffset);
                String url = WS_PROTOCOL + host + requestInfo.getUrl().getFile();
                if (messageInfo.getHttpService().getProtocol().equals("https")) {
                    url = WSS_PROTOCOL + host + requestInfo.getUrl().getFile();
                }
                newRequest += url + request.substring(bodyOffset + requestInfo.getBodyLength());

                messageInfo.setRequest(newRequest.getBytes());
            }
        }
    }

}
