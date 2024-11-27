package com.negative.massassignment;

import burp.*;
import org.json.JSONObject;
import org.json.XML;
import javax.swing.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class MassAssignment implements IBurpExtender, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Mass Assignment");
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
        if (selectedMessages == null || selectedMessages.length == 0) {
            return menuItems;
        }

        IHttpRequestResponse message = selectedMessages[0];
        IRequestInfo requestInfo = helpers.analyzeRequest(message.getRequest());
        String body = new String(message.getRequest()).substring(requestInfo.getBodyOffset());


        String contentType = getContentType(requestInfo);

        if ("application/x-www-form-urlencoded".equalsIgnoreCase(contentType)) {
            menuItems.add(createMenuItem("Convert Form to JSON", body, this::formToJson, message, "application/json"));
            menuItems.add(createMenuItem("Convert Form to XML", body, this::formToXml, message, "application/xml"));
        } else if ("application/json".equalsIgnoreCase(contentType)) {
            menuItems.add(createMenuItem("Convert JSON to Form", body, this::jsonToForm, message, "application/x-www-form-urlencoded"));
            menuItems.add(createMenuItem("Convert JSON to XML", body, this::jsonToXml, message, "application/xml"));
        } else if ("application/xml".equalsIgnoreCase(contentType)) {
            menuItems.add(createMenuItem("Convert XML to Form", body, this::xmlToForm, message, "application/x-www-form-urlencoded"));
            menuItems.add(createMenuItem("Convert XML to JSON", body, this::xmlToJson, message, "application/json"));
        }

        return menuItems;
    }

    private String getContentType(IRequestInfo requestInfo) {
        for (String header : requestInfo.getHeaders()) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.split(":")[1].trim();
            }
        }
        return "";
    }

    private JMenuItem createMenuItem(String label, String body, ConversionFunction function, IHttpRequestResponse message, String newContentType) {
        JMenuItem menuItem = new JMenuItem(label);
        menuItem.addActionListener(e -> {
            try {

                String convertedBody = function.convert(body);


                List<String> headers = new ArrayList<>(helpers.analyzeRequest(message.getRequest()).getHeaders());
                updateContentType(headers, newContentType);


                byte[] newRequest = helpers.buildHttpMessage(headers, convertedBody.getBytes(StandardCharsets.UTF_8));
                message.setRequest(newRequest);
            } catch (Exception ex) {
                callbacks.printError("Error: " + ex.getMessage());
            }
        });
        return menuItem;
    }

    private void updateContentType(List<String> headers, String newContentType) {
        boolean found = false;


        for (int i = 0; i < headers.size(); i++) {
            if (headers.get(i).toLowerCase().startsWith("content-type:")) {
                headers.set(i, "Content-Type: " + newContentType);
                found = true;
                break;
            }
        }


        if (!found) {
            headers.add("Content-Type: " + newContentType);
        }
    }


    private String formToJson(String body) {
        JSONObject json = new JSONObject();
        String decoded = URLDecoder.decode(body, StandardCharsets.UTF_8);
        for (String pair : decoded.split("&")) {
            String[] keyValue = pair.split("=");
            json.put(keyValue[0], keyValue.length > 1 ? keyValue[1] : "");
        }
        return json.toString();
    }

    private String formToXml(String body) {
        return XML.toString(new JSONObject(formToJson(body)));
    }

    private String jsonToForm(String body) {
        JSONObject json = new JSONObject(body);
        StringBuilder form = new StringBuilder();
        for (String key : json.keySet()) {
            form.append(key).append("=").append(json.get(key)).append("&");
        }
        return form.substring(0, form.length() - 1);
    }

    private String jsonToXml(String body) {
        return XML.toString(new JSONObject(body));
    }

    private String xmlToForm(String body) {
        JSONObject json = XML.toJSONObject(body);
        return jsonToForm(json.toString());
    }

    private String xmlToJson(String body) {
        return XML.toJSONObject(body).toString();
    }

    @FunctionalInterface
    private interface ConversionFunction {
        String convert(String input);
    }
}