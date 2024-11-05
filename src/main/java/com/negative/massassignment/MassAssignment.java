package com.negative.massassignment;

import burp.*;
import org.json.JSONObject;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MassAssignment implements IBurpExtender, IContextMenuFactory {
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Form-JSON Converter");
        callbacks.registerContextMenuFactory(this);
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        JMenuItem formToJsonItem = new JMenuItem("Convert Form to JSON");
        formToJsonItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
                if (selectedMessages != null && selectedMessages.length > 0) {
                    IHttpRequestResponse message = selectedMessages[0];
                    IRequestInfo requestInfo = helpers.analyzeRequest(message.getRequest());
                    String body = new String(message.getRequest()).substring(requestInfo.getBodyOffset());
                    String jsonBody = FormToJson.convert(body);

                    List<String> headers = new ArrayList<>(requestInfo.getHeaders());
                    headers = updateContentType(headers, "application/json");

                    byte[] newRequest = helpers.buildHttpMessage(headers, jsonBody.getBytes());
                    message.setRequest(newRequest);
                }
            }
        });

        JMenuItem jsonToFormItem = new JMenuItem("Convert JSON to Form");
        jsonToFormItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
                if (selectedMessages != null && selectedMessages.length > 0) {
                    IHttpRequestResponse message = selectedMessages[0];
                    IRequestInfo requestInfo = helpers.analyzeRequest(message.getRequest());
                    String body = new String(message.getRequest()).substring(requestInfo.getBodyOffset());
                    String formBody = JsonToForm.convert(body, true);


                    List<String> headers = new ArrayList<>(requestInfo.getHeaders());
                    headers = updateContentType(headers, "application/x-www-form-urlencoded");

                    byte[] newRequest = helpers.buildHttpMessage(headers, formBody.getBytes());
                    message.setRequest(newRequest);
                }
            }
        });

        return List.of(formToJsonItem, jsonToFormItem);
    }

    private List<String> updateContentType(List<String> headers, String newContentType) {
        boolean contentTypeFound = false;
        for (int i = 0; i < headers.size(); i++) {
            if (headers.get(i).toLowerCase().startsWith("content-type:")) {
                headers.set(i, "Content-Type: " + newContentType);
                contentTypeFound = true;
                break;
            }
        }
        if (!contentTypeFound) {
            headers.add("Content-Type: " + newContentType);
        }
        return headers;
    }

    public static class FormToJson {
        public static String convert(String form) {
            Map<String, String> data = new HashMap<>();
            String decodedForm = URLDecoder.decode(form, StandardCharsets.UTF_8);
            for (String pair : decodedForm.split("&")) {
                String[] keyValue = pair.split("=");
                data.put(keyValue[0], keyValue.length > 1 ? keyValue[1] : "");
            }
            return new JSONObject(data).toString();
        }
    }

    public static class JsonToForm {
        public static String convert(String jsonData, boolean encode) {
            JSONObject data = new JSONObject(jsonData);
            StringBuilder query = new StringBuilder();

            for (String key : data.keySet()) {
                String value = data.getString(key);
                if ("true".equals(value)) value = "1";
                if ("false".equals(value)) value = "0";
                query.append("&").append(key).append("=").append(value);
            }

            String result = query.length() > 0 ? query.substring(1) : "";
            if (encode) {
                result = URLEncoder.encode(result, StandardCharsets.UTF_8);
                result = result.replace("%3D", "=").replace("%26", "&");
            }
            return result;
        }
    }
}