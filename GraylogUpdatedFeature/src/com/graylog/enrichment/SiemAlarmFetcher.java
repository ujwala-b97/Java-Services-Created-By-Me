package com.graylog.enrichment;

import java.util.Properties;

import org.json.JSONArray;
import org.json.JSONObject;

import com.graylog.ApiCall;

public class SiemAlarmFetcher {

    private Properties properties;

    public SiemAlarmFetcher(Properties properties) {

        this.properties = properties;
    }

    public String getRowLog(
            String ticketID
    ) throws Exception {

        String apiEndpoint =
                properties.getProperty(
                        "api_endpoint_AlarmId"
                ) + ticketID;

        System.out.println(
                "[INFO] Calling SIEM API : "
                + apiEndpoint
        );

        String response =
                ApiCall.callAPIOpenticket(
                        apiEndpoint
                );

        JSONArray arr =
                new JSONArray(response);

        if(arr.length() == 0){

            return null;
        }

        JSONObject obj =
                arr.getJSONObject(0);

        return obj.optString(
                "rowlog",
                null
        );
    }
}