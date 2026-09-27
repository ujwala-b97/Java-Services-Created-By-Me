package com.graylog;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONObject;

public class NotifySiemServer{
        private static final Logger logger = Logger.getLogger(NotifySiemServer.class.getName());
    private static Properties properties = new Properties();
    private static String siemApiEndpoint;
    private static String siemEnrichmentEndpoint;
    // Load configuration from properties file
    static {
        loadConfig();
    }
    // Load the properties file and get the API endpoint
    private static void loadConfig(){
        String filePath = System.getProperty("os.name").toLowerCase().contains("win") 
                            ? "D:\\QueueBasedArchitecture\\queue_config.properties" 
                            : "/opt/AutoAlarmConfigFiles/queue_config.propertiesV4.1"; 
        
        try (InputStream input = new FileInputStream(filePath)) {
            properties.load(input);
            siemApiEndpoint = properties.getProperty("siem_notification_endpoint");
            if (siemApiEndpoint == null || siemApiEndpoint.isEmpty()) {
                throw new IllegalStateException("SIEM API endpoint is not configured in the properties file.");
            }
        } catch (IOException e){
            logger.log(Level.SEVERE, "Error loading properties file: " + e.getMessage(), e);
        } catch (IllegalStateException e) {
            logger.log(Level.SEVERE, "Configuration error: " + e.getMessage(), e);
        } 
        siemEnrichmentEndpoint =
        	    properties.getProperty(
        	        "siem_enrichment_endpoint"
        	    );
    }

    // Method to notify the SIEM server with provided details
    public static void notifySIEMServer(String caseId, String caseStatus, String alarmId, String label){
        HttpURLConnection connection = null;
        try {
            // Construct the complete URL with encoded query parameters
            String completeUrl = buildUrl(caseId, caseStatus, alarmId, label);
            logger.info("Complete URL: " + completeUrl);

            // Open HTTP connection
            connection = (HttpURLConnection) new URL(completeUrl).openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            // Prepare and send JSON payload
            String jsonData = buildJsonPayload(caseId, caseStatus, alarmId, label);
            sendJsonPayload(connection, jsonData);

            // Handle the server response
            int responseCode = connection.getResponseCode();
            logger.info("HTTP Response Code: " + responseCode);

            handleResponse(connection, responseCode);

        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error notifying SIEM server: " + e.getMessage(), e);
        }finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    //Build the URL with query parameters
    private static String buildUrl(String caseId, String caseStatus, String alarmId, String label) throws UnsupportedEncodingException {
        return String.format("%s?case_id=%s&case_status=%s&alarm_id=%s&label=%s",
                siemApiEndpoint,
                URLEncoder.encode(caseId),
                URLEncoder.encode(caseStatus),
                URLEncoder.encode(alarmId),
                URLEncoder.encode(label));
    }

    // Build JSON payload
    private static String buildJsonPayload(String caseId, String caseStatus, String alarmId, String label) {
        return String.format(
            "{\"case_id\":\"%s\",\"case_status\":\"%s\",\"alarm_id\":\"%s\",\"label\":\"%s\"}",
            caseId, caseStatus, alarmId, label);
    }

    //Added new Raw_log Parser
    public static void notifyEnrichedAlarm(
            JSONObject enrichedJson
    ){
        HttpURLConnection connection = null;

        try {

            logger.info(
                "Sending Enriched Alarm To SIEM"
            );

            enrichedJson.remove("all_ips");
            enrichedJson.remove("all_fields");
            enrichedJson.remove("raw_response");
            enrichedJson.remove("enrichment_status");

            logger.info(
                enrichedJson.toString(4)
            );

            URL url =
                new URL(
                    siemEnrichmentEndpoint
                );

            connection =
                (HttpURLConnection)
                url.openConnection();

            connection.setRequestMethod(
                "POST"
            );

            connection.setRequestProperty(
                "Content-Type",
                "application/json"
            );

            connection.setDoOutput(
                true
            );

            try(
                OutputStream os =
                    connection.getOutputStream()
            ){

                byte[] input =
                    enrichedJson
                        .toString()
                        .getBytes(
                            StandardCharsets.UTF_8
                        );

                os.write(
                    input,
                    0,
                    input.length
                );
            }

            int responseCode =
                connection.getResponseCode();

            logger.info(
                "Enrichment Response Code : "
                + responseCode
            );

            handleResponse(
                connection,
                responseCode
            );

        }
        catch(Exception e){

            logger.log(
                Level.SEVERE,
                "Error sending enriched alarm",
                e
            );
        }
        finally{

            if(connection != null){

                connection.disconnect();
            }
        }
    }
    
    // Send JSON data to the SIEM server
    private static void sendJsonPayload(HttpURLConnection connection, String jsonData) throws IOException {
        try (OutputStream os = connection.getOutputStream()) {
            byte[] input = jsonData.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        } 
    }
    // Handle the response from the SIEM server
    private static void handleResponse(HttpURLConnection connection, int responseCode) throws IOException{
        if (responseCode == HttpURLConnection.HTTP_OK) {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null){
                    response.append(responseLine.trim());
                }
                logger.info("SIEM Server Response: " + response.toString());
            }
        }else {
            logger.severe("Failed to notify SIEM server. HTTP response code: " + responseCode);
            try (BufferedReader errorReader = new BufferedReader(new InputStreamReader(connection.getErrorStream()))) {
                StringBuilder errorResponse = new StringBuilder();
                String errorLine;
                while ((errorLine = errorReader.readLine()) != null) {
                    errorResponse.append(errorLine.trim());
                }
                logger.severe("Error Response: " + errorResponse.toString());
            }
        }
    }
}
