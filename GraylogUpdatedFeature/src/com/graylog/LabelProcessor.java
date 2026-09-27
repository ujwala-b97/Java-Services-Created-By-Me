package com.graylog;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class LabelProcessor {
   private final Set<String> seenLabels = new HashSet();
   private final String apiServerUrl;
   private final String username;
   private final String password;
   private final Properties properties;

   public LabelProcessor(String apiServerUrl, String username, String password, Properties properties) {
      this.apiServerUrl = apiServerUrl;
      this.username = username;
      this.password = password;
      this.properties = properties;
   }

   public void processLabel(String inputID, String ticketID, String ticketStatus, String Label_status, ApiCall apiCall, AlarmsPramExtractor alarmsPramExtractor, NotifySiemServer notifySiemServer) throws Exception {
      System.out.println("Processing Alarm ID: " + ticketID + ", Label: " + ticketStatus + ", label_status: " + Label_status);
      String apiendpoint = this.properties.getProperty("api_endpoint_AlarmId") + ticketID;
      String response1 = ApiCall.callAPIOpenticket(apiendpoint);
      String query;
      String encodedQuery;
      String apiUrl;
      String response;
      JSONObject jsonObject;
      JSONArray messagesArray;
      String label;
      if ("Remove".equalsIgnoreCase(Label_status)) {
         System.out.println("Checking Graylog for matching alarms...");
         query = "gl2_source_input:" + inputID + " && Label:\"" + ticketStatus + "\" && Backlog_id:\"" + ticketID + "\"";
         encodedQuery = URLEncoder.encode(query, StandardCharsets.UTF_8.toString());
         apiUrl = this.apiServerUrl + "?query=" + encodedQuery + "&range=0&decorate=true";
         System.out.println("Graylog API URL: " + apiUrl);

         try {
            response = apiCall.callAPI(apiUrl, this.username, this.password);
         } catch (IOException var23) {
            System.err.println("Error during API call to Graylog: " + var23.getMessage());
            var23.printStackTrace();
            return;
         }

         System.out.println("Graylog Response: " + response);
         jsonObject = new JSONObject(response);
         messagesArray = jsonObject.getJSONArray("messages");
         if (messagesArray.length() > 0) {
            System.out.println("Matching alarms found in Graylog. Updating Label...");

            for(int i = 0; i < messagesArray.length(); ++i) {
               JSONObject messageObject = messagesArray.getJSONObject(i);
               String documentId = messageObject.getJSONObject("message").getString("_id");
               label = messageObject.getString("index");
               String fullMessage = messageObject.getJSONObject("message").getString("message");
               String updatedMessage = fullMessage.replaceAll("\"label\":\"[^\"]*\"", "\"label\":null");
               System.out.println("Updating Document ID: " + documentId + " in Index: " + label);
               this.updateElasticsearchLabel(documentId, label, this.properties.getProperty("server_ip"), updatedMessage);
            }
         } else {
            System.out.println("No matching alarms found in Graylog. Proceeding to another feature...");
         }
      } else if (Label_status == null || Label_status.isEmpty()) {
         try {
            query = "gl2_source_input:" + inputID + " && Label:\"" + ticketStatus + "\"";
            encodedQuery = URLEncoder.encode(query, StandardCharsets.UTF_8.toString());
            apiUrl = this.apiServerUrl + "?query=" + encodedQuery + "&range=0&decorate=true";
            System.out.println("Graylog API URL: " + apiUrl);

            try {
               response = apiCall.callAPI(apiUrl, this.username, this.password);
            } catch (IOException var22) {
               System.err.println("Error during API call to Graylog: " + var22.getMessage());
               var22.printStackTrace();
               return;
            }

            if (response != null) {
               try {
                  jsonObject = new JSONObject(response);
                  messagesArray = jsonObject.getJSONArray("messages");
                  if (messagesArray.length() > 0) {
                     boolean labelFound = false;

                     for(int i = 0; i < messagesArray.length(); ++i) {
                        try {
                           JSONObject messageObject = messagesArray.getJSONObject(i);
                           label = messageObject.getJSONObject("message").optString("Label", (String)null);
                           System.out.println("Extracted Label: " + label);
                           if (label != null && !label.isEmpty()) {
                              if (this.seenLabels.contains(label)) {
                                 System.out.println("Duplicate label found: " + label);
                                 this.processDuplicateLabel(ticketID, ticketStatus, apiCall, alarmsPramExtractor, notifySiemServer);
                                 labelFound = true;
                                 break;
                              }

                              this.seenLabels.add(label);
                              System.out.println("Unique label found: " + label);
                           } else {
                              System.out.println("Label is null or empty.");
                           }
                        } catch (JSONException var24) {
                           System.err.println("Error parsing JSON message object: " + var24.getMessage());
                           var24.printStackTrace();
                        }
                     }

                     if (!labelFound) {
                        this.sendDataToGraylog(response1);
                     }
                  } else {
                     System.out.println("No messages found in Graylog response.");
                     this.sendDataToGraylog(response1);
                  }
               } catch (JSONException var25) {
                  System.err.println("Error parsing JSON response from Graylog: " + var25.getMessage());
                  var25.printStackTrace();
               }
            }
         } catch (Exception var26) {
            System.err.println("Unexpected error in 'Labelling' process: " + var26.getMessage());
            var26.printStackTrace();
         }
      }

   }

   private void sendDataToGraylog(String response) {
      DatagramSocket socket = null;

      try {
         String serverIp = this.properties.getProperty("server_ip");
         int sendPort = Integer.parseInt(this.properties.getProperty("send_port"));
         System.out.println("Sending data to Graylog. Server IP: " + serverIp + ", Port: " + sendPort);
         socket = new DatagramSocket();
         InetAddress serverAddress = InetAddress.getByName(serverIp);
         byte[] sendData = response.getBytes();
         DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, serverAddress, sendPort);
         socket.send(sendPacket);
         System.out.println("Data successfully sent to Graylog");
      } catch (IOException var11) {
         System.err.println("Error while sending data to Graylog: " + var11.getMessage());
         var11.printStackTrace();
      } finally {
         if (socket != null && !socket.isClosed()) {
            socket.close();
            System.out.println("Socket closed.");
         }

      }

   }

   public void updateElasticsearchLabel(String documentId, String indexName, String serverIp, String updatedMessage) {
      try {
         String elasticsearchUrl = "http://" + serverIp + ":9200/" + indexName + "/_doc/" + documentId + "/_update";
         String escapedMessage = escapeJsonString(updatedMessage);
         String[] curlCommand = new String[]{"curl", "-X", "POST", elasticsearchUrl, "-H", "Content-Type: application/json", "-u", "admin:admin", "-d", "{\n  \"doc\": {\n    \"message\": \"" + escapedMessage + "\",\n" + "    \"Label\": null\n" + "  }\n" + "}"};
         System.out.println("Executing curl command:");
         String[] var11 = curlCommand;
         int exitCode = curlCommand.length;

         for(int var9 = 0; var9 < exitCode; ++var9) {
            String cmd = var11[var9];
            System.out.print(cmd + " ");
         }

         System.out.println();
         ProcessBuilder processBuilder = new ProcessBuilder(curlCommand);
         Process process = processBuilder.start();
         exitCode = process.waitFor();
         if (exitCode == 0) {
            System.out.println("Label removed successfully from both extractor & message field.");
         } else {
            System.out.println("Error updating label field.");
         }
      } catch (InterruptedException | IOException var12) {
         System.err.println("Error executing curl command: " + var12.getMessage());
         var12.printStackTrace();
      }

   }

   public static String escapeJsonString(String jsonString) {
      return jsonString.replace("\\", "\\\\").replace("\"", "\\\"");
   }

   private void processDuplicateLabel(String alarm_id, String label, ApiCall apiCall, AlarmsPramExtractor alarmsPramExtractor, NotifySiemServer notifySiemServer) {
      try {
         String siemApiEndpoint = this.properties.getProperty("api_endpoint_AlarmId") + alarm_id;
         String inputID = this.properties.getProperty("input_id");
         String query = "gl2_source_input:" + inputID + " && Label:\"" + label + "\"";
         String encodedQuery = URLEncoder.encode(query, StandardCharsets.UTF_8.toString());
         String apiUrl = this.apiServerUrl + "?query=" + encodedQuery + "&range=0&decorate=true";
         System.out.println("Graylog API URL: " + apiUrl);
         String response = apiCall.callAPI(apiUrl, this.username, this.password);

         String siemResponse;
         try {
            siemResponse = ApiCall.callAPIOpenticket(siemApiEndpoint);
         } catch (IOException var22) {
            System.err.println("Error while calling SIEM API: " + var22.getMessage());
            var22.printStackTrace();
            return;
         }

         try {
            alarmsPramExtractor.extractAndPrintParameters(siemResponse);
            AlarmsPramExtractor.extractAlarmDetails(response);
         } catch (Exception var21) {
            System.err.println("Error while extracting alarm parameters: " + var21.getMessage());
            var21.printStackTrace();
         }

         boolean isDuplicateAlarm = AlarmsPramExtractor.compareAlarmDetails(siemResponse, response);
         if (isDuplicateAlarm) {
            System.out.println("Duplicate alarm found. Extracting matched alarm parameters...");

            try {
               JSONObject graylogJson = new JSONObject(response);
               JSONArray graylogMessages = graylogJson.optJSONArray("messages");
               if (graylogMessages != null) {
                  for(int i = 0; i < graylogMessages.length(); ++i) {
                     JSONObject messageObject = graylogMessages.getJSONObject(i);
                     JSONObject fields = messageObject.optJSONObject("message");
                     if (fields != null && fields.optString("Label", "").equals(label)) {
                        String case_id = fields.optString("Ticket_id", "N/A");
                        String case_status = fields.optString("Alarm_Status", "N/A");
                        System.out.println("Matched Alarm Parameters:");
                        System.out.println("Case ID: " + case_id);
                        System.out.println("Case Status: " + case_status);
                        System.out.println("Label: " + label);
                        System.out.println("alarm_id:" + alarm_id);
                        System.out.println("Calling notifySIEMServer with caseId: " + case_id + ", caseStatus: " + case_status + ", alarmId: " + alarm_id + ", label: " + label);
                        NotifySiemServer.notifySIEMServer(case_id, case_status, alarm_id, label);
                        System.out.println("Notified successsfully");
                     }
                  }
               } else {
                  System.err.println("No messages found in Graylog response.");
               }
            } catch (Exception var23) {
               System.err.println("Error extracting matched alarm parameters: " + var23.getMessage());
               var23.printStackTrace();
            }
         }
      } catch (Exception var24) {
         System.err.println("Error processing duplicate label: " + var24.getMessage());
         var24.printStackTrace();
      }

   }
}