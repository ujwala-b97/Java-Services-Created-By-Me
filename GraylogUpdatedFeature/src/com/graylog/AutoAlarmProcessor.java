    package com.graylog;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.Map.Entry;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.graylog.enrichment.EnrichmentProcessor;

public class AutoAlarmProcessor {
   private final Set<String> seenAlarms = Collections.synchronizedSet(new HashSet());
   private final String apiServerUrl;
   private final String username;
   private final String password;
   private final Properties properties;
   private final ExecutorService executorService;

   public AutoAlarmProcessor(String apiServerUrl, String username, String password, Properties properties, int threadPoolSize) {
      this.apiServerUrl = apiServerUrl;
      this.username = username;
      this.password = password;
      this.properties = properties;
      this.executorService = Executors.newFixedThreadPool(threadPoolSize);
   }

   public boolean processAlarms(String inputID, String ticketIDList, ApiCall apiCall, AlarmsPramExtractor alarmsPramExtractor, NotifySiemServer notifySiemServer) {
      System.out.println("[INFO] Starting processAlarms for inputID: " + inputID);
      String[] ticketIDs = ticketIDList.split(",");
      List<Future<Boolean>> results = new ArrayList();
      boolean isAnyDuplicateFound = false;
      String[] var12 = ticketIDs;
      int var11 = ticketIDs.length;

      for(int var10 = 0; var10 < var11; ++var10) {
         String ticketID = var12[var10];
         String trimmedTicketID = ticketID.trim();
         if (!trimmedTicketID.isEmpty()) {
            results.add(this.executorService.submit(() -> {
               try {
                  return this.compareAlarmDetails(trimmedTicketID, inputID, apiCall, alarmsPramExtractor, notifySiemServer);
               } catch (Exception var7) {
                  System.err.println("[ERROR] Unexpected error for TicketID " + trimmedTicketID + ": " + var7.getMessage());
                  var7.printStackTrace();
                  return false;
               }
            }));
         }
      }

      Iterator var15 = results.iterator();

      while(var15.hasNext()) {
         Future result = (Future)var15.next();

         try {
            if ((Boolean)result.get()) {
               isAnyDuplicateFound = true;
            }
         } catch (Exception var14) {
            System.err.println("[ERROR] Error processing alarm: " + var14.getMessage());
            var14.printStackTrace();
         }
      }

      return isAnyDuplicateFound;
   }

   private boolean compareAlarmDetails(String ticketID, String inputID, ApiCall apiCall, AlarmsPramExtractor alarmsPramExtractor, NotifySiemServer notifySiemServer) throws Exception {
      System.out.println("[INFO] Processing AlarmID: " + ticketID);
      String siemApiEndpoint = this.properties.getProperty("api_endpoint_AlarmId") + ticketID;
      String siemResponse = this.callApiWithRetries(() -> {
         try {
            return ApiCall.callAPIOpenticket(siemApiEndpoint);
         } catch (Exception var2) {
            var2.printStackTrace();
            return siemApiEndpoint;
         }
      }, 3);
      if (siemResponse != null && !siemResponse.trim().isEmpty()) {
         JSONObject siemAlarm = this.parseJsonResponse(siemResponse, ticketID);
         if (siemAlarm == null) {
            return false;
         } else {
            alarmsPramExtractor.extractAndPrintParameters(siemResponse);
            String apiUrl = this.apiServerUrl + "?query=" + URLEncoder.encode(inputID, StandardCharsets.UTF_8.name()) + "&range=0&decorate=true&sort=timestamp:desc";
            String graylogResponse = this.callApiWithRetries(() -> {
               try {
                  return apiCall.callAPI(apiUrl, this.username, this.password);
               } catch (IOException var4) {
                  var4.printStackTrace();
                  return apiUrl;
               }
            }, 3);
            if (graylogResponse != null && !graylogResponse.trim().isEmpty()) {
               JSONArray messagesArray = this.extractMessagesArray(graylogResponse);
               if (messagesArray != null && messagesArray.length() != 0) {
                  AlarmsPramExtractor.extractAlarmDetails(graylogResponse);
                  boolean duplicateFound = false;

                  for(int i = 0; i < messagesArray.length(); ++i) {

                      JSONObject graylogMessage =
                              messagesArray.getJSONObject(i)
                                           .optJSONObject("message");

                      if(graylogMessage != null &&
                         compareFields(
                             siemAlarm,
                             graylogMessage
                         )) {

                          notifyDuplicateAlarm(
                              ticketID,
                              graylogMessage,
                              notifySiemServer
                          );

                          duplicateFound = true;

                          break;
                      }
                  }

                  if(!duplicateFound){

                	    System.out.println(
                	       "[INFO] No Duplicate Found"
                	    );

                	    EnrichmentProcessor ep =
                	    	    new EnrichmentProcessor(
                	    	        properties
                	    	    );

                	    JSONObject enriched =
                	        ep.enrich(ticketID);

                	    NotifySiemServer.notifyEnrichedAlarm(
                	            enriched
                	    );
                	}
                  
                  return duplicateFound;
               }
                  else {
                  System.out.println("[WARN] No messages in Graylog response for AlarmID: " + ticketID);
                  return false;
               }
            } else {
               System.out.println("[WARN] No response from Graylog for AlarmID: " + ticketID);
               return false;
            }
         }
      } else {
         System.out.println("[WARN] Empty SIEM response for AlarmID: " + ticketID);
         return false;
      }
   }

   private JSONObject parseJsonResponse(String response, String ticketID) {
      try {
         if (response.trim().startsWith("{")) {
            return new JSONObject(response);
         }

         if (response.trim().startsWith("[")) {
            JSONArray jsonArray = new JSONArray(response);
            if (jsonArray.length() > 0) {
               return jsonArray.getJSONObject(0);
            }

            System.out.println("[WARN] SIEM response array is empty for alarm_id: " + ticketID);
         } else {
            System.out.println("[WARN] SIEM response is neither JSON object nor array for alarm_id: " + ticketID);
         }
      } catch (JSONException var4) {
         System.out.println("[ERROR] Invalid JSON format in SIEM response for alarm_id: " + ticketID);
         var4.printStackTrace();
      }

      return null;
   }

   private JSONArray extractMessagesArray(String graylogResponse) {
      try {
         JSONObject graylogJson = new JSONObject(graylogResponse);
         return graylogJson.optJSONArray("messages");
      } catch (Exception var3) {
         System.err.println("[ERROR] Failed to parse Graylog response: " + var3.getMessage());
         return null;
      }
   }

   private void notifyDuplicateAlarm(String ticketID, JSONObject graylogMessage, NotifySiemServer notifySiemServer) {
      String case_id = graylogMessage.optString("Ticket_id", "N/A");
      String case_status = graylogMessage.optString("Alarm_Status", "N/A");
      String label = graylogMessage.optString("Label", "N/A");
      System.out.println("[INFO] Duplicate alarm found! Notifying SIEM server for AlarmID: " + ticketID);
      System.out.println("Sending params to siem API" + ticketID + case_id + case_status + label);
      NotifySiemServer.notifySIEMServer(case_id, case_status, ticketID, label);
      System.out.println("[INFO] Notified successfully.");
   }

   private boolean compareFields(JSONObject siemAlarm, JSONObject graylogMessage) {
      Map<String, String> fieldMappings = this.getFieldMappings();
      Iterator var5 = fieldMappings.entrySet().iterator();

      while(var5.hasNext()) {
         Entry<String, String> entry = (Entry)var5.next();
         String siemField = (String)entry.getKey();
         String graylogField = (String)entry.getValue();
         String siemValue = siemAlarm.optString(siemField, "").toLowerCase();
         String graylogValue = graylogMessage.optString(graylogField, "").toLowerCase();
         if (!siemValue.equals(graylogValue)) {
            System.out.println("[INFO] Field mismatch [" + siemField + "] SIEM: " + siemValue + " vs Graylog: " + graylogValue);
            return false;
         }
      }

      return true;
   }

   private String callApiWithRetries(Supplier<String> apiCall, int retries) throws Exception {
      int attempts = 0;

      while(attempts < retries) {
         try {
            String response = (String)apiCall.get();
            if (response != null && !response.trim().isEmpty()) {
               return response;
            }
         } catch (Exception var5) {
            ++attempts;
            if (attempts == retries) {
               throw new Exception("Failed to call API after " + retries + " attempts", var5);
            }
         }
      }

      return null;
   }

   public void shutdown() {
      if (this.executorService != null && !this.executorService.isShutdown()) {
         this.executorService.shutdown();
         try {
            if (!this.executorService.awaitTermination(60L, TimeUnit.SECONDS)) {
               this.executorService.shutdownNow();
            }
         } catch (InterruptedException var2) {
            this.executorService.shutdownNow();
            Thread.currentThread().interrupt();
         }
      }

   }

   private Map<String, String> getFieldMappings() {
      Map<String, String> mappings = new HashMap();
      mappings.put("src_ip", "Source_IP");
      mappings.put("dst_ip", "Destination_IP");
      mappings.put("username", "Username");
      mappings.put("category", "Alarm_Category");
      mappings.put("plugin_id", "Plugin_id");
      mappings.put("plugin_sid", "Plugin_sid");
      mappings.put("tenant_id", "Tenant_Id");
      mappings.put("alarm_name", "Alarm_Name");
      return mappings;
   }
}
    