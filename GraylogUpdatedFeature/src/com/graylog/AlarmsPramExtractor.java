package com.graylog;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Properties;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class AlarmsPramExtractor {
   public static void extractAlarmDetails(String response) {
      JSONObject jsonResponse = new JSONObject(response);
      JSONArray messages = jsonResponse.optJSONArray("messages");
      if (messages != null) {
         for(int i = 0; i < messages.length(); ++i) {
            JSONObject messageWrapper = messages.getJSONObject(i);
            JSONObject messageObject = messageWrapper.optJSONObject("message");
            if (messageObject != null) {
               String alarmRisk = messageObject.optString("Alarm_Risk", "N/A");
               String alarmCategory = messageObject.optString("Alarm_Category", "N/A");
               String tenantId = messageObject.optString("Tenant_Id", "N/A");
               String sourceIP = messageObject.optString("Source_IP", "N/A");
               String destinationIP = messageObject.optString("Destination_IP", "N/A");
               String pluginId = messageObject.optString("Plugin_id", "N/A");
               String pluginSid = messageObject.optString("Plugin_sid", "N/A");
               String username = messageObject.optString("Username", "N/A");
               String alarmName = messageObject.optString("Alarm_Name", "N/A");
               String case_id = messageObject.optString("Ticket_id", "N/A");
               String case_status = messageObject.optString("Alarm_Status", "N/A");
               String lable = messageObject.optString("Label", "N/A");
               String userdata1 = messageObject.optString("userdata1", "N/A");
               String userdata2 = messageObject.optString("userdata2", "N/A");
               String userdata3 = messageObject.optString("userdata3", "N/A");
               String userdata4 = messageObject.optString("userdata4", "N/A");
               String userdata5 = messageObject.optString("userdata5", "N/A");
               String userdata6 = messageObject.optString("userdata6", "N/A");
               String userdata7 = messageObject.optString("userdata7", "N/A");
               String userdata8 = messageObject.optString("userdata8", "N/A");
               System.out.println("Alarm Details from graylog server:");
               System.out.println("Alarm Category: " + alarmCategory);
               System.out.println("Tenant ID: " + tenantId);
               System.out.println("Source IP: " + sourceIP);
               System.out.println("Destination IP: " + destinationIP);
               System.out.println("Plugin ID: " + pluginId);
               System.out.println("Plugin SID: " + pluginSid);
               System.out.println("Username: " + username);
               System.out.println("Alarm Name: " + alarmName);
               System.out.println("Case ID: " + case_id);
               System.out.println("Case Status: " + case_status);
               System.out.println("Lable: " + lable);
               System.out.println("userdata1 ,userdata2,userdata3,userdata4,userdata5,userdata6,userdata7,userdata8 " + userdata1 + userdata2 + userdata3 + userdata4 + userdata5 + userdata6 + userdata7 + userdata8);
               System.out.println("----------");
            }
         }
      } else {
         System.out.println("No messages found in the response.");
      }

   }

   public static String getCurrentTimestamp() {
      return formatTimestamp(new Date());
   }

   public static String getPastTimestamp(int daysAgo) {
      Calendar calendar = Calendar.getInstance();
      calendar.add(6, -daysAgo);
      return formatTimestamp(calendar.getTime());
   }

   private static String formatTimestamp(Date date) {
      SimpleDateFormat isoFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
      return isoFormat.format(date);
   }

   public void extractAndPrintParameters(String jsonResponse) {
      try {
         JSONArray jsonArray = new JSONArray(jsonResponse);

         for(int i = 0; i < jsonArray.length(); ++i) {
            JSONObject jsonObject = jsonArray.getJSONObject(i);
            String alarmRisk = jsonObject.optString("risk", "N/A");
            String sourceIp = jsonObject.optString("src_ip", "N/A");
            String destinationIp = jsonObject.optString("dst_ip", "N/A");
            String username = jsonObject.optString("username", "N/A");
            String category = jsonObject.optString("category", "N/A");
            String pluginId = jsonObject.optString("plugin_id", "N/A");
            String sensorIp = jsonObject.optString("sensor_ip", "N/A");
            String pluginSid = jsonObject.optString("plugin_sid", "N/A");
            String tenantId = jsonObject.optString("tenant_id", "N/A");
            String alarmName = jsonObject.optString("alarm_name", "N/A");
            String case_status = jsonObject.optString("status", "N/A");
            String label = jsonObject.optString("label", "N/A");
            String userdata1 = jsonObject.optString("userdata1", "N/A");
            String userdata2 = jsonObject.optString("userdata2", "N/A");
            String userdata3 = jsonObject.optString("userdata3", "N/A");
            String userdata4 = jsonObject.optString("userdata4", "N/A");
            String userdata5 = jsonObject.optString("userdata5", "N/A");
            String userdata6 = jsonObject.optString("userdata6", "N/A");
            String userdata7 = jsonObject.optString("userdata7", "N/A");
            String userdata8 = jsonObject.optString("userdata8", "N/A");
            System.out.println("Extracted Parameters from siem server:");
            System.out.println("Source IP: " + sourceIp);
            System.out.println("Destination IP: " + destinationIp);
            System.out.println("Username: " + username);
            System.out.println("Category: " + category);
            System.out.println("Plugin ID: " + pluginId);
            System.out.println("Sensor IP: " + sensorIp);
            System.out.println("Plugin SID1: " + pluginSid);
            System.out.println("Tenant ID: " + tenantId);
            System.out.println("alarm Name: " + alarmName);
            System.out.println("case_status: " + case_status);
            System.out.println("Lable" + label);
            System.out.println("Alarm_Risk" + alarmRisk);
            System.out.println("userdata1 ,userdata2,userdata3,userdata4,userdata5,userdata6,userdata7,userdata8 " + userdata1 + userdata2 + userdata3 + userdata4 + userdata5 + userdata6 + userdata7 + userdata8);
         }
      } catch (Exception var25) {
         System.err.println("Error parsing JSON response: " + var25.getMessage());
         var25.printStackTrace();
      }

   }

   public static boolean compareAlarmDetails(String siemResponse, String graylogResponse) {
      try {
         System.out.println("SIEM Response: " + siemResponse);
         System.out.println("Graylog Response: " + graylogResponse);
         if (siemResponse != null && siemResponse.trim().startsWith("[")) {
            JSONArray siemAlarms = new JSONArray(siemResponse);
            if (siemAlarms.length() == 0) {
               System.out.println("No alarms found in SIEM response.");
               return false;
            } else if (graylogResponse != null && graylogResponse.trim().startsWith("{")) {
               JSONObject graylogJson = new JSONObject(graylogResponse);
               JSONArray graylogMessages = graylogJson.optJSONArray("messages");
               if (graylogMessages != null && graylogMessages.length() != 0) {
                  for(int i = 0; i < siemAlarms.length(); ++i) {
                     JSONObject siemAlarm = siemAlarms.getJSONObject(i);
                     String siemSrcIp = normalizeString(siemAlarm.optString("src_ip", "N/A"));
                     String siemDstIp = normalizeString(siemAlarm.optString("dst_ip", "N/A"));
                     String siemCategory = normalizeString(siemAlarm.optString("category", "N/A"));
                     String siemPluginId = normalizeString(siemAlarm.optString("plugin_id", "N/A"));
                     String siemPluginSid = normalizeString(siemAlarm.optString("plugin_sid", "N/A"));
                     String siemTenantId = normalizeString(siemAlarm.optString("tenant_id", "N/A"));
                     String siemAlarmName = normalizeString(siemAlarm.optString("alarm_name", "N/A"));
                     String siemCaseStatus = normalizeString(siemAlarm.optString("status", "N/A"));
                     String siemLabel = normalizeString(siemAlarm.optString("label", "N/A"));
                     String siemUserdata1 = normalizeString(siemAlarm.optString("userdata1", "N/A"));
                     String siemUserdata2 = normalizeString(siemAlarm.optString("userdata2", "N/A"));
                     String siemUserdata3 = normalizeString(siemAlarm.optString("userdata3", "N/A"));
                     String siemUserdata4 = normalizeString(siemAlarm.optString("userdata4", "N/A"));
                     String siemUserdata5 = normalizeString(siemAlarm.optString("userdata5", "N/A"));
                     String siemUserdata6 = normalizeString(siemAlarm.optString("userdata6", "N/A"));
                     String siemUserdata7 = normalizeString(siemAlarm.optString("userdata7", "N/A"));
                     String siemUserdata8 = normalizeString(siemAlarm.optString("userdata8", "N/A"));

                     for(int j = 0; j < graylogMessages.length(); ++j) {
                        JSONObject graylogMessageWrapper = graylogMessages.getJSONObject(j);
                        JSONObject graylogMessage = graylogMessageWrapper.optJSONObject("message");
                        String graylogSourceIP = normalizeString(graylogMessage.optString("Source_IP", "N/A"));
                        String graylogDestinationIP = normalizeString(graylogMessage.optString("Destination_IP", "N/A"));
                        String graylogAlarmCategory = normalizeString(graylogMessage.optString("Alarm_Category", "N/A"));
                        String graylogPluginId = normalizeString(graylogMessage.optString("Plugin_id", "N/A"));
                        String graylogPluginSid = normalizeString(graylogMessage.optString("Plugin_sid", "N/A"));
                        String graylogTenantId = normalizeString(graylogMessage.optString("Tenant_Id", "N/A"));
                        String graylogAlarmName = normalizeString(graylogMessage.optString("Alarm_Name", "N/A"));
                        String graylogCaseStatus = normalizeString(graylogMessage.optString("Alarm_Status", "N/A"));
                        String graylogLabel = normalizeString(graylogMessage.optString("Label", "N/A"));
                        String graylogUserdata1 = normalizeString(graylogMessage.optString("userdata1", "N/A"));
                        String graylogUserdata2 = normalizeString(graylogMessage.optString("userdata2", "N/A"));
                        String graylogUserdata3 = normalizeString(graylogMessage.optString("userdata3", "N/A"));
                        String graylogUserdata4 = normalizeString(graylogMessage.optString("userdata4", "N/A"));
                        String graylogUserdata5 = normalizeString(graylogMessage.optString("userdata5", "N/A"));
                        String graylogUserdata6 = normalizeString(graylogMessage.optString("userdata6", "N/A"));
                        String graylogUserdata7 = normalizeString(graylogMessage.optString("userdata7", "N/A"));
                        String graylogUserdata8 = normalizeString(graylogMessage.optString("userdata8", "N/A"));
                        boolean allFieldsMatch = siemSrcIp.equals(graylogSourceIP) && siemDstIp.equals(graylogDestinationIP) && siemCategory.equals(graylogAlarmCategory) && siemPluginId.equals(graylogPluginId) && siemPluginSid.equals(graylogPluginSid) && siemTenantId.equals(graylogTenantId) && siemAlarmName.equals(graylogAlarmName) && siemCaseStatus.equals(graylogCaseStatus) && siemLabel.equals(graylogLabel) && siemUserdata1.equals(graylogUserdata1) && siemUserdata2.equals(graylogUserdata2) && siemUserdata3.equals(graylogUserdata3) && siemUserdata4.equals(graylogUserdata4) && siemUserdata5.equals(graylogUserdata5) && siemUserdata6.equals(graylogUserdata6) && siemUserdata7.equals(graylogUserdata7) && siemUserdata8.equals(graylogUserdata8);
                        if (!allFieldsMatch) {
                           System.out.println("Mismatch details for SIEM Alarm " + i + " and Graylog Message " + j + ":");
                           if (!siemSrcIp.equals(graylogSourceIP)) {
                              System.out.println("  Source IP mismatch: SIEM=" + siemSrcIp + ", Graylog=" + graylogSourceIP);
                           }

                           if (!siemDstIp.equals(graylogDestinationIP)) {
                              System.out.println("  Destination IP mismatch: SIEM=" + siemDstIp + ", Graylog=" + graylogDestinationIP);
                           }

                           if (!siemCategory.equals(graylogAlarmCategory)) {
                              System.out.println("  Alarm Category mismatch: SIEM=" + siemCategory + ", Graylog=" + graylogAlarmCategory);
                           }

                           if (!siemPluginId.equals(graylogPluginId)) {
                              System.out.println("  Plugin ID mismatch: SIEM=" + siemPluginId + ", Graylog=" + graylogPluginId);
                           }

                           if (!siemPluginSid.equals(graylogPluginSid)) {
                              System.out.println("  Plugin SID mismatch: SIEM=" + siemPluginSid + ", Graylog=" + graylogPluginSid);
                           }

                           if (!siemTenantId.equals(graylogTenantId)) {
                              System.out.println("  Tenant ID mismatch: SIEM=" + siemTenantId + ", Graylog=" + graylogTenantId);
                           }

                           if (!siemAlarmName.equals(graylogAlarmName)) {
                              System.out.println("  Alarm Name mismatch: SIEM=" + siemAlarmName + ", Graylog=" + graylogAlarmName);
                           }

                           if (!siemCaseStatus.equals(graylogCaseStatus)) {
                              System.out.println("  Case Status mismatch: SIEM=" + siemCaseStatus + ", Graylog=" + graylogCaseStatus);
                           }

                           if (!siemLabel.equals(graylogLabel)) {
                              System.out.println("  Label mismatch: SIEM=" + siemLabel + ", Graylog=" + graylogLabel);
                           }

                           if (!siemUserdata1.equals(graylogUserdata1)) {
                              System.out.println("  USERDATA1 mismatch: SIEM=" + siemUserdata1 + ", Graylog=" + graylogUserdata1);
                           }

                           if (!siemUserdata2.equals(graylogUserdata2)) {
                              System.out.println("  USERDATA2 mismatch: SIEM=" + siemUserdata2 + ", Graylog=" + graylogUserdata2);
                           }

                           if (!siemUserdata3.equals(graylogUserdata3)) {
                              System.out.println("  USERDATA3 mismatch: SIEM=" + siemUserdata3 + ", Graylog=" + graylogUserdata3);
                           }

                           if (!siemUserdata4.equals(graylogUserdata4)) {
                              System.out.println("  USERDATA4 mismatch: SIEM=" + siemUserdata4 + ", Graylog=" + graylogUserdata4);
                           }

                           if (!siemUserdata5.equals(graylogUserdata5)) {
                              System.out.println("  USERDATA5 mismatch: SIEM=" + siemUserdata5 + ", Graylog=" + graylogUserdata5);
                           }

                           if (!siemUserdata6.equals(graylogUserdata6)) {
                              System.out.println("  USERDATA6 mismatch: SIEM=" + siemUserdata6 + ", Graylog=" + graylogUserdata6);
                           }

                           if (!siemUserdata7.equals(graylogUserdata7)) {
                              System.out.println("  USERDATA7 mismatch: SIEM=" + siemUserdata7 + ", Graylog=" + graylogUserdata7);
                           }

                           if (!siemUserdata8.equals(graylogUserdata8)) {
                              System.out.println("  USERDATA8 mismatch: SIEM=" + siemUserdata8 + ", Graylog=" + graylogUserdata8);
                           }
                        }

                        if (allFieldsMatch) {
                           System.out.println("Duplicate alarm found! SIEM Alarm " + i + " matches Graylog Message " + j);
                           return true;
                        }
                     }
                  }

                  System.out.println("No duplicate alarms found. Reasons for mismatches are printed above.");
                  sendDataToGraylog(siemResponse);
                  return false;
               } else {
                  System.out.println("No messages found in Graylog response.");
                  return false;
               }
            } else {
               System.out.println("Graylog response is not in expected format or is empty.");
               sendDataToGraylog(siemResponse);
               return false;
            }
         } else {
            System.out.println("SIEM response is not in expected format or is empty.");
            sendDataToGraylog(siemResponse);
            return false;
         }
      } catch (JSONException var45) {
         System.err.println("Error parsing JSON response: " + var45.getMessage());
         var45.printStackTrace();
         return false;
      }
   }

   private static String normalizeString(String input) {
      if (input == null) {
         return "N/A";
      } else {
         String cleaned = input.replaceAll("[\\p{C}]", "").replaceAll("\\\\/", "/").trim().replaceAll("\\s+", " ");
         return cleaned.isEmpty() ? "N/A" : cleaned;
      }
   }

   public static void sendDataToGraylog(String response) {
      DatagramSocket socket = null;
      Properties properties = new Properties();

      try {
         properties.load(new FileInputStream("/opt/AutoAlarmConfigFiles/queue_config.propertiesV4.1"));
         String serverIp = properties.getProperty("server_ip");
         int sendPort = Integer.parseInt(properties.getProperty("send_port"));
         if (serverIp == null || sendPort == 0) {
            System.out.println("Server IP or port not specified in config file.");
            return;
         }

         socket = new DatagramSocket();
         InetAddress serverAddress = InetAddress.getByName(serverIp);
         byte[] data = response.getBytes();
         DatagramPacket packet = new DatagramPacket(data, data.length, serverAddress, sendPort);
         socket.send(packet);
         System.out.println("Data sent to Graylog server");
      } catch (IOException var11) {
         System.err.println("Error sending data to Graylog: " + var11.getMessage());
         var11.printStackTrace();
         return;
      } finally {
         if (socket != null && !socket.isClosed()) {
            socket.close();
         }

      }

   }
}