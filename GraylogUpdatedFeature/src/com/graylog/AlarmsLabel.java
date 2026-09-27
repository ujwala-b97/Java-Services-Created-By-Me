  package com.graylog;
  import java.io.BufferedReader;
  import java.io.FileInputStream;
  import java.io.IOException;
	import java.io.InputStream;
	import java.io.InputStreamReader;
    import java.io.OutputStream;
    import java.net.DatagramPacket;
	import java.net.DatagramSocket;
	import java.net.HttpURLConnection; 
	import java.net.InetAddress; 
    import java.net.ServerSocket;
    import java.net.SocketException;
	import java.net.URL;
    import java.net.URLEncoder;
    import java.nio.charset.StandardCharsets;
    import java.time.LocalDate;
    import java.time.temporal.ChronoUnit;
    import java.util.ArrayList;
    import java.util.Base64;
    import java.util.Collections;
    import java.util.HashSet;
    import java.util.List;
    import java.util.Properties;
    import java.util.Set;
    import java.util.concurrent.BlockingQueue;
	import java.util.concurrent.ExecutorService;
	import java.util.concurrent.Executors;
	import java.util.concurrent.LinkedBlockingQueue; 
    import org.json.JSONArray;
    import org.json.JSONException;
    import org.json.JSONObject;	    
public class AlarmsLabel{	
public static void main(String[] args){
Properties properties = new Properties();		           
		        String filePath;    
		        if (System.getProperty("os.name").toLowerCase().contains("win")){
		            filePath ="D:\\QueueBasedArchitecture\\queue_config.properties"; 
		        }else {  
		            filePath ="/opt/AutoAlarmConfigFiles/queue_config.propertiesV4.1";     
		         }               
		       try(InputStream input = new FileInputStream(filePath)){
		            properties.load(input);                                       
	  	            System.out.println("loaded input");	   	   
		            int receiverPort = Integer.parseInt(properties.getProperty("reciever_port").trim());
		            System.out.println("receiver port"+receiverPort);   		                       
		            DatagramSocket socket = new DatagramSocket(receiverPort);      
		            System.out.println("Ticket listener started on port " + receiverPort);                      
		            BlockingQueue<TicketInfo> dataQueue = new LinkedBlockingQueue<>(); 
		            TicketProcessorThread processorThread = new TicketProcessorThread(dataQueue, properties);
		            processorThread.start();                      
		            int numThreads = Integer.parseInt(properties.getProperty("num_threads").trim());  
		            ExecutorService executor = Executors.newFixedThreadPool(numThreads); 
		            for (int i = 0; i < numThreads; i++){       
		                executor.execute(new APICallWorker(dataQueue, properties)); 
		            }
		            byte[] receiveData = new byte[1024];
		            while (true){  
		                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
		                socket.receive(receivePacket); 
		                String receivedData = new String(receivePacket.getData(), 0, receivePacket.getLength());
		                System.out.println("The received data is " + receivedData);// here getting data in listener port		             
		                JSONObject json = new JSONObject(receivedData);
		                String actionType=json.getString("action_type");	               		                		                
		                if("Case".equals(actionType)){
		                	String ticketID = json.getString("ticket_id");
			                String ticketStatus = json.getString("ticket_status");
                        processorThread.processTicketID(actionType,ticketID, ticketStatus,null);  
		                System.out.println("Received ticket ID: " + ticketID + ", Status: " + ticketStatus);
		            }
		                    else if ("Labelling".equals(actionType)){
		                    String Alarm_id = json.getString("alarm_id");  
		                    String label = json.getString("label");  
		                    String Label_status = json.getString("label_status");		                   
		                        // Regular processing
		                        processorThread.processTicketID(actionType, Alarm_id, label, Label_status);
		                        System.out.println("Received Alarm ID: " + Alarm_id + ", Label: " + label+"Lable Status"+ Label_status);
		                    
		                }
		      else if ("Autoalarm".equals(actionType)){
		    	    String alarmID = json.getString("alarm_id");
		    	    Thread.sleep(1000);
		    	    processorThread.processTicketID(actionType, alarmID, null, null);  
		    	    System.out.println("Received Alarm ID for AutoAlarm: " + alarmID);
		    	}else{
				  System.out.println("No data found"); 
			  }
		  }	  
		        } catch (SocketException e){
		            System.err.println("Failed to create socket: " + e.getMessage());
		        } catch (IOException e){ 
		            System.err.println("I/O error: " + e.getMessage());
		       }   catch (JSONException e) {
		           System.err.println("JSONException: Error parsing JSON data. Data received: " + ". Error: " + e.getMessage());
		       } catch (InterruptedException e) {
		            e.printStackTrace();
		        }
		       catch (Exception e) {
		           System.err.println("Unhandled Exception: " + e.getMessage());
		           e.printStackTrace();
		       }
		    }
public static class TicketProcessorThread extends Thread {
    private final BlockingQueue<TicketInfo> dataQueue;
    private final Properties properties;

    public TicketProcessorThread(BlockingQueue<TicketInfo> dataQueue, Properties properties){
        this.dataQueue = dataQueue;
        this.properties = properties;
    }

    // Method to process and queue ticket information
    public void processTicketID(String actionType, String id, String statusOrLabel, String label_status) throws IOException, InterruptedException {
        if (label_status == null) {
        	label_status = "N/A"; // Optional: Set a default value if tenantId is missing
        }
        TicketInfo ticketInfo = new TicketInfo(actionType, id, statusOrLabel, label_status);
        dataQueue.put(ticketInfo);
        System.out.println("Processed and queued TicketInfo: " + ticketInfo.toString());
    }
}

		    private static class APICallWorker implements Runnable{
		        private final BlockingQueue<TicketInfo> dataQueue;
		        public APICallWorker(BlockingQueue<TicketInfo> dataQueue, Properties properties){
		            this.dataQueue = dataQueue;
		            this.properties = properties;
		        } 
              
		        private final Properties properties;     
				@Override   
		        public void run() { 
		            while (true) {
		                try {    		                	
                        	ApiCall obj=new ApiCall();
                        	AlarmsPramExtractor alarmsPramExtractor= new AlarmsPramExtractor();
                        	NotifySiemServer notifySiemServer=new NotifySiemServer();
                        	String username = properties.getProperty("apiserver_username");
		                    String password = properties.getProperty("apiserver_password");
		                    String api_server_url = properties.getProperty("api_server_url");		                    
		                    String inputID=properties.getProperty("input_id");
		                    int sendPort = Integer.parseInt(properties.getProperty("send_port"));
	                        String serverIp = properties.getProperty("server_ip");

		                    TicketInfo ticketInfo = dataQueue.take();
		                    String actionType=ticketInfo.getActionType();
		                    String ticketID = ticketInfo.getId();
		                    String ticketStatus = ticketInfo.getStatusOrLabel();
		                    String Label_status=ticketInfo.getLabel_status();
		                    System.out.println("label status is "+ Label_status);
		                    
		                    if("Case".equals(actionType)){
		                    System.out.println("Thread " + Thread.currentThread().getId() + " processing ticket ID: " + ticketID
		                            + ", Status: " + ticketStatus);

		                    if("Closed".equalsIgnoreCase(ticketStatus)){
		                    	 //String apiUrl=api_server_url+"?query="+ticketID+"&range=0&decorate=true";
		                    	String query = "gl2_source_input:" + inputID + " && ticket_id:\"" + ticketID + "\"";
		                    	String encodedQuery = URLEncoder.encode(query, StandardCharsets.UTF_8.toString());
		                    	String apiUrl = api_server_url + "?query=" + encodedQuery + "&range=0&decorate=true";

		                    	 System.out.println("relative URL"+apiUrl);		                    
		                        try{                                                                                                                                     
		                            String response = callAPI(apiUrl, username, password);                                                                       
		                            // Convert the API response to a JSON object    
		                            JSONObject jsonObject = new JSONObject(response);  
                                  
		                            //Extract desired fields from the JSON object
		                            JSONArray messagesArray = jsonObject.getJSONArray("messages"); 
		                            if (messagesArray.length() > 0){
		                                JSONObject messageObject = messagesArray.getJSONObject(0);   
//		                                System.out.println("Message: " + messageObject); 
		                                JSONObject msgJson = messageObject.getJSONObject("message");  //new                                 
		                               String alarmStatus = msgJson.getString("Alarm_Status");
		                                System.out.println("Alarm Status is"+ alarmStatus);
		                                messageObject.getJSONObject("message").put("Alarm_Status", "closed");
		                                String updatedAlarmStatus = messageObject.getJSONObject("message").getString("Alarm_Status");
		                                System.out.println("Updated Alarm Status: " + updatedAlarmStatus);
		                                                             
		                                String index = messageObject.getString("index");  
//		                                System.out.println("Index: " + index); 
		                                String message = messageObject.getJSONObject("message").getString("message"); 
		                                // System.out.println("Message: " + message); 
		                                String id = messageObject.getJSONObject("message").getString("_id");

		                                // System.out.println("_id: " + id);
     
		                                //Replace a specific substring in the message
		                                String replacedMessage = message.replace("\"status\":\"open\"", "\"status\":\"closed\"");
		                             // System.out.println("Message: " + replacedMessage);
		                                
		                                String username1="admin"; 
		                                String password1="admin";   
		                                String ServerIp=properties.getProperty("server_ip");		                                
		                           
		                                String[] curlCommand={  
		                                	    "curl", 
		                                	    "-X", "POST", 
		                                	    "http://"+ ServerIp + ":9200/" + index + "/_doc/" + id + "/_update",
		                                	    "-H", "Content-Type: application/json",
		                                	    "-u", username1 + ":" + password1,  // Add this line for authorization
		                                	    "-d",
		                                	    "{\n" +
		                                	    "  \"doc\": {\n" +
		                                	    "    \"message\": \"" + escapeJsonString(replacedMessage) + "\",\n" +
		                                	    "    \"Alarm_Status\":\"" + escapeJsonString(updatedAlarmStatus) + "\"\n" +
		                                	    "  }\n" +
		                                	    "}" 
		                                	};    		                                        
		                             // Print the curl command   
		                             System.out.println("Executing curl command:");
		                             for (String cmd : curlCommand) {
		                                 System.out.print(cmd + " ");
		                             }
		                             System.out.println(); // New line                                     
		                             try {  
		                                 ProcessBuilder processBuilder = new ProcessBuilder(curlCommand);
		                                 Process process = processBuilder.start();
		                                 int exitCode = process.waitFor();
		                                 if (exitCode == 0) {
		                                     System.out.println("Document updated successfully.");
		                                 } else {
		                                     System.out.println("Error updating document.");
		                                 }
		                             } catch (IOException | InterruptedException e){ 
		                                 System.out.println("An error occurred: " + e.getMessage());
		                             }
		                                }
		                        } catch (Exception e) {
		                            e.printStackTrace();        
		                        }
                                
		                 
		                    } else {       
		                        try {       
		                            String apiEndpoint = properties.getProperty("api_endpoint") + ticketID;
		                            String response=obj.callAPIOpenticket(apiEndpoint);
		                            byte[] sendData =response.getBytes();		                                  
		                            DatagramSocket socket = new DatagramSocket(); 
		                            InetAddress serverAddress = InetAddress.getByName(serverIp); 
		                            DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, serverAddress, sendPort);
		                            socket.send(sendPacket); 
		                            System.out.println("data sent successfully");
		                            socket.close();                                              
		                                                                                                                          
		                            //Here you can add the updated code for the risk dashboard		                                                                                                                              
		                            Thread.sleep(10000);//(to extract the parameters from input )  	                                   
		                            String apiUrl=api_server_url+"?query="+ticketID+"&range=0&decorate=true"; 
                                        
		                            System.out.println("url is"+apiUrl); 		                                                                      
		                            String response2 = callAPI(apiUrl, username, password);
                                     System.out.println("the response"+response2);                                                                        
		                                                              
		                             JSONObject jsonObject = new JSONObject(response2);  
                                                  
		                            // Extract desired fields from the JSON object
		                            JSONArray messagesArray = jsonObject.getJSONArray("messages");   
		                            if (messagesArray.length() > 0){
		                                JSONObject messageObject = messagesArray.getJSONObject(0); 
		                                int alarmRisk = messageObject.getJSONObject("message").getInt("Alarm_Risk");
		                                String alarmCategory = messageObject.getJSONObject("message").getString("Alarm_Category");
                                        String backlog_id=messageObject.getJSONObject("message").getString("Backlog_id");

		                                System.out.println("The alarm risk, category, and backlogid are: " + alarmRisk + ", " + alarmCategory + ", "+backlog_id );
		                                                  
		                                Thread.sleep(10000);      
			                            // here need to add the code to search the logs using extracted category and alarm name 
		                                // Construct the search query for logs using extracted category  
		                                String searchQuery = URLEncoder.encode("Alarm_Category:" + alarmCategory);
		                                String searchUrl = properties.getProperty("api_server_url") + "?query=" + searchQuery + "&range=0&decorate=true";
                                                         
		                                // Make the API call to search logs  
		                                String searchResponse = callAPI(searchUrl, username, password);  
		                                System.out.println("Search response: " + searchResponse); 
		                                                        
		                                // Parse the search response JSON
		                                JSONObject searchResult = new JSONObject(searchResponse);
		                                JSONArray messagesArray1 = searchResult.getJSONArray("messages");
                                  
		                                // Check if any messages are found
		                                if (messagesArray.length() > 0){ 
		                                    // Initialize variables to store the latest message information
		                                    String latestMessageTimestamp = "";
		                                    String latestMessageContent = "";

		                                    //Iterate through messages to find the latest one
		                                    for (int i = 0; i < messagesArray.length(); i++) {
		                                        JSONObject messageObject1 = messagesArray.getJSONObject(i);
		                                        String messageTimestamp = messageObject1.getJSONObject("message").getString("timestamp");		                     
		                                        // Compare timestamps to find the latest message
		                                        if(messageTimestamp.compareTo(latestMessageTimestamp) > 0){
		                                            latestMessageTimestamp = messageTimestamp;
		                                               }
		                                    } 
		                                    //Print or process the latest message information
		                                    if (!latestMessageTimestamp.isEmpty()){
		                                        System.out.println("Latest message timestamp: " + latestMessageTimestamp);
		                                        
		                                       // Calculate alarm probability based on date difference
		                                        LocalDate currentDate = LocalDate.now();
		                                        LocalDate alarmDate = LocalDate.parse(latestMessageTimestamp.substring(0, 10)); // Assuming date format is "yyyy-MM-dd"
		                                        long daysDifference = ChronoUnit.DAYS.between(alarmDate, currentDate);
		                                        

		                                     // Assign probability based on the difference
		                                        int yearlyProbability=Integer.parseInt(properties.getProperty("yearly_Probability"));
		                                        int sixMonthP=Integer.parseInt(properties.getProperty("six_months_Probability"));
		                                        int quarterlyP=Integer.parseInt(properties.getProperty("three_months_Probability"));
		                                        int monthlyP=Integer.parseInt(properties.getProperty("monthly_Probability"));
  		                                        
		                                     int alarmProbability;
		                                     if (daysDifference >= yearlyProbability) {
		                                         alarmProbability = 5; // Year
		                                     } else if (daysDifference >= sixMonthP) {
		                                         alarmProbability = 4; // Six months
		                                     } else if (daysDifference >= quarterlyP) {
		                                         alarmProbability = 3; // Three months
		                                     } else if (daysDifference >= monthlyP) {
		                                         alarmProbability = 2; // Monthly
		                                     } else {
		                                         alarmProbability = 1; // Daily
		                                     } 

		                                     System.out.println("Alarm Probability: " + alarmProbability);
		                                     
		                                     int alarm_impact=alarmProbability * alarmRisk;
		                                    
		                                     String siem_api = properties.getProperty("risk_dashboard_siem_api") +
		                                             "?ticketID=" + ticketID +
		                                             "&alarm_impact=" + alarm_impact +
		                                             "&backlog_id=" + URLEncoder.encode(backlog_id, "UTF-8");

		                           // Print request URL for debugging
		                           System.out.println("Request URL: " + siem_api);

		                           // Send POST request
		                           HttpURLConnection connection = null;
		                           try {
		                               // Create connection
		                               URL url = new URL(siem_api);
		                               connection = (HttpURLConnection) url.openConnection();
		                               connection.setRequestMethod("POST");
		                               connection.setRequestProperty("Content-Type", "application/json");
		                               connection.setDoOutput(true); 

		                               // Get response code 
		                               int responseCode = connection.getResponseCode();
		                                  System.out.println("Response Code: " + responseCode);

		                               // Get response
		                               try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
		                                   StringBuilder response1 = new StringBuilder();
		                                   String responseLine;
		                                   while ((responseLine = br.readLine()) != null) {
		                                       response1.append(responseLine.trim());
		                                   }
		                                   System.out.println("Response: " + response1.toString());
		                               }
		                           } catch (IOException e) {
		                               e.printStackTrace(); // Print the stack trace for debugging
		                           }finally {
		                                         if (connection != null) {
		                                             connection.disconnect();
		                                         }
		                                     }
		                                     		                                        
		                                    } else {
		                                        System.out.println("No messages found in the search response.");
		                                    }
		                                } else {
		                                    System.out.println("No messages found in the search response.");
		                                }
    		                            }     
	                           }catch (Exception e) {//added exctra to disable ssl
		                            e.printStackTrace(); 
		                            }    
		                    } 
		                }//Use a Set to track unique labels
		                 //   if ("Labelling".equals(actionType)){
		                    	if ("Labelling".equals(actionType)){		                                     
		                  		             
		                    	    LabelProcessor labelProcessor = new LabelProcessor(api_server_url, username, password, properties);
		                    	    labelProcessor.processLabel(inputID, ticketID, ticketStatus,Label_status,obj, alarmsPramExtractor, notifySiemServer);
		                    	    System.out.println("label status"+Label_status);
		                    	}		                    	
		                    	if("Autoalarm".equals(actionType)){
		                    	    int threadPoolSize = 5; // Define the thread pool size, adjust as needed
		                    	    AutoAlarmProcessor autoAlarmProcessor = new AutoAlarmProcessor(
		                    	        api_server_url,
		                    	        username,
		                    	        password,
		                    	        properties,
		                    	        threadPoolSize
		                    	    );
		                    	    try {
		                    	        // Ensure ticketID is final or effectively final
		                    	        final String finalTicketID = ticketID;

		                    	        // Process the alarms
		                    	        autoAlarmProcessor.processAlarms(inputID, finalTicketID, obj, alarmsPramExtractor, notifySiemServer);
		                    	    } catch (Exception e) {
		                    	        System.err.println("[ERROR] Error processing auto alarms: " + e.getMessage());
		                    	        e.printStackTrace();
		                    	    } finally {
		                    	        // Shut down the AutoAlarmProcessor and its executor service
		                    	        autoAlarmProcessor.shutdown(); // Ensure the thread pool is shut down
		                    	    }
		                    	}

                 	                   
		                }catch (Exception e){//added extra on 3rd feb
		                        System.err.println("Error in API communication: " + e.getMessage());
		                        e.printStackTrace();
		                }
		            }
		                    
		   }
				private static String callAPI(String apiUrl, String username, String password) throws IOException {
				    URL url = new URL(apiUrl);
				    HttpURLConnection connection = (HttpURLConnection) url.openConnection();

				    // Set method and headers
				    connection.setRequestMethod("GET");
				    connection.setRequestProperty("Accept", "application/json");
				    connection.setRequestProperty("X-Requested-By", "JavaClient");

				    // Basic auth
				    String auth = username + ":" + password;
				    String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
				    connection.setRequestProperty("Authorization", "Basic " + encodedAuth);

				    // Debug logging
				    System.out.println("Request URL: " + apiUrl);
				    System.out.println("Encoded Auth: " + encodedAuth);

				    int responseCode = connection.getResponseCode();
				    System.out.println("Response Code: " + responseCode);

				    BufferedReader reader;                                 
				    if (responseCode == HttpURLConnection.HTTP_OK) {
				        // Read success response
				        reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
				    } else {
				        // Read error response
				        reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
				        System.out.println("API request failed");
				    }

				    String inputLine;
				    StringBuilder response = new StringBuilder();
				    while ((inputLine = reader.readLine()) != null){
				        response.append(inputLine);
				    }
				    reader.close();
				    System.out.println("Response:\n" + response.toString());
				    return response.toString();
				}
                                             
		    // Function to escape JSON string    
		    private static String escapeJsonString(String jsonString){ 
		        return jsonString.replace("\"", "\\\""); 
		    }          
                      
		} 
}
