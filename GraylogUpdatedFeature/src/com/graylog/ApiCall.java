 package com.graylog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/*public class ApiCall {
   public static String callAPIOpenticket(String apiUrl) throws IOException {
      URL url = new URL(apiUrl);
      HttpURLConnection connection = (HttpURLConnection)url.openConnection();
      connection.setRequestMethod("GET");
      int responseCode = connection.getResponseCode();
      System.out.println("Response Code: " + responseCode);
      StringBuilder response = new StringBuilder();
      if (responseCode == 200) {
         BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));

         String line;
         while((line = reader.readLine()) != null) {
            response.append(line);
         }

         reader.close();
      } else {
         System.out.println("Error occurred.Response Code: " + responseCode);
      }

      return response.toString();
   }*/
public class ApiCall {
    public static String callAPIOpenticket(String apiUrl) throws Exception {
        disableSSLVerification(); // <== Disable SSL certificate validation

        URL url = new URL(apiUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        System.out.println("Response Code: " + responseCode);

        StringBuilder response = new StringBuilder();
        if (responseCode == 200) {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
        } else {
            System.out.println("Error occurred. Response Code: " + responseCode);
        }

        return response.toString();
    }

    private static void disableSSLVerification() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                public void checkServerTrusted(X509Certificate[] certs, String authType) { }
            }
        };

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new SecureRandom());

        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(
            (hostname, session) -> true
        );
    }

 public String callAPI(String apiUrl, String username, String password) throws IOException {
      URL url = new URL(apiUrl);
      HttpURLConnection connection = (HttpURLConnection)url.openConnection();
      connection.setRequestMethod("GET");
      connection.setRequestProperty("Accept", "application/json");
      connection.setRequestProperty("X-Requested-By", "JavaClient");
      String auth = username + ":" + password;
      System.out.println("Auth: " + auth);
      String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
      System.out.println("Encoded Auth: " + encodedAuth);
      connection.setRequestProperty("Authorization", "Basic " + encodedAuth);
      int responseCode = connection.getResponseCode();
      System.out.println("Response Code: " + responseCode);
      StringBuilder response = new StringBuilder();
      BufferedReader reader;
      if (responseCode == 200) {
         reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
      } else {
         System.out.println("API request failed. Reading error stream...");
         InputStream errorStream = connection.getErrorStream();
         if (errorStream == null) {
            throw new IOException("Server returned status code " + responseCode + " with no error stream.");
         }

         reader = new BufferedReader(new InputStreamReader(errorStream));
      }

      String inputLine;
      while((inputLine = reader.readLine()) != null) {
         response.append(inputLine);
      }

      reader.close();
      System.out.println("Response:\n" + response.toString());
      return response.toString();
   }
   
	}

