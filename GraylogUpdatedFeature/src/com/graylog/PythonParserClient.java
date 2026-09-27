package com.graylog;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class PythonParserClient {

    public static void main(String[] args)
            throws Exception {

   	 System.out.println("started");

        String rawLog =
            "srcip=1.1.1.1 dstip=2.2.2.2 user=admin";

        ProcessBuilder pb =
            new ProcessBuilder(
                "python3",
                "/opt/log_enrichment/api_parser.py",
                rawLog
            );

        Process process = pb.start();

        BufferedReader reader =
            new BufferedReader(
                new InputStreamReader(
                    process.getInputStream()
                )
            );

        String line;

        while((line = reader.readLine()) != null) {

            System.out.println(line);
        }

        process.waitFor();
    }
}