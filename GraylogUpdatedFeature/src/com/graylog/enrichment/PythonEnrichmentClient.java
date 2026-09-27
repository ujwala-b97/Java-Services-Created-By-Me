package com.graylog.enrichment;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.json.JSONObject;

public class PythonEnrichmentClient {

	public JSONObject parse(
	        String rowLog
	) throws Exception {

	    ProcessBuilder pb =
	            new ProcessBuilder(
	                    "python3",
	                    "/opt/log_enrichment/api_parser.py",
	                    rowLog
	            );

	    Process process =
	            pb.start();

	    BufferedReader reader =
	            new BufferedReader(
	                    new InputStreamReader(
	                            process.getInputStream()
	                    )
	            );

	    BufferedReader errorReader =
	            new BufferedReader(
	                    new InputStreamReader(
	                            process.getErrorStream()
	                    )
	            );

	    StringBuilder output =
	            new StringBuilder();

	    StringBuilder errorOutput =
	            new StringBuilder();

	    String line;

	    while ((line = reader.readLine()) != null) {

	        output.append(line);
	    }

	    while ((line = errorReader.readLine()) != null) {

	        errorOutput.append(line);
	    }

	    process.waitFor();

	    System.out.println(
	            "PYTHON STDOUT : "
	            + output
	    );

	    System.out.println(
	            "PYTHON STDERR : "
	            + errorOutput
	    );

	    String response =
	            output.toString().trim();

	    if(!response.startsWith("{")){

	        JSONObject error =
	                new JSONObject();

	        error.put(
	                "enrichment_status",
	                "INVALID_JSON"
	        );

	        error.put(
	                "raw_response",
	                response
	        );

	        return error;
	    }

	    return new JSONObject(
	            response
	    );
	}
}