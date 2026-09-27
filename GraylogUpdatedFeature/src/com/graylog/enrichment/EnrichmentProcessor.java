package com.graylog.enrichment;
import org.json.JSONObject;
import java.util.Properties;

import org.json.JSONObject;

public class EnrichmentProcessor {

    private Properties properties;

    public EnrichmentProcessor(
            Properties properties
    ){

        this.properties = properties;
    }

    public JSONObject enrich(
            String ticketID
    ) throws Exception {

        System.out.println(
                "[INFO] Enrichment started for : "
                + ticketID
        );

        SiemAlarmFetcher fetcher =
                new SiemAlarmFetcher(
                        properties
                );

        String rowLog =
                fetcher.getRowLog(
                        ticketID
                );

        System.out.println(
                "\nROW LOG:\n"
                + rowLog
        );

        PythonEnrichmentClient client =
                new PythonEnrichmentClient();

        JSONObject enriched =
                client.parse(
                        rowLog
                );

        enriched.put(
                "alarm_id",
                ticketID
        );

        return enriched;
    }
}