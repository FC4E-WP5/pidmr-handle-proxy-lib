package eu.faircore4eosc.pidmr.logging;

import net.cnri.util.StreamTable;
import net.handle.hdllib.*;

import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.TimeUnit;

import eu.faircore4eosc.pidmr.ConfigLoader;
import eu.faircore4eosc.pidmr.utilities.TimeUtils;

public class InfluxLogger {

    public static void log(ConfigLoader.Config pidmrConfig, String pidType, String pid, String display,
                           String redirectUrl, String responseTime, Integer status) {

        String influxdbConfigFile = pidmrConfig.getInfluxdbConfigFile();
        StreamTable configTable = new StreamTable();
        File serverDir = new File(HSG.DEFAULT_CONFIG_SUBDIR_NAME);

        try {
            File configFile = new File(serverDir, influxdbConfigFile);
            if (configFile.exists()) {
                configTable.readFromFile(configFile);
                if (configTable.containsKey("influxdb_config")) {
                    Map<String, Object> influxdbConfig = null;
                    Object config = configTable.get("influxdb_config");
                    if (config instanceof Map<?, ?> rawMap) {
                        influxdbConfig = new HashMap<>();
                        for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
                            if (entry.getKey() instanceof String) {
                                influxdbConfig.put((String) entry.getKey(), entry.getValue());
                            }
                        }
                    } else {
                        System.err.println("configuration error: influxdb_config is invalid");
                        return;
                    }
                    String bindAddress = (String) influxdbConfig.get("bind_address");
                    String bindPort = (String) influxdbConfig.get("bind_port");
                    String username = (String) influxdbConfig.get("username");
                    String password = (String) influxdbConfig.get("password");
                    String databaseName = (String) influxdbConfig.get("databaseName");
                    String measurement = (String) influxdbConfig.get("measurement");
                    String num_threads = (String) influxdbConfig.get("num_threads");

                    int numThreads = Integer.parseInt(num_threads);
                    String url = bindAddress + ":" + bindPort;

                    InfluxDB influxDB = InfluxDBFactory.connect(url, username, password);
                    influxDB.setDatabase(databaseName);

                    try {
                        influxDB.enableBatch(10, 200, TimeUnit.MILLISECONDS);
                        Point point = Point.measurement(measurement)
                                .addField("time_stamp", TimeUtils.getCurrentTimestamp())
                                .addField("pid_endpoint", redirectUrl)
                                .addField("pid_type", pidType)
                                .addField("pid_id", pid)
                                .addField("pid_mode", display)
                                .addField("pid_resolver_status", status)
                                .addField("responseTime", responseTime)
                                .build();

                        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                        CompletableFuture.runAsync(() -> {
                            try {
                                influxDB.write(point);
                            } catch (Exception e) {
                                System.err.println("Write failed: " + e.getMessage());
                            }
                        }, executor).thenRun(executor::shutdown);

                    } catch (Exception e) {
                        System.err.println("Error transmitting the data to InfluxDB: " + e.getMessage());
                    } finally {
                        influxDB.close();
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading InfluxDB config: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}
