package eu.faircore4eosc.pidmr.logging;

import net.cnri.util.StreamTable;
import net.handle.hdllib.*;
import net.handle.server.Main;
import net.handle.hdllib.AbstractMessage;

import java.io.File;
import java.net.InetAddress;

import eu.faircore4eosc.pidmr.ConfigLoader;

public class AccessLogger {

    public static void log(ConfigLoader.Config config,
                           String pidType, String pid, String display,
                           int httpStatus, String redirectUrl, String clientAddress,
                           int hdlResponseCode, long responseTime) {
        Main main;
        String hdlServerConfigPath = config.getHdlServerConfigPath();
        StreamTable configTable = new StreamTable();
        File serverDir = new File(hdlServerConfigPath);

        try {
            configTable.readFromFile(new File(serverDir, HSG.CONFIG_FILE_NAME));
        } catch (Exception e) {
            System.err.println("Error reading Handle config: " + e);
            return;
        }

        try {
            main = new Main(serverDir, configTable);
            String extraInfo = pidType + ";" + pid + ";" + display + ";" + httpStatus + ";" + redirectUrl;
            InetAddress client = InetAddress.getByName(clientAddress);
            main.logAccess("HTTP:PIDMRHDLProxy", client,
                    AbstractMessage.OC_RESOLUTION, hdlResponseCode, extraInfo, responseTime);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }
}
