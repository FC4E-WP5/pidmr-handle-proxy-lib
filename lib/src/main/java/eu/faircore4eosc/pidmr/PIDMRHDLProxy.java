package eu.faircore4eosc.pidmr;

import eu.faircore4eosc.pidmr.ConfigLoader;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.cnri.util.StreamTable;
import net.handle.apps.servlet_proxy.HDLProxy;
import net.handle.apps.servlet_proxy.HDLServletRequest;
import net.handle.apps.servlet_proxy.HDLServletRequest.ResponseType;
import net.handle.hdllib.*;
import net.handle.server.Main;
import net.handle.server.servletcontainer.HandleServerInterface;

import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;
import org.influxdb.dto.Query;

public class PIDMRHDLProxy extends HDLProxy {
    public static RequestProcessor resolver = null;
    private boolean matchFound = false;
    private String display = null;
    private String pid = null;

    private final String RESOLVING_MODE_LANDINGPAGE = "landingpage";
    private final String RESOLVING_MODE_METADATA = "metadata";
    private final String RESOLVING_MODE_RESOURCE = "resource";
    private final String RESOLVING_MODE_CN = "cn";
    private final String CN_BIBTEX = "bibtex";
    private final String CN_TURTLE = "turtle";
    private final String CN_RDF = "rdf";
    private final String CN_CITATION = "citation";
    private String pidType = null;
    private String recognizedPid = null;

    protected HandleServerInterface handleServer;

    private ConfigLoader.Config config;

    public enum PidType {
        TYPE_21,
        EPIC_OLD,
        ARXIV,
        ARK,
        URN_NBN_DE,
        URN_NBN_FI,
        DOI,
        SWH,
        ZENODO,
        ORCID,
        ZBMATH,
        SWMATH,
        ZBL,
        ROR,
        ISLRN,
        ISNI,
        ISBN,
        BIBCODE,
        UNKNOWN;

        public static PidType fromString(String type) {
            switch (type) {
                case "21":
                case "epic_old":
                    return TYPE_21;
                case "arXiv":
                    return ARXIV;
                case "ark":
                    return ARK;
                case "urn:nbn:de":
                    return URN_NBN_DE;
                case "urn:nbn:fi":
                    return URN_NBN_FI;
                case "doi":
                    return DOI;
                case "swh":
                    return SWH;
                case "10.5281/zenodo":
                    return ZENODO;
                case "orcid":
                    return ORCID;
                case "zbMATH":
                    return ZBMATH;
                case "swMATH":
                    return SWMATH;
                case "Zbl":
                    return ZBL;
                case "ROR":
                    return ROR;
                case "ISLRN":
                    return ISLRN;
                case "ISNI":
                    return ISNI;
                case "ISBN":
                    return ISBN;
                case "Bibcode":
                    return BIBCODE;
                default:
                    return UNKNOWN;
            }
        }
    }

    private static final String DOI_PREFIX = "doi:";
    private static final String CROSSREF = "crossref";
    private static final String DATACITE = "datacite";

    @Override
    public void init() throws ServletException {
        super.init();
        ConfigLoader configLoader = new ConfigLoader("config.json");
        try {
            config = configLoader.loadConfig();
        } catch (IOException e) {
            throw new ServletException("Failed to load configuration", e);
        }
    }

    // @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        HDLServletRequest hdl = new HDLServletRequest(this, req, resp, resolver);
        if (!hdl.hdl.contains("MR@")) {
            if (req.getQueryString() != null) {
                if (req.getQueryString().contains("&")) {
                    pid = req.getQueryString().split("&")[0];
                    display = req.getQueryString().split("&")[1];
                }
                else {
                    pid = req.getQueryString();
                }
                if (display == null) {
                    display = config.getResolvingModes().get("RESOLVING_MODE_LANDINGPAGE");
                }
                if (pid != null) {
                    pidType = checkPidType(pid);
                    if (pidType != null) {
                        try {
                            dispatchPidHandlingMode(pid, display, hdl, pidType, resp);
                        } catch (HandleException e) {
                            throw new RuntimeException(e);
                        }
                        return;
                    } else {
                        resp.setCharacterEncoding("UTF-8");
                        resp.setContentType("application/json");
                        resp.getWriter().println("{\"error\": \"pid type can not be determind.\"}");
                    }
                }
            }
        }
        if (handleSpecial(req, resp)) return;
        super.doGet(req, resp);
    }

    // @Override
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        HDLServletRequest hdl = new HDLServletRequest(this, req, resp, resolver);
        pidType = checkPidType(hdl.hdl);
        if (pidType != null) {
            if (!pidType.equals("21") && !pidType.equals("epic_old")) {
                display = hdl.params.getParameter("display");
                if (display == null) {
                    display = config.getResolvingModes().get("RESOLVING_MODE_LANDINGPAGE");
                }
                pid = hdl.hdl;
                try {
                    dispatchPidHandlingMode(pid, display, hdl, pidType, resp);
                } catch (HandleException e) {
                    throw new RuntimeException(e);
                }
            }
            else {
                try {
                    super.doPost(req, resp);
                } catch (Exception e) {
                    // Handle the exception here, e.g., log an error message or take corrective action.
                }
            }
        } else {
            noPidType(resp);
        }
    }

    private void dispatchPidHandlingMode(String pid, String display, HDLServletRequest hdl, String pidType, HttpServletResponse resp) throws IOException, ServletException, HandleException {
        PidType type = PidType.fromString(pidType);
        switch (type) {
            case TYPE_21:
                handle21(pidType, pid, display, hdl, resp);
                break;
            case ARXIV:
                handleArxiv(pidType, pid, display, hdl, resp);
                break;
            case ARK:
                handleArk(pidType, pid, display, hdl, resp);
                break;
            case URN_NBN_DE:
                handleUrnDe(pidType, pid, display, hdl, resp);
                break;
            case URN_NBN_FI:
                handleUrnFi(pidType, pid, display, hdl, resp);
                break;
            case DOI:
                handleDoi(pidType, pid, display, hdl, resp);
                break;
            case SWH:
                String[] swhPidParts = pid.split(":");
                String swhType = swhPidParts[2];
                String swhHash = swhPidParts[3];
                if (display.equals(RESOLVING_MODE_RESOURCE)) {
                    handleSwh(pidType, swhHash, display, hdl, resp);
                } else {
                    handleSwh(pidType, pid, display, hdl, resp);
                }
                break;
            case ZENODO:
                handleZenodo(pidType, pid, display, hdl, resp);
                break;
            case ORCID:
                handleOrcid(pidType, pid, display, hdl, resp);
                break;
            case ZBMATH:
                handleZbmath(pidType, pid, display, hdl, resp);
                break;
            case SWMATH:
                handleSwmath(pidType, pid, display, hdl, resp);
                break;
            case ZBL:
                handleZbl(pidType, pid, display, hdl, resp);
                break;
            case ROR:
                handleRor(pidType, pid, display, hdl, resp);
                break;
            case ISLRN:
                handleISLRN(pidType, pid, display, hdl, resp);
                break;
            case ISNI:
                handleISNI(pidType, pid, display, hdl, resp);
                break;
            case ISBN:
                handleISBN(pidType, pid, display, hdl, resp);
                break;
            case BIBCODE:
                handleBIBCODE(pidType, pid, display, hdl, resp);
                break;
            default:
                noPidType(resp);
                break;
        }
    }

    private void noPidType(HttpServletResponse resp) throws IOException {
        resp.setCharacterEncoding("UTF-8");
        resp.setContentType("application/json");
        resp.getWriter().println("{\"error\": \"pid type can not be determind.\"}");
    }

    private String checkPidType(String pid) throws IOException {
        File providersFile = new File(config.getProvidersFilePath());
        File providersBackupFile = new File(config.getProvidersBackupFilePath());
        String providersFilePath;
        recognizedPid = null;
        if (providersFile.exists() || providersBackupFile.exists()) {
            if (providersFile.exists()) {
                providersFilePath = config.getProvidersFilePath();
            } else {
                providersFilePath = config.getProvidersBackupFilePath();
            }
            try {
                JsonObject jsonContent = readJsonFile(providersFilePath);
                if (jsonContent != null) {
                    JsonArray providers = (JsonArray) jsonContent.get("content");
                    providers.forEach(provider -> {
                        JsonArray regexesArray = provider.getAsJsonObject().get("regexes").getAsJsonArray();
                        String pidType = provider.getAsJsonObject().get("type").getAsString();
                        regexesArray.forEach(regexesItem -> {
                            String regex = regexesItem.toString().replace("\"", "").replace("\\\\", "\\");
                            if (!regex.startsWith("^")) {
                                regex = "^" + regex;
                            }
                            if (!regex.endsWith("$")) {
                                regex = regex + "$";
                            }
                            if (getPidType(pid, regex)) {
                                recognizedPid = pidType;
                            }
                        });
                    });
                }
            } catch (Exception e) {
                // Handle the exception here, e.g., log an error message or take corrective action.
            }
        }
        return recognizedPid;
    }

    private JsonObject readJsonFile(String providersFilePath) throws IOException {
        Path path = Paths.get(providersFilePath);
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            throw new FileNotFoundException("Provider file not found or not a regular file: " + providersFilePath);
        }
        try (FileReader reader = new FileReader(providersFilePath)) {
            JsonParser jsonParser = new JsonParser();
            return jsonParser.parse(reader).getAsJsonObject();
        }
    }

    private boolean getPidType(String pid, String regex) {
        Pattern pattern = Pattern.compile(regex.trim(), Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(pid.trim());
        return matchFound = matcher.find();
    }

    private String fetchUrnDeResourceUrl(String pid, String metadataEndpoint) {
        String urnMetadataURL = metadataEndpoint + pid;
        try {
            URL apiUrl = new URL(urnMetadataURL);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = reader.readLine()) != null) {
                    content.append(inputLine);
                }
                reader.close();
                connection.disconnect();
                String jsonContent = content.toString();
                JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
                JsonElement nbnUrl = jsonObject.get("data").getAsJsonObject().get("resolving_information").getAsJsonObject().get("url_info").getAsJsonObject().get("url");
                String redirectUrl = nbnUrl.toString().replace("\"", "");
                return redirectUrl;
            }
        } catch (Exception e) {
            // Log error or handle exception
        }
        return null;
    }

    private void redirect(String pidType, String pid, String display, String redirectUrl, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        String addr = "";
        try {
            addr = hdl.getRemoteAddr();
        } catch (Throwable t) {
        }
        try {
            URL apiUrl = new URL(redirectUrl);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
            } else if (responseCode == 301 || responseCode == 302 || responseCode == 307) {
                String newUrl = connection.getHeaderField("Location");
                URL url = new URL(newUrl);
                connection = (HttpURLConnection) url.openConnection();
                responseCode = connection.getResponseCode();
                hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, newUrl);
            } else {
                handleHttpError(responseCode, resp);
            }
            logPIDMRAccess(pidType, pid, display, responseCode, addr, AbstractMessage.RC_SUCCESS, hdl.getResponseTime());
            logIntoInfluxDB(pidType, pid, display, hdl.getResponseTime() + "ms", responseCode);
        } catch (IOException e) {
            handleHttpError(500, resp);
            logPIDMRAccess(pidType, pid, display, 500, addr, AbstractMessage.RC_ERROR, hdl.getResponseTime());
            logIntoInfluxDB(pidType, pid, display, hdl.getResponseTime() + "ms", 500);
        }
    }

    public void logIntoInfluxDB(String pidType, String pid, String display, String responseTime, Integer status) {
        String influxdbConfigFile = config.getInfluxdbConfigFile();
        StreamTable configTable = new StreamTable();
        File serverDir = new File(HSG.DEFAULT_CONFIG_SUBDIR_NAME);
        try {
            File configFile = new File(serverDir, influxdbConfigFile);
            if (configFile.exists()) {
                try {
                    configTable.readFromFile(configFile);
                    if (configTable.containsKey("influxdb_config")) {
                        Map<String, Object> influxdbConfig = (Map<String, Object>) configTable.get("influxdb_config");
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
                                    .time(System.currentTimeMillis(), TimeUnit.MILLISECONDS)
                                    .addField("pidType", pidType)
                                    .addField("pid", pid)
                                    .addField("display", display)
                                    .addField("status", status)
                                    .addField("responseTime", responseTime)
                                    .build();
                            try {
                                ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                            } catch (NumberFormatException e) {
                                System.err.println("Invalid number format for num_threads: " + num_threads);
                            }
                            ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                            CompletableFuture.runAsync(() -> {
                                try {
                                    influxDB.write(point);
                                } catch (Exception e) {
                                    System.err.println("Write failed: " + e.getMessage());
                                }
                            }, executor).thenRun(() -> {
                            });
                            executor.shutdown();
                        } catch (Exception e) {
                            logIntoInfluxDB(pidType, pid, display, responseTime, status);
                            System.err.println("Error transmiting the data: " + e.getMessage());
                        } finally {
                            influxDB.close();
                        }
                    }
                } catch (Exception e) {
                    System.err.println("Error reading configuration: " + e);
                }
            }
        } catch (Exception e) {
            e.printStackTrace(System.err);
            System.err.println("Error loading configuration: " + e);
        }
    }

    private void handleHttpError(int responseCode, HttpServletResponse resp) throws IOException {
        resp.setCharacterEncoding("UTF-8");
        resp.setContentType("application/json");
        switch (responseCode) {
            case 400:
                resp.getWriter().println("{\"400\": \"Bad Request\"}");
                break;
            case 401:
                resp.getWriter().println("{\"401\": \"Unauthorized\"}");
                break;
            case 402:
                resp.getWriter().println("{\"402\": \"Payment Required\"}");
                break;
            case 403:
                resp.getWriter().println("{\"403\": \"Forbidden\"}");
                break;
            case 404:
                resp.getWriter().println("{\"404\": \"Not Found\"}");
                break;
            case 422:
                resp.getWriter().println("{\"404\": \"Unprocessable Content\"}");
                break;
            case 500:
                resp.getWriter().println("{\"500\": \"Internal Server Error\"}");
                break;
            case 501:
                resp.getWriter().println("{\"501\": \"Not Implemented\"}");
                break;
            case 502:
                resp.getWriter().println("{\"502\": \"Bad Gateway\"}");
                break;
            case 503:
                resp.getWriter().println("{\"503\": \"Service Unavailable\"}");
                break;
            case 504:
                resp.getWriter().println("{\"504\": \"Gateway Timeout\"}");
                break;
            default:
                resp.getWriter().println("{\"error\": \"Unexpected response code: " + responseCode + "\"}");
                break;
        }
    }

    private void logPIDMRAccess(String pidType, String pid, String display, int status, String addr, int hdlResponseCode,long responseTime) {
        Main main = null;
        String hdlServerConfigPath = config.getHdlServerConfigPath();
        StreamTable configTable = new StreamTable();
        File serverDir = new File(hdlServerConfigPath);
        try {
            configTable.readFromFile(new File(serverDir, HSG.CONFIG_FILE_NAME));
        } catch (Exception e) {
            System.err.println("Error reading configuration: " + e);
            return;
        }

        try {
            main = new Main(serverDir, configTable);
            main.logAccess("HTTP:PIDMRHDLProxy", InetAddress.getByName(addr), AbstractMessage.OC_RESOLUTION, hdlResponseCode, pidType + ";" + pid + ";" + display + ";" + status, responseTime);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }

    private void handleDoi(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws HandleException, IOException {
        String redirectUrl = null;
        JsonArray resourceRedirectUrl = null;
        JsonElement dataciteResourceRedirectUrl;
        String cnType = null;

        pid = checkForCanonicalDoiFormat(pid);
        pid = pid.replace(DOI_PREFIX, "");

        if (display.contains("cn_")) {
            cnType = display.split("cn_")[1];
            display = RESOLVING_MODE_CN;
        }

        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = config.getEndpoints().get("DOI_LANDINGPAGE_ENDPOINT") + pid;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = handleMetadataMode(pid, resp);
                if (redirectUrl == null) return;
                break;
            case RESOLVING_MODE_RESOURCE:
                resourceRedirectUrl = handleResourceMode(pid, resp, hdl);
                if (resourceRedirectUrl == null) return;
                break;
            case RESOLVING_MODE_CN:
                if (cnType != null) {
                    redirectUrl = handleCnMode(pid, cnType);
                }
                break;
        }

        if (redirectUrl != null) {
            redirect(pidType, pid, display, redirectUrl, hdl, resp);
        } else if (resourceRedirectUrl != null) {
            processResourceRedirectUrl(resourceRedirectUrl, pidType, pid, display, hdl, resp);
        } else {
            redirect(pidType, pid, display, redirectUrl, hdl, resp);
        }
    }

    private String handleMetadataMode(String pid, HttpServletResponse resp) throws IOException {
        String doiProvider = getDoiProvider(pid);
        if (doiProvider == null) {
            noDoiProvider(resp);
            return null;
        }

        switch (doiProvider) {
            case CROSSREF:
                return config.getEndpoints().get("CROSSREF_METADATA_ENDPOINT") + pid;
            case DATACITE:
                return config.getEndpoints().get("DATACITE_METADATA_ENDPOINT") + pid;
            default:
                return null;
        }
    }

    private JsonArray handleResourceMode(String pid, HttpServletResponse resp, HDLServletRequest hdl) throws IOException {
        String doiProvider = getDoiProvider(pid);
        if (doiProvider == null) {
            noDoiProvider(resp);
            return null;
        }

        switch (doiProvider) {
            case CROSSREF:
                return fetchCrossrefDoiResourceUrl(config.getEndpoints().get("CROSSREF_METADATA_ENDPOINT") + pid);
            case DATACITE:
                JsonElement dataciteResourceRedirectUrl = fetchDataciteDoiResourceUrl(config.getEndpoints().get("DATACITE_METADATA_ENDPOINT") + pid);
                if (dataciteResourceRedirectUrl != null) {
                    String redirectUrl = dataciteResourceRedirectUrl.toString().replace("\"", "");
                    redirect(pidType, pid, display, redirectUrl, hdl, resp);
                }
                return null;
            default:
                return null;
        }
    }

    private String handleCnMode(String pid, String cnType) {
        String mimType = getMimType(cnType);
        String crossrefUrl = "https://api.crossref.org/works/" + pid + "/transform/" + mimType;
        try {
            URL apiUrl = new URL(crossrefUrl);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                return crossrefUrl;
            } else {
                return "https://data.crosscite.org/" + mimType + pid;
            }
        } catch (Exception e) {
            // Handle the exception here, e.g., log an error message or take corrective action.
            return null;
        }
    }

    private void processResourceRedirectUrl(JsonArray resourceRedirectUrl, String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        int size = resourceRedirectUrl.size();
        if (size == 1) {
            JsonElement url = resourceRedirectUrl.get(0).getAsJsonObject().get("URL");
            String redirectUrl = url.toString().replace("\"", "");
            redirect(pidType, pid, display, redirectUrl, hdl, resp);
        } else {
            JsonArray urlJsonArray = new JsonArray();
            for (JsonElement link : resourceRedirectUrl) {
                JsonObject linkObject = link.getAsJsonObject();
                String url = linkObject.get("URL").getAsString();
                urlJsonArray.add(url);
            }
            resp.setCharacterEncoding("UTF-8");
            resp.setContentType("application/json");
            resp.getWriter().println(urlJsonArray);
        }
    }

    private String checkForCanonicalDoiFormat(String pid) {
        Pattern pattern = Pattern.compile("^((https?://)?doi.org/).+$", Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(pid);
        boolean matchFound = matcher.find();
        if (matchFound) {
            pid = pid.split(matcher.group(1))[1];
        }
        return pid;
    }

    private void noDoiProvider(HttpServletResponse resp) throws IOException {
        resp.setCharacterEncoding("UTF-8");
        resp.setContentType("application/json");
        resp.getWriter().println("{\"error\": \"DOI provider can not be determind.\"}");
    }

    private String getDoiProvider(String pid) {
        String doiProvider = null;
        if (pid.contains("/")) {
            String doiProviderId = pid.split("/")[0];
            HandleValue[] vals;
            try {
                vals = resolveHandle(doiProviderId);
            } catch (HandleException e) {
                return doiProvider;
            }
            String dataStr;
            for (HandleValue val : vals) {
                String typeAsStr = val.getTypeAsString();
                if (typeAsStr.equals("HS_SERV")) {
                    dataStr = val.getDataAsString();
                    if (dataStr != null && dataStr.contains("/")) {
                        doiProvider = dataStr.toLowerCase().split("/")[1];
                        break;
                    }
                }
            }
        }
        return doiProvider;
    }

    private String getMimType(String cnType) {
        String mimType = null;
        switch (cnType) {
            case CN_BIBTEX:
                mimType = config.getMimTypes().get("CN_BIBTEX_MIMTYPE");
                break;
            case CN_TURTLE:
                mimType = config.getMimTypes().get("CN_TURTLE_MIMTYPE");
                break;
            case CN_RDF:
                mimType = config.getMimTypes().get("CN_RDF_MIMTYPE");
                break;
            case CN_CITATION:
                mimType = config.getMimTypes().get("CN_CITATION_MIMTYPE");
                break;
            default:
                break;
        }
        return mimType;
    }

    private JsonElement fetchDataciteDoiResourceUrl(String url) {
        try {
            String jsonContent = fetchContent(url);
            if (jsonContent != null) {
                JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
                return jsonObject.getAsJsonObject("data").getAsJsonObject("attributes").get("url");
            }
        } catch (Exception e) {
            // Handle the exception here, e.g., log an error message or take corrective action.
        }
        return null;
    }

    private JsonArray fetchCrossrefDoiResourceUrl(String url) {
        try {
            String jsonContent = fetchContent(url);
            if (jsonContent != null) {
                JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
                JsonObject messageObject = jsonObject.getAsJsonObject("message");
                // Check if the "message" object contains the "links" array
                if (messageObject.has("link") && messageObject.get("link").isJsonArray()) {
                    return messageObject.getAsJsonArray("link");
                } else {
                    // Handle the exception here, e.g., log an error message or take corrective action.
                    // Error ("No 'links' array found within the 'message' object.");
                }
            }
        } catch (Exception e) {
            // Handle the exception here, e.g., log an error message or take corrective action.
        }
        return null;
    }

    private String fetchContent(String url) {
        try {
            URL apiUrl = new URL(url);
            HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = reader.readLine()) != null) {
                    content.append(inputLine);
                }
                reader.close();
                connection.disconnect();
                return content.toString();
            } else {
                // Handle the exception here, e.g., log an error message or take corrective action.
                // Error: ("Failed to fetch data. HTTP response code: " + responseCode)
            }
        } catch (Exception e) {
            // Handle the exception here, e.g., log an error message or take corrective action.
        }
        return null;
    }

    private void handleZenodo(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        String documentId = extractDocumentId(pid);
        if (documentId == null) {
            // Handle the exception here, e.g., log an error message or take corrective action.
            // Error ("No match found");
            return;
        }

        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = config.getEndpoints().get("Zenodo_LANDINGPAGE_ENDPOINT") + documentId;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = config.getEndpoints().get("Zenodo_METADATA_ENDPOINT") + documentId;
                break;
            case RESOLVING_MODE_RESOURCE:
                handleZenodoResourceMode(pidType, pid, display, hdl, documentId, resp);
                return;  // Return here since handleZenodoResourceMode deals with the response
        }

        if (redirectUrl != null) {
            redirect(pidType, pid, display, redirectUrl, hdl, resp);
        }
    }

    private String extractDocumentId(String pid) {
        String regex = "(\\d+)$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(pid);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private void handleZenodoResourceMode(String pidType, String pid, String display, HDLServletRequest hdl, String documentId, HttpServletResponse resp) throws IOException {
        String metadataUrl = config.getEndpoints().get("Zenodo_RESOURCE_ENDPOINT") + documentId;
        String jsonContent = fetchContent(metadataUrl);

        if (jsonContent != null) {
            JsonArray metadataFiles = extractMetadataFiles(jsonContent);
            if (metadataFiles != null) {
                processMetadataFiles(pidType, pid, display, hdl, metadataFiles, resp);
            } else {
                // Handle the exception here, e.g., log an error message or take corrective action.
                // Error ("No 'files' array found within the JSON content.");
            }
        }
    }

    private JsonArray extractMetadataFiles(String jsonContent) {
        JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
        if (jsonObject.has("files") && jsonObject.get("files").isJsonArray()) {
            return jsonObject.getAsJsonArray("files");
        }
        return null;
    }

    private void processMetadataFiles(String pidType, String pid, String display, HDLServletRequest hdl, JsonArray metadataFiles, HttpServletResponse resp) throws IOException {
        int size = metadataFiles.size();
        if (size == 1) {
            String redirectUrl = metadataFiles
                    .get(0)
                    .getAsJsonObject()
                    .get("links")
                    .getAsJsonObject()
                    .get("self")
                    .getAsString();
            redirect(pidType, pid, display, redirectUrl, hdl, resp);
        } else {
            JsonArray urlJsonArray = new JsonArray();
            for (JsonElement link : metadataFiles) {
                String url = link.getAsJsonObject()
                        .get("links")
                        .getAsJsonObject()
                        .get("self")
                        .getAsString();
                urlJsonArray.add(url);
            }
            sendJsonResponse(urlJsonArray.toString(), resp);
        }
    }

    private void sendJsonResponse(String jsonArrayString, HttpServletResponse resp) {
        try {
            resp.setCharacterEncoding("UTF-8");
            resp.setContentType("application/json");
            resp.getWriter().println(jsonArrayString);
        } catch (IOException e) {
            // Handle the exception here, e.g., log an error message or take corrective action.
        }
    }

    private HandleValue[] resolveHandle(String handle) throws HandleException {
        byte[] handleBytes = Util.encodeString(handle);
        ResolutionRequest resolutionRequest = new ResolutionRequest(handleBytes, null, null, null);
        AbstractResponse response = super.resolver.processRequest(resolutionRequest, null);
        if (response.responseCode != AbstractMessage.RC_SUCCESS) {
            throw new HandleException(HandleException.INTERNAL_ERROR, response.toString());
        }
        if (response instanceof ResolutionResponse) {
            ResolutionResponse resResponse = (ResolutionResponse) response;
            return resResponse.getHandleValues();
        } else {
            throw new HandleException(HandleException.INTERNAL_ERROR, AbstractMessage.getResponseCodeMessage(response.responseCode));
        }
    }

    private void handleRedirect(String pidType, String pid, String display, String landingPageEndpoint, String metadataEndpoint, String resourceEndpoint, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = landingPageEndpoint != null ? landingPageEndpoint + pid : null;
                break;
            case RESOLVING_MODE_METADATA:
                if (metadataEndpoint != null) {
                    if (pidType.equals("arXiv")) {
                        String id = pid.split(":")[1];
                        redirectUrl = metadataEndpoint + id;
                    } else if (pidType.equals("swh")) {
                        redirectUrl = metadataEndpoint + pid + "?format=json";
                    } else if (pidType.equals("ark")) {
                        redirectUrl = metadataEndpoint + pid + "/?";
                    } else {
                        redirectUrl = metadataEndpoint + pid;
                    }
                }
                break;
            case RESOLVING_MODE_RESOURCE:
                if (resourceEndpoint != null) {
                    if (pidType.equals("arXiv")) {
                        redirectUrl = resourceEndpoint + pid + ".pdf";
                    } else if (pidType.equals("swh")) {
                        redirectUrl = resourceEndpoint + pid + "/raw/";
                    } else if (pidType.equals("Bibcode")) {
                        redirectUrl = resourceEndpoint + pid + "/PUB_PDF/";
                    } else if (pidType.equals("urn:nbn:de")) {
                        redirectUrl = fetchUrnDeResourceUrl(pid, metadataEndpoint);
                    }
                }
                break;
        }
        if (redirectUrl != null) {
            redirect(pidType, pid, display, redirectUrl, hdl, resp);
        }
    }
    private void handleZbl(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("Zbl_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("Zbl_METADATA_ENDPOINT"), null, hdl, resp);
    }

    private void handleSwmath(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("Swmath_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("Swmath_METADATA_ENDPOINT"), null, hdl, resp);
    }

    private void handleZbmath(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("Zbmath_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("Zbmath_METADATA_ENDPOINT"), null, hdl, resp);
    }

    private void handleOrcid(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("Orcid_LANDINGPAGE_ENDPOINT"), null, null, hdl, resp);
    }

    private void handleUrnFi(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("UrnFi_LANDINGPAGE_ENDPOINT"), null, null, hdl, resp);
    }

    private void handleArxiv(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("Arxiv_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("Arxiv_METADATA_ENDPOINT"), config.getEndpoints().get("Arxiv_RESOURCE_ENDPOINT"), hdl, resp);
    }

    private void handle21(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("Hdl_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("HDl_METADATA_ENDPOINT"), null, hdl, resp);
    }

    private void handleSwh(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("Swh_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("Swh_METADATA_ENDPOINT"), config.getEndpoints().get("Swh_RESOURCE_ENDPOINT"), hdl, resp);
    }

    private void handleRor(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("ROR_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("ROR_METADATA_ENDPOINT"), null, hdl, resp);
    }

    private void handleISLRN(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("ISLRN_LANDINGPAGE_ENDPOINT"), null, null, hdl, resp);
    }

    private void handleISNI(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("ISNI_LANDINGPAGE_ENDPOINT"), null, null, hdl, resp);
    }

    private void handleISBN(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("ISBN_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("ISBN_METADATA_ENDPOINT"), null, hdl, resp);
    }

    private void handleBIBCODE(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("BIBCODE_LANDINGPAGE_ENDPOINT"), null, config.getEndpoints().get("BIBCODE_RESOURCE_ENDPOINT"), hdl, resp);
    }

    private void handleArk(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("ARK_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("ARK_METADATA_ENDPOINT"), null, hdl, resp);
    }

    private void handleUrnDe(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        handleRedirect(pidType, pid, display, config.getEndpoints().get("UrnDe_LANDINGPAGE_ENDPOINT"), config.getEndpoints().get("UrnDe_METADATA_ENDPOINT"), config.getEndpoints().get("UrnDe_METADATA_ENDPOINT"), hdl, resp);
    }
}






















