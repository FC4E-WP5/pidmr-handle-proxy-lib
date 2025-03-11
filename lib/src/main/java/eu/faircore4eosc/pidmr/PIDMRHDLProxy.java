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

import java.util.Arrays;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Optional;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.cnri.util.StreamTable;
import net.handle.apps.servlet_proxy.HDLProxy;
import net.handle.apps.servlet_proxy.HDLServletRequest;
import net.handle.apps.servlet_proxy.HDLServletRequest.ResponseType;
import net.handle.apps.servlet_proxy.RotatingAccessLog;

import net.handle.hdllib.*;
import net.handle.server.Main;
import net.handle.server.servletcontainer.HandleServerInterface;

import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.dto.Point;
import org.influxdb.dto.Query;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

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
    private boolean supportedMode = false;
    private final Integer TIME_OUT = 10000;
    protected HandleServerInterface handleServer;
    List<Integer> redirectHttpCodes = Arrays.asList(300, 301, 302, 303, 304, 305, 306, 307, 308);

    private ConfigLoader.Config config;

    public enum PidType {
        EPIC,
        EPIC_OLD,
        ARXIV,
        ARK,
        URN_NBN_CH,
        URN_NBN_DE,
        URN_NBN_FI,
        URN_NBN_NL,
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
        ISSN,
        BIBCODE,
        DBGAP,
        PRIDE,
        PUBMED,
        BIOSAMPLE,
        EAN13,
        RAID,
        GENOME_ID,
        GND,
        ISAN,
        CVCL,
        INCHIKEY,
        WIKIDATA,
        DID,
        IGSN,
        LCCN,
        COL,
        LDC,
        NANOPUB,
        PMCID,
        DBVAR,
        ScopusAuthorID,
        GDS_ID,
        GDZ,
        ZB_Pub,
        DigiZeitschriften,
        IdRef,
        UNKNOWN;

        private static final Map<String, PidType> TYPE_MAP = new HashMap<>();

        static {
            String[][] mappings = {
                    {"epic", "EPIC"},
                    {"epic_old", "EPIC_OLD"},
                    {"arXiv", "ARXIV"},
                    {"ark", "ARK"},
                    {"urn:nbn:ch", "URN_NBN_CH"},
                    {"urn:nbn:de", "URN_NBN_DE"},
                    {"urn:nbn:fi", "URN_NBN_FI"},
                    {"urn:nbn:nl", "URN_NBN_NL"},
                    {"doi", "DOI"},
                    {"swh", "SWH"},
                    {"10.5281/zenodo", "ZENODO"},
                    {"orcid", "ORCID"},
                    {"zbMATH", "ZBMATH"},
                    {"swMATH", "SWMATH"},
                    {"Zbl", "ZBL"},
                    {"ROR", "ROR"},
                    {"ISLRN", "ISLRN"},
                    {"ISNI", "ISNI"},
                    {"ISBN", "ISBN"},
                    {"ISSN", "ISSN"},
                    {"Bibcode", "BIBCODE"},
                    {"dbGaP", "DBGAP"},
                    {"PRIDE", "PRIDE"},
                    {"PubMed", "PUBMED"},
                    {"BioSample", "BIOSAMPLE"},
                    {"EAN13", "EAN13"},
                    {"RAiD", "RAID"},
                    {"Genome_ID", "GENOME_ID"},
                    {"GND", "GND"},
                    {"ISAN", "ISAN"},
                    {"CVCL", "CVCL"},
                    {"InChiKey", "INCHIKEY"},
                    {"Wikidata", "WIKIDATA"},
                    {"DID", "DID"},
                    {"IGSN", "IGSN"},
                    {"LCCN", "LCCN"},
                    {"COL", "COL"},
                    {"LDC", "LDC"},
                    {"nanopub", "NANOPUB"},
                    {"PMCID", "PMCID"},
                    {"dbVar", "DBVAR"},
                    {"ScopusAuthorID", "ScopusAuthorID"},
                    {"GDS_ID", "GDS_ID"},
                    {"GDZ", "GDZ"},
                    {"ZB_Pub", "ZB_Pub"},
                    {"IdRef", "IdRef"},
                    {"DigiZeitschriften", "DigiZeitschriften"}
            };

            for (String[] mapping : mappings) {
                TYPE_MAP.put(mapping[0], PidType.valueOf(mapping[1]));
            }
        }

        public static PidType fromString(String type) {
            return TYPE_MAP.getOrDefault(type, PidType.UNKNOWN);
        }
    }

    public enum EndpointType {
        ZBL("Zbl_LANDINGPAGE_ENDPOINT", "Zbl_METADATA_ENDPOINT"),
        SWMATH("Swmath_LANDINGPAGE_ENDPOINT", "Swmath_METADATA_ENDPOINT"),
        ZBMATH("Zbmath_LANDINGPAGE_ENDPOINT", "Zbmath_METADATA_ENDPOINT"),
        ORCID("Orcid_LANDINGPAGE_ENDPOINT", null),
        URN_NBN_FI("UrnFi_LANDINGPAGE_ENDPOINT", null),
        URN_NBN_NL("UrnNl_LANDINGPAGE_ENDPOINT", null),
        ARXIV("Arxiv_LANDINGPAGE_ENDPOINT", "Arxiv_METADATA_ENDPOINT", "Arxiv_RESOURCE_ENDPOINT"),
        EPIC("Hdl_LANDINGPAGE_ENDPOINT", "HDl_METADATA_ENDPOINT"),
        EPIC_OLD("Hdl_LANDINGPAGE_ENDPOINT", "HDl_METADATA_ENDPOINT"),
        SWH("Swh_LANDINGPAGE_ENDPOINT", "Swh_METADATA_ENDPOINT", "Swh_RESOURCE_ENDPOINT"),
        ROR("ROR_LANDINGPAGE_ENDPOINT", "ROR_METADATA_ENDPOINT"),
        ISLRN("ISLRN_LANDINGPAGE_ENDPOINT", null),
        ISNI("ISNI_LANDINGPAGE_ENDPOINT", null),
        ISBN("ISBN_LANDINGPAGE_ENDPOINT", "ISBN_METADATA_ENDPOINT"),
        ISSN("ISSN_LANDINGPAGE_ENDPOINT", "ISSN_METADATA_ENDPOINT"),
        BIBCODE("BIBCODE_LANDINGPAGE_ENDPOINT", null, "BIBCODE_RESOURCE_ENDPOINT"),
        ARK("ARK_LANDINGPAGE_ENDPOINT", "ARK_METADATA_ENDPOINT"),
        URN_NBN_DE("UrnDe_LANDINGPAGE_ENDPOINT", "UrnDe_METADATA_ENDPOINT", "UrnDe_RESOURCE_ENDPOINT"),
        URN_NBN_CH("UrnCh_LANDINGPAGE_ENDPOINT", "UrnCh_METADATA_ENDPOINT", "UrnCh_RESOURCE_ENDPOINT"),
        DBGAP("DBGAP_LANDINGPAGE_ENDPOINT", null),
        PRIDE("PRIDE_LANDINGPAGE_ENDPOINT", null),
        PUBMED("PubMed_LANDINGPAGE_ENDPOINT", null),
        BIOSAMPLE("BioSample_LANDINGPAGE_ENDPOINT", null),
        EAN13("EAN13_LANDINGPAGE_ENDPOINT", null),
        GENOME_ID("GENOME_ID_LANDINGPAGE_ENDPOINT", null),
        GND("GND_LANDINGPAGE_ENDPOINT", "GND_METADATA_ENDPOINT"),
        ISAN("ISAN_LANDINGPAGE_ENDPOINT", null),
        CVCL("CVCL_LANDINGPAGE_ENDPOINT", null),
        INCHIKEY("InChiKey_LANDINGPAGE_ENDPOINT", null),
        WIKIDATA("Wikidata_LANDINGPAGE_ENDPOINT", "Wikidata_METADATA_ENDPOINT"),
        DID("DID_LANDINGPAGE_ENDPOINT", null),
        IGSN("IGSN_LANDINGPAGE_ENDPOINT", null),
        LCCN("LCCN_LANDINGPAGE_ENDPOINT", "LCCN_METADATA_ENDPOINT"),
        COL("COL_LANDINGPAGE_ENDPOINT", null),
        LDC("LDC_LANDINGPAGE_ENDPOINT", null),
        NANOPUB("NANOPUB_LANDINGPAGE_ENDPOINT", "NANOPUB_METADATA_ENDPOINT"),
        PMCID("PMCID_LANDINGPAGE_ENDPOINT", null),
        DBVAR("DBVAR_LANDINGPAGE_ENDPOINT", null),
        ScopusAuthorID("ScopusAuthorID_LANDINGPAGE_ENDPOINT", null),
        GDS_ID("GDS_ID_LANDINGPAGE_ENDPOINT", null),
        GDZ("GDZ_LANDINGPAGE_ENDPOINT", "GDZ_METADATA_ENDPOINT", "GDZ_RESOURCE_ENDPOINT"),
        ZB_Pub("ZB_Pub_LANDINGPAGE_ENDPOINT", "ZB_Pub_METADATA_ENDPOINT"),
        DigiZeitschriften("DigiZeitschriften_LANDINGPAGE_ENDPOINT", "DigiZeitschriften_METADATA_ENDPOINT"),
        IdRef("IdRef_LANDINGPAGE_ENDPOINT", null),

        RAID("RAiD_LANDINGPAGE_ENDPOINT", null, null) {
            @Override
            public String preprocessPid(String pid) {
                return checkForCanonicalFormat(pid);
            }
        };

        private final String landingPageEndpoint;
        private final String metadataEndpoint;
        private final String resourceEndpoint;

        EndpointType(String landingPageEndpoint, String metadataEndpoint) {
            this(landingPageEndpoint, metadataEndpoint, null);
        }

        EndpointType(String landingPageEndpoint, String metadataEndpoint, String resourceEndpoint) {
            this.landingPageEndpoint = landingPageEndpoint;
            this.metadataEndpoint = metadataEndpoint;
            this.resourceEndpoint = resourceEndpoint;
        }

        public String getLandingPageEndpoint() {
            return landingPageEndpoint;
        }

        public String getMetadataEndpoint() {
            return metadataEndpoint;
        }

        public String getResourceEndpoint() {
            return resourceEndpoint;
        }

        public String preprocessPid(String pid) {
            return pid;
        }
    }

    private static final String DOI_PREFIX = "doi:";
    private static final String CROSSREF = "crossref";
    private static final String DATACITE = "datacite";
    private static final String JALC = "jalc";

    private static final String PID_TYPE_21 = "epic";
    private static final String PID_TYPE_EPIC_OLD = "epic_old";

    // Precompile the common regex pattern for efficiency
    private static final Pattern CANONICAL_FORMAT_PATTERN = Pattern.compile("https:\\/\\/[^\\/]+\\/(?:doi:)?(.+)", Pattern.CASE_INSENSITIVE);

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

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        HDLServletRequest hdl = new HDLServletRequest(this, req, resp, resolver);
        String pidType = checkPidType(hdl.hdl);
        if (pidType == null) {
            errorHandling(resp, HttpServletResponse.SC_BAD_REQUEST, "PID type can not be determind.");
            return;
        }
        if (PID_TYPE_21.equals(pidType) || PID_TYPE_EPIC_OLD.equals(pidType)) {
            handleSpecialPidTypes(req, resp);
            return;
        }
        if (!checkForSupportedResolutionMode(resp, hdl.params.getParameter("display"), pidType)) {
            handleHttpError(400, resp, "Resolution mode is not supported.");
            return;
        }
        handleNormalPidType(hdl, resp, pidType);
    }

    private void handleSpecialPidTypes(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        try {
            super.doPost(req, resp);
        } catch (Exception e) {
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "Error in super.doPost: " + e.getMessage());
            errorHandling(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An internal error occurred.");
        }
    }

    private void handleNormalPidType(HDLServletRequest hdl, HttpServletResponse resp, String pidType) throws IOException, ServletException {
        String display = hdl.params.getParameter("display");
        if (display == null || display.trim().isEmpty()) {
            display = sanitizeInput(config.getResolvingModes().get("RESOLVING_MODE_LANDINGPAGE"));
        }
        String pid = sanitizeInput(hdl.hdl);
        try {
            dispatchPidHandlingMode(pid, display, hdl, pidType, resp);
        } catch (HandleException e) {
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "Error dispatching PID handling mode: " + e.getMessage());
            errorHandling(resp, HttpServletResponse.SC_BAD_REQUEST, "Error dispatching PID handling mode.");
        }
    }

    @Override
    public void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
        HDLServletRequest hdl = new HDLServletRequest(this, req, resp, resolver);
        if (!hdl.hdl.contains("PIDMR@")) {
            if (req.getQueryString() != null) {
                if (req.getQueryString().contains("&")) {
                    pid = req.getQueryString().split("&")[0];
                    display = req.getQueryString().split("&")[1];
                } else {
                    pid = req.getQueryString();
                }
                if (display == null) {
                    display = config.getResolvingModes().get("RESOLVING_MODE_LANDINGPAGE");
                }
                if (pid != null) {
                    pidType = checkPidType(pid);
                    if (!checkForSupportedResolutionMode(resp, display, pidType)) {
                        handleHttpError(400, resp, "Resolution mode is not supported.");
                        return;
                    }

                    if (pidType != null) {
                        try {
                            dispatchPidHandlingMode(pid, display, hdl, pidType, resp);
                        } catch (HandleException e) {
                            throw new RuntimeException(e);
                        }
                        return;
                    } else {
                        errorHandling(resp, HttpServletResponse.SC_BAD_REQUEST, "PID type can not be determind.");
                        return;
                    }
                }
            }
        }
        if (handleSpecial(req, resp)) return;
        super.doGet(req, resp);
    }

    public String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        PolicyFactory policy = Sanitizers.FORMATTING.and(Sanitizers.LINKS);
        return policy.sanitize(input);
    }

    private boolean checkForSupportedResolutionMode(HttpServletResponse resp, String display, String pidType) {
        supportedMode = false;
        JsonArray providers = getProviders();
        providers.forEach(provider -> {
            JsonArray resolutionModes = getProviderElementGivenTheType("resolution_modes", provider);
            String tempPidType = getProviderType(provider);

            if (tempPidType.equals(pidType)) {
                resolutionModes.forEach(resolutionMode -> {
                    String tempResolutionMode = resolutionMode.getAsJsonObject().get("mode").getAsString();
                    if (tempResolutionMode.equals(display)) {
                        supportedMode = true;
                    }
                });
            }
        });
        return supportedMode;
    }

    private void dispatchPidHandlingMode(String pid, String display, HDLServletRequest hdl, String pidType, HttpServletResponse resp) throws IOException, ServletException, HandleException {
        PidType type = PidType.fromString(pidType);
        Map<PidType, RequestHandler> handlerMap = new HashMap<>();
        handlerMap.put(PidType.DOI, (p, r) -> handleDoi(pidType, pid, display, hdl, r));
        handlerMap.put(PidType.ZENODO, (p, r) -> handleZenodo(pidType, pid, display, hdl, r));
        handlerMap.put(PidType.SWH, (p, r) -> {
            String[] swhPidParts = pid.split(":");
            String swhHash = swhPidParts[3];
            String resolvedPid = display.equals(RESOLVING_MODE_RESOURCE) ? swhHash : pid;
            handleRequest(EndpointType.SWH, pidType, resolvedPid, display, hdl, r);
        });

        RequestHandler defaultHandler = (p, r) -> {
            try {
                EndpointType endpoint = EndpointType.valueOf(type.name());
                handleRequest(endpoint, pidType, pid, display, hdl, r);
            } catch (IllegalArgumentException e) {
                errorHandling(r, HttpServletResponse.SC_BAD_REQUEST, "The PID type can not be determined.");
            }
        };

        RequestHandler handler = handlerMap.getOrDefault(type, defaultHandler);

        try {
            handler.handle(pid, resp);
        } catch (IOException | ServletException | HandleException e) {
            e.printStackTrace();
            errorHandling(resp, HttpServletResponse.SC_BAD_REQUEST, "The PID type can not be determined.");
        }
    }

    @FunctionalInterface
    public interface RequestHandler {
        void handle(String pid, HttpServletResponse resp) throws IOException, ServletException, HandleException;
    }

    private void errorHandling(HttpServletResponse resp, int errorCode, String errorMessage) throws IOException {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");
        resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("errorCode", errorCode);
        errorResponse.put("error", errorMessage);
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(errorResponse);
        resp.getWriter().write(jsonResponse);
    }

    private JsonArray getProviders() {
        File providersFile = new File(config.getProvidersFilePath());
        File providersBackupFile = new File(config.getProvidersBackupFilePath());
        String providersFilePath;
        if (providersFile.exists() || providersBackupFile.exists()) {
            if (providersFile.exists()) {
                providersFilePath = config.getProvidersFilePath();
            } else {
                providersFilePath = config.getProvidersBackupFilePath();
            }
            try {
                JsonObject providersFileContent = readProvidersFile(providersFilePath);
                if (providersFileContent != null) {
                    JsonArray providers = (JsonArray) providersFileContent.get("content");
                    return providers;
                }
            } catch (Exception e) {
                super.logError(RotatingAccessLog.ERRLOG_LEVEL_FATAL, "Providers list could not be fetched: " + e.getMessage());
            }
        }
        return null;
    }

    private JsonArray getProviderElementGivenTheType(String providerElement, JsonElement provider) {
        JsonArray providerElementArray = provider.getAsJsonObject().get(providerElement).getAsJsonArray();
        return providerElementArray;
    }

    private String getProviderType(JsonElement provider) {
        String pidType = provider.getAsJsonObject().get("type").getAsString();
        return pidType;
    }

    private String checkPidType(String pid) throws IOException {
        recognizedPid = null;
        try {
            JsonArray providers = getProviders();
            providers.forEach(provider -> {
                JsonArray regexesArray = getProviderElementGivenTheType("regexes", provider);
                String pidType = getProviderType(provider);
                regexesArray.forEach(regexesItem -> {
                    String regex = regexesItem.toString().replace("\"", "").replace("\\\\", "\\");
                    if (!regex.startsWith("^")) {
                        regex = "^" + regex;
                    }
                    if (!regex.endsWith("$")) {
                        regex = regex + "$";
                    }
                    if (isPidMatchingPattern(pid, regex)) {
                        recognizedPid = pidType;
                    }
                });
            });
        } catch (Exception e) {
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_FATAL, "PID type could not be determined: " + e.getMessage());
        }
        return recognizedPid;
    }

    private JsonObject readProvidersFile(String providersFilePath) throws IOException {
        Path path = Paths.get(providersFilePath);
        if (!Files.exists(path) || !Files.isRegularFile(path)) {
            throw new FileNotFoundException("Provider file not found or not a regular file: " + providersFilePath);
        }
        try (FileReader reader = new FileReader(providersFilePath)) {
            JsonParser jsonParser = new JsonParser();
            return jsonParser.parse(reader).getAsJsonObject();
        }
    }

    public boolean isPidMatchingPattern(String pid, String regex) {
        return matchPidToRegexPattern(pid, regex).find();
    }

    private static Matcher matchPidToRegexPattern(String pid, String regex) {
        Pattern pattern = Pattern.compile(regex.trim(), Pattern.CASE_INSENSITIVE);
        return pattern.matcher(pid.trim());
    }

    private String fetchUrnDeChResourceUrl(String pid, String metadataEndpoint) {
        String urnMetadataURL = String.format(metadataEndpoint, pid);
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
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "Error fetching urn:nbn:de/ch resource url: " + e.getMessage());
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
            connection.setConnectTimeout(TIME_OUT);
            connection.setReadTimeout(TIME_OUT);
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
            } else if (redirectHttpCodes.contains(responseCode)) {
                String newUrl = connection.getHeaderField("Location");
                URL url = new URL(newUrl);
                connection = (HttpURLConnection) url.openConnection();
                responseCode = connection.getResponseCode();
                hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, newUrl);
            } else {
                handleHttpError(responseCode, resp, connection.getResponseMessage());
            }
            logPIDMRAccess(pidType, pid, display, responseCode, addr, AbstractMessage.RC_SUCCESS, hdl.getResponseTime());
            logIntoInfluxDB(pidType, pid, display, redirectUrl, hdl.getResponseTime() + "ms", responseCode);
        } catch (IOException e) {
            handleHttpError(500, resp, e.getMessage());
            logPIDMRAccess(pidType, pid, display, 500, addr, AbstractMessage.RC_ERROR, hdl.getResponseTime());
            logIntoInfluxDB(pidType, pid, display, redirectUrl,hdl.getResponseTime() + "ms", 500);
        }
    }

    public void logIntoInfluxDB(String pidType, String pid, String display, String redirectUrl, String responseTime, Integer status) {
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
                                    .time(System.currentTimeMillis() / 1000L, TimeUnit.MILLISECONDS)
                                    .addField("time_stamp", getLogDateTime())
                                    .addField("pid_endpoint", redirectUrl)
                                    .addField("pid_type", pidType)
                                    .addField("pid_id", pid)
                                    .addField("pid_mode", display)
                                    .addField("pid_resolver_status", status)
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
                            super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "Error transmiting the data to influxdb: " + e.getMessage());
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

    private String getLogDateTime() {
        LocalDateTime localDateTime = LocalDateTime.now();
        DateTimeFormatter dateTimeFormat = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
        String formattedDateTime = localDateTime.format(dateTimeFormat);
        return formattedDateTime;
    }
    
    private void handleHttpError(int responseCode, HttpServletResponse resp, String errmsg) throws IOException {
        errorHandling(resp,responseCode, errmsg);
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
        String cnType = null;
        pid = checkForCanonicalFormat(pid);
        pid = pid.replace(DOI_PREFIX, "");
        if (display.contains("cn_")) {
            cnType = display.split("cn_")[1];
            display = RESOLVING_MODE_CN;
        }
        String doiProvider = getDoiProvider(pid);
        if (doiProvider == null) {
            noDoiProvider(resp);
            return;
        }
        try {
            switch (display) {
                case RESOLVING_MODE_LANDINGPAGE:
                    redirectUrl = getDoiLandingPageUrl(pid);
                    performRedirect(pidType, pid, display, redirectUrl, hdl, resp);
                    break;
                case RESOLVING_MODE_METADATA:
                    redirectUrl = handleDoiMetadataMode(pid, resp);
                    if (redirectUrl == null) {
                        sendError(404, resp, "No metadata found for: " + pid);
                    } else {
                        performRedirect(pidType, pid, display, redirectUrl, hdl, resp);
                    }
                    break;
                case RESOLVING_MODE_RESOURCE:
                    handleDoiResourceMode(pidType, pid, display, doiProvider, hdl, resp);
                    break;
                case RESOLVING_MODE_CN:
                    if (cnType != null) {
                        redirectUrl = handleCnMode(pid, cnType);
                        performRedirect(pidType, pid, display, redirectUrl, hdl, resp);
                    }
                    break;
                default:
                    sendError(400, resp, "Unsupported resolving mode: " + display);
            }
        } catch (Exception e) {
            sendError(500, resp, "Internal server errorxxx: " + e.getMessage());
        }
    }


    private String getDoiLandingPageUrl(String pid) {
        return String.format(config.getEndpoints().get("DOI_LANDINGPAGE_ENDPOINT"), pid);
    }

    private void handleDoiResourceMode(String pidType, String pid, String display, String doiProvider, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        String dataciteResourceRedirectUrl = null;
        JsonArray crossrefResourceRedirectUrl = null;
        switch (doiProvider) {
            case CROSSREF:
                crossrefResourceRedirectUrl = fetchCrossrefDoiResourceUrl(
                        String.format(config.getEndpoints().get("CROSSREF_METADATA_ENDPOINT"), pid)
                );
                if (crossrefResourceRedirectUrl == null) {
                    sendError(404, resp, "No resource found for: " + pid);
                    return;
                }
                processResourceRedirectUrl(crossrefResourceRedirectUrl, pidType, pid, display, hdl, resp);
                break;
            case DATACITE:
            case JALC:
                dataciteResourceRedirectUrl = fetchDataciteDoiResourceUrl(
                        String.format(config.getEndpoints().get("DATACITE_METADATA_ENDPOINT"), pid)
                );
                if (dataciteResourceRedirectUrl == null) {
                    sendError(404, resp, "No resource found for: " + pid);
                    return;
                }
                if (dataciteResourceRedirectUrl != null) {
                    dataciteResourceRedirectUrl = dataciteResourceRedirectUrl.replace("\"", "");
                }
                performRedirect(pidType, pid, display, dataciteResourceRedirectUrl, hdl, resp);
                break;
            default:
                sendError(400, resp, "Unsupported DOI provider: " + doiProvider);
        }
    }

    private void performRedirect(String pidType, String pid, String display, String redirectUrl, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        redirect(pidType, pid, display, redirectUrl, hdl, resp);
    }

    private void sendError(int statusCode, HttpServletResponse resp, String message) throws IOException {
        handleHttpError(statusCode, resp, message);
    }

    private String handleDoiMetadataMode(String pid, HttpServletResponse resp) throws IOException {
        String doiProvider = getDoiProvider(pid);
        if (doiProvider == null) {
            noDoiProvider(resp);
            return null;
        }
        switch (doiProvider) {
            case CROSSREF:
                return String.format(config.getEndpoints().get("CROSSREF_METADATA_ENDPOINT"), pid);
            case DATACITE:
                return String.format(config.getEndpoints().get("DATACITE_METADATA_ENDPOINT"), pid);
            case JALC:
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
            sendJsonResponse(urlJsonArray.toString(), resp);
        }
    }

    public static String checkForCanonicalFormat(String pid) {
        return extractCanonicalPid(pid).orElse(pid);
    }

    public static Optional<String> extractCanonicalPid(String pid) {
        Matcher matcher = CANONICAL_FORMAT_PATTERN.matcher(pid.trim());
        if (matcher.find()) {
            return Optional.of(matcher.group(1));
        }
        return Optional.empty();
    }

    private void noDoiProvider(HttpServletResponse resp) throws IOException {
        errorHandling(resp, HttpServletResponse.SC_BAD_REQUEST, "DOI provider can not be determind.");
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

    private String fetchDataciteDoiResourceUrl(String url) {
        try {
            String jsonContent = fetchContent(url);
            if (jsonContent != null) {
                JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
                String redirectUrl = jsonObject.getAsJsonObject("data").getAsJsonObject("attributes").get("url").toString();
                if (redirectUrl != null) {
                    return redirectUrl;
                }
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
                if (messageObject.has("link") && messageObject.get("link").isJsonArray()) {
                    return messageObject.getAsJsonArray("link");
                } else {
                    super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "No resource link for crossref doi found.");
                }
            }
        } catch (Exception e) {
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_FATAL, "Crossref resource link could not be fetched.");
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
                redirectUrl = String.format(config.getEndpoints().get("Zenodo_LANDINGPAGE_ENDPOINT"), documentId);
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = String.format(config.getEndpoints().get("Zenodo_METADATA_ENDPOINT"), documentId);
                break;
            case RESOLVING_MODE_RESOURCE:
                handleZenodoResourceMode(pidType, pid, display, hdl, documentId, resp);
                return;
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
        String metadataUrl = String.format(config.getEndpoints().get("Zenodo_RESOURCE_ENDPOINT"), documentId);
        String jsonContent = fetchContent(metadataUrl);
        if (jsonContent != null) {
            JsonArray metadataFiles = extractMetadataFiles(jsonContent);
            if (metadataFiles != null) {
                processMetadataFiles(pidType, pid, display, hdl, metadataFiles, resp);
            } else {
                super.logError(RotatingAccessLog.ERRLOG_LEVEL_NORMAL, "No metadata found in metadata file.");
                errorHandling(resp, HttpServletResponse.SC_NOT_FOUND, "No metadata found.");
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
            super.logError(RotatingAccessLog.ERRLOG_LEVEL_FATAL, "Failed to send resource link list: " + e.getMessage());
            try {
                errorHandling(resp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred while processing the request.");
            } catch (IOException ioException) {
                super.logError(RotatingAccessLog.ERRLOG_LEVEL_FATAL, "Failed to send error response to client: " + e.getMessage());
            }
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

    private void handleRedirect(String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp, String landingPageEndpoint, String metadataEndpoint, String resourceEndpoint) throws IOException {
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = landingPageEndpoint != null ? String.format(landingPageEndpoint, pid) : null;
                break;
            case RESOLVING_MODE_METADATA:
                if (metadataEndpoint != null) {
                    if (pidType.equals("arXiv")) {
                        pid = pid.split(":")[1];
                    }
                    redirectUrl = String.format(metadataEndpoint, pid);
                }
                break;
            case RESOLVING_MODE_RESOURCE:
                if (pidType.equals("urn:nbn:de") || pidType.equals("urn:nbn:ch")) {
                    redirectUrl = fetchUrnDeChResourceUrl(pid, metadataEndpoint);
                } else if (pidType.equals("GDZ")) {
                    redirectUrl = String.format(resourceEndpoint, pid, pid);
                } else {
                    redirectUrl = String.format(resourceEndpoint, pid);
                }
                break;
        }
        if (redirectUrl != null) {
            redirect(pidType, pid, display, redirectUrl, hdl, resp);
        }
    }

    private void handleRequest(EndpointType type, String pidType, String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws IOException {
        String processedPid = type.preprocessPid(pid);
        handleRedirect(
                pidType,
                processedPid,
                display,
                hdl,
                resp,
                config.getEndpoints().get(type.getLandingPageEndpoint()),
                config.getEndpoints().get(type.getMetadataEndpoint()),
                config.getEndpoints().get(type.getResourceEndpoint())
        );
    }
}
