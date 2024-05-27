/**********************************************************************\
 © COPYRIGHT 2019 Corporation for National Research Initiatives (CNRI);
                        All rights reserved.

        The HANDLE.NET software is made available subject to the
      Handle.Net Public License Agreement, which may be obtained at
          http://hdl.handle.net/20.1000/112 or hdl:20.1000/112
\**********************************************************************/

package net.handle.pidmr;

import net.handle.apps.servlet_proxy.HDLServletRequest.ResponseType;
import net.handle.apps.servlet_proxy.HDLServletRequest;
import net.handle.apps.servlet_proxy.HDLProxy;
import net.handle.hdllib.*;

import javax.servlet.ServletException;
import javax.servlet.http.*;
import java.io.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

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
    private final String CROSSREF_METADATA_ENDPOINT = "https://api.crossref.org/works/";
    private final String DATACITE_METADATA_ENDPOINT = "https://api.datacite.org/dois/";
    private final String DOI_LANDINGPAGE_ENDPOINT = "https://dx.doi.org/";

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
                    display = RESOLVING_MODE_LANDINGPAGE;
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
                    display = RESOLVING_MODE_LANDINGPAGE;
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
        switch (pidType) {
            case "21":
            case "epic_old":
                handle21(pid, display, hdl);
                break;
            case "arXiv":
                handleArxiv(pid, display, hdl);
                break;
            case "ark":
                handleArk(pid, display, hdl);
                break;
            case "urn:nbn:de":
                handleUrnDe(pid, display, hdl);
                break;
            case "urn:nbn:fi":
                handleUrnFi(pid, display, hdl);
                break;
            case "doi":
                handleDoi(pid, display, hdl, resp);
                break;
            case "swh":
                String[] swhPidParts = pid.split(":");
                String swhType = swhPidParts[2];
                String swhHash = swhPidParts[3];
                if (display.equals(RESOLVING_MODE_RESOURCE)) {
                    handleSwh(swhHash, display, hdl);
                } else {
                    handleSwh(pid, display, hdl);
                }
                break;
            case "10.5281/zenodo":
                handleZenodo(pid, display, hdl, resp);
                break;
            case "orcid":
                handleOrcid(pid, display, hdl);
                break;
            case "zbMATH":
                handleZbmath(pid, display, hdl);
                break;
            case "swMATH":
                handleSwmath(pid, display, hdl);
                break;
            case "Zbl":
                handleZbl(pid, display, hdl);
                break;
            case "ROR":
                handleRor(pid, display, hdl);
                break;
            case "ISLRN":
                handleISLRN(pid, display, hdl);
                break;
            default:
                try {
                    noPidType(resp);
                    return;
                } catch (IOException e) {
                    // Handle the exception here, e.g., log an error message or take corrective action.
                }
                break;
        }
    }

    private void noPidType(HttpServletResponse resp) throws IOException {
        resp.setCharacterEncoding("UTF-8");
        resp.setContentType("application/json");
        resp.getWriter().println("{\"error\": \"pid type can not be determind.\"}");
    }

    private String checkPidType(String pid) throws IOException {
        // This assumes that the handle proxy server redides in /home/providers directory
        String providersFilePath = "/home/providers/providers.json";
        String providersBackupFilePath = "/home/providers/providers_backup.json";
        File providersFile = new File(providersFilePath);
        File providersBackupFile = new File(providersBackupFilePath);
        recognizedPid = null;
        if (providersFile.exists() || providersBackupFile.exists()) {
            if (!providersFile.exists()) {
                providersFilePath = providersBackupFilePath;
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

    private void handleSwh(String pid, String display, HDLServletRequest hdl) {
        // Handle SWH URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://archive.softwareheritage.org/" + pid;
                break;
            case RESOLVING_MODE_METADATA:
                String id = pid.split(":")[1];
                redirectUrl = "https://archive.softwareheritage.org/api/1/resolve/" + pid + "?format=json";
                break;
            case RESOLVING_MODE_RESOURCE:
                redirectUrl = "https://archive.softwareheritage.org/browse/content/sha1_git:" + pid + "/raw/";
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }
    private void handle21(String pid, String display, HDLServletRequest hdl) {
        // Handle 21 URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://hdl.handle.net/" + pid;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = "https://hdl.handle.net/" + pid + "?noredirect";
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }
    private void handleArxiv(String pid, String display, HDLServletRequest hdl) {
        // Handle Arxiv URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://arxiv.org/abs/" + pid.substring(6);
                break;
            case RESOLVING_MODE_METADATA:
                String id = pid.split(":")[1];
                redirectUrl = "http://export.arxiv.org/oai2?verb=GetRecord&metadataPrefix=oai_dc&identifier=oai:arXiv:org:" + id;
                break;
            case RESOLVING_MODE_RESOURCE:
                redirectUrl = "https://arxiv.org/pdf/" + pid + ".pdf";
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private void handleUrnDe(String pid, String display, HDLServletRequest hdl) {
        // Handle URN DE URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://nbn-resolving.org/redirect/" + pid;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = "https://nbn-resolving.org/json/" + pid;
                break;
            case RESOLVING_MODE_RESOURCE:
                String urnMetadataURL = "https://nbn-resolving.org/json/" + pid;
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
                        redirectUrl = nbnUrl.toString().replace("\"", "");
                    } else {
                        // Handle the exception here, e.g., log an error message or take corrective action.
                        // Error ("Failed to fetch data. HTTP response code: " + responseCode);
                    }
                } catch (Exception e) {
                    // Handle the exception here, e.g., log an error message or take corrective action.
                }
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private void handleUrnFi(String pid, String display, HDLServletRequest hdl) {
        // Handle URN FI URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://urn.fi/" + pid;
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private void handleDoi(String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) throws HandleException, IOException {
        String redirectUrl = null;
        JsonArray resourceRedirectUrl = null;
        JsonElement dataciteResourceRedirectUrl;
        String cnType = null;
        String doiProvider;
        pid = checkForCanonicalDoiFormat(pid);
        if (pid.contains("doi:")) {
            pid = pid.split("doi:")[1];
        }
        if (display.contains("cn_")) {
            cnType = display.split("cn_")[1];
            display = "cn";
        }
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = DOI_LANDINGPAGE_ENDPOINT + pid;
                break;
            case RESOLVING_MODE_METADATA:
                doiProvider = getDoiProvider(pid);
                if (doiProvider == null) {
                    noDoiProvider(resp);
                    return;
                }
                switch (doiProvider) {
                    case "crossref":
                        redirectUrl = CROSSREF_METADATA_ENDPOINT + pid;
                        break;
                    case "datacite":
                        redirectUrl = DATACITE_METADATA_ENDPOINT + pid;
                        break;
                }
                break;
            case RESOLVING_MODE_RESOURCE:
                doiProvider = getDoiProvider(pid);
                if (doiProvider == null) {
                    noDoiProvider(resp);
                    return;
                }
                switch (doiProvider) {
                    case "crossref":
                        resourceRedirectUrl = fetchCrossrefDoiResourceUrl(CROSSREF_METADATA_ENDPOINT + pid);
                        break;
                    case "datacite":
                        dataciteResourceRedirectUrl = fetchDataciteDoiResourceUrl(DATACITE_METADATA_ENDPOINT + pid);
                        if (dataciteResourceRedirectUrl != null) {
                            redirectUrl = dataciteResourceRedirectUrl.toString().replace("\"", "");
                        }
                        break;
                }
                break;
            case RESOLVING_MODE_CN:
                if (cnType != null) {
                    String mimType = getMimType(cnType);
                    String crossrefUrl = "https://api.crossref.org/works/" + pid + "/transform/" + mimType;
                    try {
                        URL apiUrl = new URL(crossrefUrl);
                        HttpURLConnection connection = (HttpURLConnection) apiUrl.openConnection();
                        connection.setRequestMethod("GET");
                        int responseCode = connection.getResponseCode();
                        if (responseCode == 200) {
                            redirectUrl = crossrefUrl;
                        } else {
                            redirectUrl = "https://data.crosscite.org/" + mimType + pid;
                        }
                    } catch (Exception e) {
                        // Handle the exception here, e.g., log an error message or take corrective action.
                    }
                }
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        } else if (resourceRedirectUrl != null) {
            int size = resourceRedirectUrl.size();
            if (size == 1) {
                JsonElement url = resourceRedirectUrl
                        .get(0)
                        .getAsJsonObject()
                        .get("URL");
                redirectUrl = url.toString().replace("\"", "");
                hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
            } else {
                JsonArray urlJsonArray = new JsonArray();
                for (JsonElement link : resourceRedirectUrl) {
                    JsonObject linkObject = link.getAsJsonObject();
                    String url = linkObject.get("URL").getAsString();
                    urlJsonArray.add(url);
                }
                try {
                    resp.setCharacterEncoding("UTF-8");
                    resp.setContentType("application/json");
                    resp.getWriter().println(urlJsonArray);
                } catch (IOException e) {
                    // Handle the exception here, e.g., log an error message or take corrective action.
                }
            }
        } else {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, DOI_LANDINGPAGE_ENDPOINT + pid);
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

    private void handleOrcid(String pid, String display, HDLServletRequest hdl) {
        // Handle URN FI URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://orcid.org/" + pid;
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private void handleZbmath(String pid, String display, HDLServletRequest hdl) {
        // Handle zbMATH URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://zbmath.org/authors/" + pid;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = "https://api.zbmath.org/v1/author/" + pid;
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private void handleSwmath(String pid, String display, HDLServletRequest hdl) {
        // Handle swMATH URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://zbmath.org/software/" + pid;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = "https://api.zbmath.org/v1/software/" + pid;
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private void handleZbl(String pid, String display, HDLServletRequest hdl) {
        // Handle swMATH URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://zbmath.org/" + pid;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = "https://api.zbmath.org/v1/document/" + pid;
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private void handleRor(String pid, String display, HDLServletRequest hdl) {
        // Handle swMATH URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://ror.org/" + pid;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = "https://api.ror.org/v1/organizations/" + pid;
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private void handleISLRN(String pid, String display, HDLServletRequest hdl) {
        // Handle ISLRN URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://www.islrn.org/resources/" + pid;
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private String getMimType(String cnType) {
        String mimType = null;
        switch (cnType) {
            case CN_BIBTEX:
                mimType = "application/x-bibtex/";
                break;
            case CN_TURTLE:
                mimType = "text/turtle/";
                break;
            case CN_RDF:
                mimType = "application/rdf+xml/";
                break;
            case CN_CITATION:
                mimType = "application/vnd.citationstyles.csl+json/";
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

    private void handleArk(String pid, String display, HDLServletRequest hdl) {
        // Handle Ark URLs
        String redirectUrl = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://n2t.net/" + pid;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = "https://n2t.net/" + pid + "/?";
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
        }
    }

    private void handleZenodo(String pid, String display, HDLServletRequest hdl, HttpServletResponse resp) {
        // Handle Zenodo URLs
        String regex = "(\\d+)$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(pid);
        String documentId = null;
        if (matcher.find()) {
            documentId = matcher.group(1);
        } else {
            // Handle the exception here, e.g., log an error message or take corrective action.
            // Error ("No match found");
        }
        String redirectUrl = null;
        JsonArray redirectUrl1 = null;
        JsonArray metadataFiles = null;
        switch (display) {
            case RESOLVING_MODE_LANDINGPAGE:
                redirectUrl = "https://zenodo.org/record/" + documentId;
                break;
            case RESOLVING_MODE_METADATA:
                redirectUrl = "https://zenodo.org/api/records/" + documentId;
                break;
            case RESOLVING_MODE_RESOURCE:
                String metadataUrl = "https://zenodo.org/api/records/" + documentId;
                String jsonContent = fetchContent(metadataUrl);

                if (jsonContent != null) {

                    JsonObject jsonObject = JsonParser.parseString(jsonContent).getAsJsonObject();
                    if (jsonObject.has("files") && jsonObject.get("files").isJsonArray()) {
                        metadataFiles = jsonObject.getAsJsonArray("files");
                    } else {
                        // Handle the exception here, e.g., log an error message or take corrective action.
                        // Error ("No 'links' array found within the 'message' object.");
                    }
                    if (metadataFiles != null) {
                        int size = metadataFiles.size();
                        if (size == 1) {
                            JsonElement url1 = metadataFiles
                                    .get(0)
                                    .getAsJsonObject()
                                    .get("links")
                                    .getAsJsonObject()
                                    .get("self");
                            redirectUrl = url1.toString().replace("\"", "");
                        } else {
                            JsonArray urlJsonArray = new JsonArray();
                            for (JsonElement link : metadataFiles) {
                                JsonObject linkObject = link.getAsJsonObject().get("links").getAsJsonObject();
                                String url2 = linkObject.get("self").getAsString();
                                urlJsonArray.add(url2);
                            }
                            String jsonArrayString = urlJsonArray.toString();
                            try {
                                resp.setCharacterEncoding("UTF-8");
                                resp.setContentType("application/json");
                                resp.getWriter().println(jsonArrayString);
                            } catch (IOException e) {
                                // Handle the exception here, e.g., log an error message or take corrective action.
                            }
                        }
                    }
                }
                break;
        }
        if (redirectUrl != null) {
            hdl.sendHTTPRedirect(ResponseType.MOVED_PERMANENTLY, redirectUrl);
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
}
