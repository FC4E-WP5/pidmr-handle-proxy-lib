# pidmr-handle-proxy-lib

### Requirements
- Java 8 (or 11 or 18)
- Gradle 8.7

## Persistent Identifier Meta Resolver Proxy (PIDMR Proxy)

The PIDMRHDLProxy class is a Java servlet that acts as a proxy for resolving Persistent Identifiers (PIDs) using the Handle System. Extending the HDLProxy class, it provides additional functionality for handling various types of PIDs, including Digital Object Identifiers (DOIs), ARXIV IDs, ARKs, and more. It is designed to manage PID resolution requests within a Handle Server environment, facilitating the mapping of PIDs to their corresponding resources or metadata.

Key functionalities include:

    Initialization of configurations from a JSON file.
    Processing HTTP GET and POST requests to resolve PIDs.
    Dispatching requests to specific handling methods based on PID types.
    Redirecting requests and handling errors.

The PIDMRHDLProxy class serves as an intermediary between clients and the Handle Server, providing a robust framework for PID resolution and metadata retrieval for various research objects. This documentation outlines its purpose, structure, methods, and usage.

Please note that the Servlet is tested with Java Version 8, 11 and 18.

## PIDMR Proxy Integration

For the integration of the PIDMR Handle Proxy the following adaptions should be made in Handle Software.

### Adaption of the build.gradle

Add the following to the repositories section since the lib is currently hosted locally assuming Handle Software is installed under /opt/hsj:

    flatDir {
    dirs("/opt/hsj/handle-9.3.1/lib")
    }

and the following to the dependencies section

    compile name: 'pidmrhdlproxy-0.1'

### Adaption of Main.java

1) Importing PIDMRHDLProxy Servlet


    import net.handle.pidmr.PIDMRHDLProxy;

2) Registering PIDMRHDLProxy Servlet include replacing the following:


    ServletHolder hdlProxy = new ServletHolder(HDLProxy.class.getName(), HDLProxy.class);

with the following:

    ServletHolder pidmrhdlProxy = new ServletHolder(PIDMRHDLProxy.class.getName(), PIDMRHDLProxy.class);

3) Adding the servlet include replacing the following:


    context.getServletHandler().addServlet(hdlProxy);

with the following:

    context.getServletHandler().addServlet(pidmrhdlProxy);

4) Adding PIDMRHDLProxy route mapping as the default routing include replacing the following:


    mapping.setServletName(HDLProxy.class.getName());

with the following

    mapping.setServletName(PIDMRHDLProxy.class.getName());

### Integrating the PIDMRHDLProxy servlet in Handle Software

To build the jar archive execute the following command:

    ./gradlew build

This assumes that you have already installed gradle.For the PIDMRHDLProxy to take effect place the created jar archive in the
lib folder of the Handle Software located at:
    
    handle-9.3.1/lib/

assuming that the current Handle Software version 9.3.1 is installed.
    
### Functionality of PIDMR Handle Proxy

POST requests sent via the resolving form are received by the doPost method in the above servlet. Some parameters are sent with the request including the pid (hdl), a resolution mode (display) from either landingpage, metadata or resource and a flag (redirect) for whether to redirect the request to a given url in the database or process the request by the Handle Proxy server itself. The provided flag (redirect) is native to Handle Software itself and is only used for processing Handle PIDs.

First step is to determine the type of the PID provided by the request. For determination of the PID type the information provided by the PIDMR API for providers is used.

Upon determining the PID type a corresponding handling of the request is executed based on the resolution mode. For landingpage and metadata mode a redirect request is sent to the local PID resolution service API. For resource mode, provided the local provider provides the information, the metadata of the requested PID is fetched, processed and the required resource end point is extracted from the metadata to which the resource mode request is then sent.