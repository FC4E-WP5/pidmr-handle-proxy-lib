# pidmr-handle-proxy-lib



## Persistent Identifier Meta Resolver Proxy (PIDMR Proxy)

The PIDMRHDLProxy class is a Java servlet that acts as a proxy for resolving Persistent Identifiers (PIDs) using the Handle System. Extending the HDLProxy class, it provides additional functionality for handling various types of PIDs, including Digital Object Identifiers (DOIs), ARXIV IDs, ARKs, and more. It is designed to manage PID resolution requests within a Handle Server environment, facilitating the mapping of PIDs to their corresponding resources or metadata.

Key functionalities include:

    Initialization of configurations from a JSON file.
    Processing HTTP GET and POST requests to resolve PIDs.
    Dispatching requests to specific handling methods based on PID types.
    Redirecting requests and handling errors.

The PIDMRHDLProxy class serves as an intermediary between clients and the Handle Server, providing a robust framework for PID resolution and metadata retrieval for various research objects. This documentation outlines its purpose, structure, methods, and usage.