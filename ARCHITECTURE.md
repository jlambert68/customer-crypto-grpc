# System architecture

The diagram shows the logical process boundaries and data flow in this educational demo. All six client identities are separate from the server identity; the CLI is launched separately for each identity. The localhost REST gateway can load one of the five customer or back-office identity files selected in its browser UI. The rotation process is privileged and can access plaintext during re-encryption.

```mermaid
flowchart TB
    W["Browser web client<br/>Select demo identity<br/>Read and update forms"]
    G["Local REST client gateway<br/>Selected identity credentials<br/>Structured console logs"]
    S[("gRPC server + SQLite<br/>Encrypted customer records<br/>Server-only key shares<br/>Grants and rotation jobs")]
    subgraph CUSTOMERS[Customer clients]
      C1["Customer 1<br/>Own private share"]
      C2["Customer 2<br/>Own private share"]
      C3["Customer 3<br/>Own private share"]
    end
    subgraph BACKOFFICE[Back-office clients]
      B1["Back office 1<br/>Customers 1 and 2"]
      B2["Back office 2<br/>Customers 2 and 3"]
    end
    R["Separate rotation process<br/>Decrypt locally<br/>Generate fresh DEK<br/>Re-encrypt and upload"]
    W <-->|"HTTP/JSON on localhost"| G
    G <-->|"gRPC as selected identity"| S
    S <-->|"gRPC: ciphertext + partial key results"| C1
    S <-->|"gRPC: ciphertext + partial key results"| C2
    S <-->|"gRPC: ciphertext + partial key results"| C3
    S <-->|"gRPC: authorized requests"| B1
    S <-->|"gRPC: authorized requests"| B2
    S <-->|"gRPC: jobs + encrypted versions"| R
```

**Trust boundary:** The server's application API does not require plaintext or DEKs. The REST gateway is a client process and handles plaintext plus the selected identity's token and private share. Because its dropdown deliberately permits identity impersonation, it must remain local and is not a production authentication design. The bootstrap process is trusted and initially generates both sets of key shares; this demo does not establish security against a compromised provisioning environment or a malicious server. The rotation process also handles plaintext and DEKs.
