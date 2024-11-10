# Security Engineer Interview Prep

---

## NAT

- NAT is the process where a network device usually a firewall assigns a public address to a computer in a private network
    - IP Conservation - the number of devices accessing the internet far surpasses the number of IP addresses available. Routing all of these devices via one connection using NAT helps to consolidate multiple private IP addresses into one public IP address. This helps to keep more public IP addresses available even while private IP addresses proliferate.
    - NAT Security - Because NAT transfers packets of data from public to private addresses, it also prevents anything else from accessing the private device.
- IPv4 vs IPv6 and NAT - 2^128 addresses in case of ipv6 ensure we no longer need NAT for IP Conservation

---

## DNS

- Primary Zone :
- Secondary Zone :
- Stub Zone :
- DNS Requests are usually UDP - unless specified by server, The Transmission Control Protocol (TCP) is used when the response data size exceeds 512 bytes, or for tasks such as zone transfers.
- DNS Requests work backwards - 1. Find authoritative server for .com domain , then for google, then for www
- DNScat - used to setup a malicious DNS server that can now communicate with a client
- DNS Filtering can be used to block requests to known malicious domains and thus blocking those requests (OpenDNS ex of such a service)
- DNS Sinkhole - spoofed DNS server to prevent resolving malicious or blacklisted requests to known websites by assigning a forwarding address that the user now gets redirected to . Sinkholes change the flow of traffic by entering Fake DNS entries and possibly displaying a block page
- Black-holing vs sinkholing - Blackholing the packets are lost/dropped (availability compromised, user has no way of knowing their packet was dropped) . Sinkholing the traffic is redirected to an alternate server for further investigation.
- WannaCry attack and DNS Sinkholing
- Reverse DNS Lookups - looking up by IP instead of hostname
- DNS Exfilteration - sending data as subdomains so it doesn't show up in HTTP logs
- DNS configs
    - Start of Authority (SOA).
    - IP addresses (A and AAAA).
    - SMTP mail exchangers (MX).
    - Name servers (NS).
    - Pointers for reverse DNS lookups (PTR).
    - Domain name aliases (CNAME).

<aside>
💡

Requests do not show up in HTTP logs - DNS exfilteration 

DNS Sinkholing/Blackholing

</aside>

---

## ARP

- MAC to IP Mapping for L2
- ARP attack surface
    - Does not verify that the response comes from a authorized source
    - Let's host accept response even if request was never sent out
- IPv6 uses Neighbor Discovery Protocol that is encrypted and verifies source
- ARP SPOOFING/ARP POISONING -
- Attacker finds IP address of 1 workstation and 1 router
- ARPSPOOF or other tools to send forged ARP responses
- Makes workstation and router believe its the MAC address of each other , establising MITM
- Devices now communicate through attacker instead of each other
    - Consequences :
        - Sniff packets
        - Access session ID - and perform Session Hijacking
        - Pushing malicious file to workstation
        - DDoS - the attackers can provide the MAC address of a server they wish to attack with DDoS, instead of their own machine. If they do this for a large number of IPs, the target server will be bombarded with traffic.
    - Prevention:
        - Using VPN - encrypts traffic making it useless to the attacker
        - Static ARP -
        - Packet filtering to detect contradicting ARP information - block ARP packets from unwanted sources

---

DHCP

- DHCPDISCOVER -> DHCPOFFER -> DHCPREQUEST -> DHCPACK
- DHCP starvation attack :
    - Deny service to legitimate users
    - Attacker can send multiple fake DHCPDISCOVERs and use up the IP pool
    - Legitimate users now don't have an IP
    - They go to another DHCP server that could be attacker's to get an IP, including default DNS and gateway information
    - Default gateway could be attackers
    - MITM
- Mitigations - Port Security ( not comprehensive)

---

Traceroute

- Works by sending packets with short TTLs
- TTL is decremented at every hop
- when TTL is exceeded - ICMP msg is sent informing this
- While ICMP messages can't be blocked, packets with artificially low TTLs can

---

VPN

---

Firewalls and Policies

---

PKI

Here’s a concise, step-by-step process of how **PKI (Public Key Infrastructure)** works:

1. **Key Generation**: Each user or entity generates a pair of cryptographic keys: a **public key** (shared) and a **private key** (kept secret).
2. **Certificate Issuance**: The user’s public key, along with identifying information, is sent to a **Certificate Authority (CA)**. The CA verifies the identity and issues a **digital certificate** binding the public key to the user's identity.
3. **Certificate Distribution**: The CA-signed certificate is distributed to users and systems across the network, establishing trust by associating the certificate with the identity.
4. **Authentication and Encryption**: When a secure connection is needed, the certificate is used to authenticate the identity, and the **public key** encrypts data sent to the certificate holder.
5. **Decryption with Private Key**: The certificate holder uses their **private key** to decrypt the data, ensuring only the intended recipient can access it.
6. **Certificate Validation**: Clients validate the certificate through a trusted CA chain and check its validity using **OCSP** or **CRLs** to ensure it hasn’t been revoked.

This process allows for secure, authenticated communication across insecure networks.

Hashing plays a key role in **digital certificates** within PKI, specifically in verifying the authenticity and integrity of the certificate itself. Here’s how hashing fits in:

1. **Certificate Creation**:
    - When a **Certificate Authority (CA)** issues a certificate, it uses a **hash function** to create a unique "fingerprint" (hash value) for the certificate's contents (such as the public key and identity information).
2. **Digital Signature**:
    - The CA then **encrypts this hash** with its **private key**, creating a **digital signature**. This signature is included in the certificate. The signature guarantees that the certificate was indeed issued by the CA and has not been altered.
3. **Certificate Validation**:
    - When a client (such as a browser) receives the certificate, it uses the CA's **public key** to decrypt the digital signature, revealing the original hash value created by the CA.
    - The client then **hashes the certificate’s contents** itself and compares this hash with the one obtained from the digital signature.
    - If the two hashes match, the certificate is authentic and unchanged; if not, the certificate may have been tampered with.

---

TOR

Users can generally be tracked if they are -

1. Using identifiable metadata (e.g., document properties).
2. Reusing usernames or email addresses.
3. Misconfiguring privacy settings or allowing active scripts (JavaScript).
4. Inconsistent anonymity practices (switching networks).

---

Session Hijacking

---

OWASP Top 10

## Broken Access Control

Description :
1. Violation of principle of least priv or deny by default
2. Bypassing access control by Parameter Tampering, Forced Browsing, modifying API requests,
3. Insecure Direct Object Reference
4. Accessing API with missing access control for GET, PUT, POST
5. Elevation of priv
6. Metadata manipulation - Replaying or tampering with JWT, abusing JWT invalidation, cookies
7. CORS misconfiguration allows API access from unauthorized/untrusted origins
Prevention:

1. Except for public resources, deny by default
2. Uniform access control throughout the application
3. Enforce record ownership
4. Disable directory listing, ensure metadata and backup are not in web root
5. log and alert access control failure
6. Rate limit API
7. Timely invalidation of stateful session identifiers

1. Path Traversal :
2. CSRF (Cross Site Request Forgery) - Make a victim do something they didn't wanna do. Change account email, delete account etc
    - Requirements for CSRF -
        - A relevant Action
        - Cookie based session handling
        - No unpredictable parameters
    - Prevention - CSRF TOKENS
        - Unpredictable with high entropy, as for session tokens in general.
        - Tied to the user's session.
        - Strictly validated in every case before the relevant action is executed.
    - Prevention - SameSite Cookies
        - Make sure the browser does not include the cookies by default (Strict Mode)
        - Lax mode - only for GET requests and never for links that execute scripts etc
    - Prevention - Referrer Header - used to verify the source of request is from within the org
    - Content Security Policy : allows developers to define a set of rules about the types of content that are allowed to be executed (script-src, img-src etc.)
3. GET vs PUT vs POST - Security
- GET parameters are passed via URL. This means that parameters are stored in server logs, and browser history. When using GET, it makes it very easy to alter the data being submitted the the server as well, as it is right there in the address bar to play with.
- POST will not deter a malicious user though
- GET recommended for read access to static data only
1. JWT Attacks
- JWT used for session management, authentication, access control
- JSON Web Token
- Used to send information about users for session mgt, access control etc.
- Stored client side with JWT
- Why use tokens at all?
    - This way the users credentials (username/password) is only sent to the server once and never stored/cached for future requests, which keeps their details secure.
    - The downside of token auth is that the database is hit at least once for every request.
    - JWT uses encryption and hashing contrast to DB hits
- How does JWT work?
    - Authenticate against the db (username/password)
    - Once done, server generates a token based on a secret key
    - key known only by the server
    - Client now includes this token in subsequent requests
    - server only needs to decrypt it using the key
    - no DB hits needed
- JWT Format
    - Header - Base64
    - Payload - Base 64
    - Signature
- Attack Surface
    - Flawed handling of JWT
    - Improperly verifying signatures - implementing only decode() not verify()
    - Brute forcing keys (Hashcat)
- Prevention :
    - Use an up-to-date library
    - Verify all signatures, ensure encryption ensured
    - Prevent against parameter tampering
    - Use expiry date for tokens and enable feature to revoke tokens
1. SOP (Same Origin Policy)
- Ensures cross domain requests aren't allowed

---

### CORS

- Cross Origin Resource Sharing
- allows one domain to request resources from another domain
- Extends flexibility to SOP
- Ensure whitelists are properly implemented and not too permissive

Security Risks: 

1. CSRF : 
    1. How? Allows a malicious user to send requests on a user’s behalf
2. Sensitive Data Exposure:
    1. How? If the API returns sensitive info, anyone can request and see it
3. Script Injection:
    1. How? Attacker can execute malicious scripts with an overtly permissive CORS

How to secure 

1. Restrict allowed domains to only have those origins that are authorised to access the API
2. Sending preflight requests to confirm whether the request is valid/allowed (use OPTIONS when performing actions other than GET) - 
    1. why? Ensures client-side denial before a request hits the server/starts being processed 
3. Restrict allowed HTTP methods

### SOP

Restricts how a document/script loaded from one origin can interact w resources from another origin 

CORS extends SOP

---

## Cryptographic Failures

Description:
1. Ensure data is not transmitted in clear text.  ( HTTPS, TLS, FTP)
2. Strong encryption algorithms
3. Is encryption enforced? Proper HTTP Headers
4. Proper validation of  Server certification chain
5. Encryption vs Auth Encryption usage 
6. Appropriate randomness function used
7. Are MD4 or SHA1 used? PKCS 1 vs 1.5?
Prevention
1. Classify and accordingly encrypt data at rest or transit
2. Up-to-date strong algorithms
3. Data in Transit - TLS with Forward Secrecy (FS), HSTS
4. Disable for caching for sensitive data
5. Do not use legacy protocols like FTP, SMTP
6. Store properly stored passwords such as scrypt, bcrypt
7. auth encryption instead of encryption

1. TLS vs SSL
    
    TLS only protects the information being transmitted (Transport Layer) 
    
    Information about the data is not protected - unlike IPSec (Application Layer)
    
    TLS has the following phases - 
    
    Negotiates four key algorithms:
    
    1. Key Exchange
    2. Encryption
    3. Digital Signature
    4. Hashing
    
    **1. Handshake Phase** 
    
    1. TLS version
    2. Key used
    3. Key Exchange (How to choose key)
    4. Certificate the server will use to prove their identity
    5. Does the client need a cert? 
    6. Cipher Suite
    1. Application Phase
    
    Examples of these algorithms include:
    
    - Certificate verification: RSA, ECDSA, etc.
    - Key exchange: ECDHE, DHE, RSA, etc.
    - Bulk encryption: AES-GCM, ChaCha20-Poly1305, etc.
    - Hashing: SHA-1, SHA-256, etc.
    - TLS provides -
        - Confidentiality
        - Integrity
        - Replay Prevention
        - Authentication - authenticating the server to the client
    - SSL was originally used but had several cryptographic vulnerabilities
    - How does TLS work?
        - Specify which version of TLS (TLS 1.0, 1.2, 1.3, etc.) they will use
        - Decide on which cipher suites (see below) they will use
        - Authenticate the identity of the server via the server’s public key and the SSL certificate authority’s digital signature
        - Generate session keys in order to use symmetric encryption after the handshake is complete
    - Use strong algorithms for encryption and enforce them on the server
    - Application
        - Do not include non-TLS content on TLS pages
        - Use "Secure" cookie flag - which instructs the browser to only send them over encrypted HTTPS connections
        - Prevent caching of sensitive data - data might be stored unencrypted in the browser
        - HSTS - enforce use of HTTPS
2. Hashing vs Encryption
    - Hashing is a one-way function, encryption is not
    - Salting - A salt is a unique, randomly generated string that is added to each password as part of the hashing process.
    - Peppering - After hashing, HMAC or encrypt the hashes with a symmetrical encryption key before storing the password hash in the database, with the key acting as the pepper
3. Encryption vs Authenticated Encryption
    - Encryption + calculating a MAC using a Hash function, this is compared while decrypting to ensure data was not altered in transit
4. What's wrong with FTP or SMTP?
    - FTP uses clear text username:passwords to authenticate
    - SMTP does not use encryption or authentication ( alternatives, S/MIME)
5. What is Forward Secrecy? - systems change encryption frequently and automatically ensuring future sessions are not compromised if a key is compromised.
6. Forward secrecy is preventative while Backward Secrecy is mitigative.

---

## Injection Attacks

Description :

1. User supplied input is not sanitized
2. Dynamic queries or non-parametrised queries used without context-aware escaping
3. Hostile data in ORM (Object-Relational Mapping)
4. Hostile data directly used/concatenated

Prevention:

1. Use Safe APIs
2. Positive server-side input validation
3. LIMIT for SQL queries
4. Parametrised Queries & Stored Procedures :
- JAVA : JDBC API Prepared Statements - setString and setNum functions ensure data is passed in the expected format
- Using the Python DB API, don't do this:

```
# Do NOT do it this way.
cmd = "update people set name='%s' where id='%s'" % (name, id)
curs.execute(cmd)

```

This builds a SQL string using Python's string formatting, but it creates an unsafe string that is then passed through to the database and executed.
Instead, do this:

```
cmd = "update people set name=%s where id=%s"
curs.execute(cmd, (name, id))

```

This sets up placeholders so that the database can fill in the data values properly and safely.

- Stored Procedure :
    - Server side procedure
    - Stored in the db
    - exposed to client via language connections
    - reduce traffic over network
    - reduced client side processing since the server doesn't need to recompile queries everytime
- Parametrised Queries :
    - with prepared statements the server stores the partial structure representing the query and returns to the client a statement handle representing this partially processed query

## Command Injection

Allowing unauthorized commands to be executed.

Mitigations:

1. Safe API usage : like subprocess.run() and Parametrization
2. Input sanitization
3. Run w least priv
4. Sandboxing
5. Use predefined commands rather than letting users have free reign

## Insecure Serialisation and Deserialisation

- What is serialisation? : The process of converting objects into flatter format for transmission
- Helps writing data to inter-process memory
- easy network transmission
- Deserialisation - converting stream of bytes into object
- Data can be converted intro binary or stream of bytes of varying readability (language dependent)
- aka pickling in python
- KEY : USER INPUT SHOULD NEVER BE DESERIALISED
- Deserialisation attacks can be executed well before the data is actually deserialised rendering post-action checks useless
- Prevention : Digital signatures to check integrity of data, BEFORE deserialising
- JAVA Serialisation format and identification
    - Always begin with the same byte "ac ed" - Hex "rO0 "in Base64.
    - Classes implementing - java.io.Serializable
    - readObject() method

## XXE (XML eXternal Entity)

- Interfere with application's processing of XML Data
- applications use XML to transfer data between browser to server
- External XML Entities are loaded from outside the DTD in which they are declared
- Types of XXE Attacks:
    - XXE to retrieve files
    - To perform SSRF
        - In the following XXE example, the external entity will cause the server to make a back-end HTTP request to an internal system within the organization's infrastructure:
        - <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "[http://internal.vulnerable-website.com/](http://internal.vulnerable-website.com/)"> ]>
    - blind XXE to exfiltrate data
    - blind XXE to retrieve data through error messages
- Introduce a new DOCTYPE to fetch required data and read it from the response
- The application performs no particular defences against XXE attacks, so you can exploit the XXE vulnerability to retrieve the /etc/passwd file by submitting the following XXE payload:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
- Attack Surface : HTTP Traffic includes XML Content
1. ORM
- Injection vuln. exists in code generated by ORM
- 
1. SQL Injection
2. Working of Buffer Overflow attack and defences
- BUFFER OVERFLOW ATTACKS
    - Buffer Overflow Explained
    - 

### XSS :

- Stored
- Reflected
- DOM

### Cookies vs Session ID :

- Sessions maintain user auth while they navigate an app since HTTP is stateless
- Cookies store information about user activity while they use an application, stored client side
- CSRF tokens are used to validate requests are coming from a legitimate source/user

### what can we get using the XSS JS execution

- Cookies
- Session ID : is a one-of-a-kind number that is temporarily stored on the server, is what is used to identify the user. It is either a cookie, a form field, or a URL that is saved.
- CSRF Tokens
- 
1. Threat vs Vulnerability vs Risk
- Vulnerability : Weakness, flaw or shortcoming in a system
- Threat : Anything that could exploit a vulnerability
- Risk : Probability of event occurring and potential scale of harm
1. Rainbow Tables : It is a precomputed dictionary of plaintext passwords and their corresponding hash values that can be used to find out what plaintext password produces a particular hash.

---

## Insecure Design

Description:

1. Requirements and Resource management :
2. SDLC :
3. Secure Design :

---

Cookies - XSS Mitigation and Impact

1. httponly cookies are not a preventive measure for XSS
2. They do minimise impact
3. Make sure JS cannot access cookies and that they are sent only over an HTTP connection - protects against session token exfiltration
4. Without the token, cookie can be stolen using document.cookie
5. HttpOnly cookies are still the only standard mechanism for persisting session tokens that cannot be exfiltrated during an XSS attack.
6. Scenarios where this doesn't work against XSS :
    1. your browser does not support HttpOnly
    2. there is a hitherto unknown vulnerability in the browser which breaks HttpOnly
    3. the server has been compromised (but then you're probably hosed anyway).

---

Cross Site Tracing

1. XSS + TRACE/TRACK Method
2. Used to bypass HttpOnly tag for cookies and access the cookie
3. Some browsers don't allow JS to run TRACE anymore but this can still be done using JAVA

---

File Inclusion Vulnerability

1. Local File Inclusion : Local file inclusion exploit (also known as LFI) is the process of including files that are already locally present on the server, through the exploitation of vulnerable inclusion procedures implemented in the application.
2. Remote File Inclusion : including remote resources

---

SSRF (Server Side Request Forgery)

1. Allows attacker to induce servers to make requests to an unintended location
2. SSRF attacks exploit trust relationships to escalate an attack from vulnerable applications and perform unauthorised actions
3. SSRF attacks against the server itself : Makes the application send a request to its loopback interface
    - Why do applications behave in this way, and implicitly trust requests that come from the local machine? This can arise for various reasons:
        1. The access control check might be implemented in a different component that sits in front of the application server. When a connection is made back to the server itself, the check is bypassed.
        2. For disaster recovery purposes
        3. The administrative interface might be listening on a different port number than the main application, and so might not be reachable directly by users.
4. SSRF attacks against other back-end systems : the application server is able to interact with other back-end systems that are not directly reachable by users
5. Open Redirection is also an interesting way to bypass conventional SSRF Defences
    1. For example, suppose the application contains an open redirection vulnerability in which the following URL:
    2. /product/nextProduct?currentProductId=6&path=http://evil-user.net returns a redirection to: [http://evil-user.net](http://evil-user.net/)

---

Containers vs VMs vs Clusters : What are these about?

1. Containers :
    1. Package just enough files needed to run an app, share the OS
    2. Lightweight
    3. Easy to move
2. VMs
    1. Have their own OS, useful for running resource intensive operations

In terms to uses : containers are best used to:

- Build cloud-native apps
- Package microservices
- Instill DevOps or CI/CD practices
- Move scalable IT projects across a diverse IT footprint that shares the same OS

VMs are best used to:

- House traditional, legacy, and monolithic workloads
- Isolate risky development cycles
- Provision infrastructural resources (such as networks, servers, and data)
- Run a different OS inside another OS (such as running Unix on Linux)

Hardware

1. NODE : A node is the smallest unit of a cluster, simply put - a combination of CPU & RAM
2. CLUSTER : Nodes pool together to form a powerful machine. Nodes load balance to ensure the workloads are efficiently executed.
3. PERSISTENT VOLUME : Since work shifts among the nodes, the PV stores all the data so its accessible even after a node no longer exists
4. Data stored on nodes locally forms a local cache and is not expected to persist

Software

1. Containers : Programs running on Kubernetes are packages as linux containers. Containerization allows you to create self-contained Linux execution environments.
2. Pods: Any containers in the same pod will share the same resources and local network. Containers can easily communicate with other containers in the same pod as though they were on the same machine while maintaining a degree of isolation from others.
3. Deployment : A deployment’s primary purpose is to declare how many replicas of a pod should be running at a time.
4. Ingress : If you want to communicate with a service running in a pod, you have to open up a channel for communication. This is referred to as ingress.

---

> The role of service accounts in cloud priv esc : Service accounts represent non-human users. They're intended for scenarios where a workload, such as a custom application, needs to access resources or perform actions without end-user involvement.
> 

---

Spectre and Meltdown Attacks

1. [https://www.cloudflare.com/en-gb/learning/security/threats/meltdown-spectre/](https://www.cloudflare.com/en-gb/learning/security/threats/meltdown-spectre/)
2. Meltdown only affects Intel and Apple processors and can be exploited to leak information that gets exposed as a result of code that processors execute during speculative execution. Meltdown is easier to exploit than Spectre and has been labeled the larger risk by security experts. Thankfully, Meltdown is also easier and more straightforward to patch.
3. Spectre affects Intel, Apple, ARM, and AMD processors and it can be exploited to actually trick processors into running code that they should not be allowed to run. According to the security experts at Google, Spectre is much harder to exploit than Meltdown, but it is also much harder to mitigate.

---

Encryption vs Encoding vs Hashing vs Obfuscation vs Signing

1. Encryption: Transforming data in a way such that only specific individuals can reverse it - there's a key involved in this process.
2. Encoding : The purpose of encoding is to transform data so that it can be properly (and safely) consumed by a different type of system. The goal is not to secure data, but to make it easily consumable - there's no keys involved.
3. Hashing: Ensures integrity of data to make sure its not been modified. Is one way. Good hashes - are one way, different inputs don't generate the same hash, small changes to data cause massive change in hash & is consistent.
4. Obfuscation: Making something harder to understand, use case : Source code. It's reversible and only an obstacle. Limited by how obfuscated a code is too obfuscated a code.
5. Signing : Secure code signing is key for supply chain attacks, makes sure consumers know the code hasn't been altered since it was published.

Note: One might ask when obfuscation would be used instead of encryption, and the answer is that obfuscation is used to make it harder for one entity to understand (like a human) while still being easy to consume for something else (like a computer). With encryption, neither a human or a computer could read the content without a key.

## Perfect Forward Secrecy (PFS), also called forward secrecy (FS), refers to an encryption system that changes the keys used to encrypt and decrypt information frequently and automatically. This ongoing process ensures that even if the most recent key is hacked, a minimal amount of sensitive data is exposed

Response Codes

100 - Informational Responses
200 - Success
300 - Redirection
400 - Client error
500 - Server error

---

Cloud Security

Architecture

Cloud consumer - customer
broker -

---

System Design for Security

When you need to understand an existing system, or design a new system, start with a set of clarifying questions:

- What are the use cases?
- How many users are expected on the system over the next year?
- How much data is the system expected to process and persist?
- Are there constraints around transactions, latency, memory, or data storage?
- What are the security requirements and customer expectations?
- What are the assets that need protection?
- What attacks that have been seen in the past on this system or systems like it?

Next dig into the key features:

- Expected usage of each feature?
- What roles are involved and how is authorization handled?
- How does that translate into requests per second?
- How does that translate into data storage?
- Reads vs writes?

Secure System Design

---

Kubernetes

- Pods vs Containers : Containers exist within pods
    - A pod could have 1 container
    - Or >1 tightly coupled containers that help serve each other aka a sidecar
    - Containers in a pod share a volume and other resources
    - SINGLE APPLICATION ALWAYS
- Creating a Pod :
    - Declaratively using YAML
    - Apply the YAML
    - structure
        - apiversion
        - kind: pod
        - metadata: name
        - spec (specifications)
            - container details
- ReplicaSets and Deployments
    - Replicas : Identical copies of a pod
    - Deployment Object for managing pods and replicas
- Services :
    - Exposes set of pods to network, can be done using a YAML specification
        - ClusterIP ; for internal service communication
        - NodePort ;
        - LoadBalancer ;

---

1. Talk about AWS Key management
2. Talk about encryption
3. Secure file distribution in the absence of TLS
4. Kubernetes - how to ensure pod isolation and security
5. Symmetric asymmetric encryption, TLS, Importance of signing
6. ANSWERING QUESTIONS WHILE BEING OVERWHELMED - EXPLAINING EVERYTHING YOU KNOW
¸

![Screenshot 2023-11-07 at 9.23.59 PM.png](Security%20Engineer%20Interview%20Prep%200c03cb369adb4fa393289dc2902ec054/Screenshot_2023-11-07_at_9.23.59_PM.png)

## Meta

1. You have to connect a remote employee to a company resource - walk me down the process.