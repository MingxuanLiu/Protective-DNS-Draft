---
title: "Considerations for Protective DNS Server Operators"
abbrev: "PDNS"
category: std

docname: draft-liu-dnsop-protective-dns-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: "AREA"
# workgroup: "Domain Name System Operations"
# keyword:
#  - next generation
#  - unicorn
#  - sparkling distributed ledger
venue:
  # group: "Domain Name System Operations"
  # type: ""
  # mail: "dnsop@ietf.org"
  # arch: "https://mailarchive.ietf.org/arch/browse/dnsop/"
  github: "MingxuanLiu/Protective-DNS-Draft"
  latest: "https://MingxuanLiu.github.io/Protective-DNS-Draft/draft-ietf-dnsop-protective-dns.html"

author:
 -
    fullname: Haixin Duan
    org: Tsinghua University
    city: Beijing
    country: China
    email: duanhx@tsinghua.edu.cn
 -
    fullname: Mingxuan Liu
    org: Zhongguancun Laboratory
    city: Beijing
    country: China
    email: liumx@mail.zgclab.edu.cn
 -
    fullname: Baojun Liu
    org: Tsinghua University
    city: Beijing
    country: China
    email: lbj@tsinghua.edu.cn
 -
    fullname: Chaoyi Lu
    org: Zhongguancun Laboratory
    city: Beijing
    country: China
    email: lucy@zgclab.edu.cn

normative:
    RFC1034: # Domain names - concepts and facilities
    RFC1035: # Domain names - implementation and specification
    RFC5782: # DNS Blacklists and Whitelists
    RFC4033: # DNS Security Introduction and Requirements
    RFC4035: # Protocol Modifications for the DNS Security Extensions
    RFC8914: # Extended DNS Errors
    RPZ:
        title: "DNS Response Policy Zones (RPZ) draft-ietf-dnsop-dns-rpz-00"
        date: March 9, 2017
        target: https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-dns-rpz-00
    Structered-Error:
        title : "Structured Error Data for Filtered DNS draft-ietf-dnsop-structured-dns-error-13"
        date: April 24, 2025
        target: https://datatracker.ietf.org/doc/draft-ietf-dnsop-structured-dns-error/

informative:
    SAC127:
        title: "SAC127 DNS Blocking Revisited"
	date: May 16, 2025
        target: https://itp.cdn.icann.org/en/files/security-and-stability-advisory-committee-ssac-reports/sac127-dns-blocking-revisited-16-05-2025-en.pdf
    Cisco:
        title: "DNS Security – Your New Secret Weapon in The Fight Against Cybercrime"
        date: February 27, 2024
        target: https://umbrella.cisco.com/blog/dns-security-your-new-secret-weapon-in-your-fight-against-cybercrime
    DNS4EU:
        title: "DNS4EU"
        date: May, 2025
        target: https://www.joindns4.eu/
    UK-NCSC-PDNS:
        title: "NCSC announces new partnership for PDNS delivery"
	date: April 2024
        target: https://4thplatform.co.uk/2024/04/19/ncsc-announces-new-partnership-for-pdns-delivery-2-2/
    UK-NCSC-PDNS-Usage:
        title: "Experts in Domain Name System (DNS) Services"
	date: 2025
        target: https://nominet.uk/dns-services/
    UK-Defence:
        title: "Active Cyber Defence"
	date: 2022
        target: https://www.ncsc.gov.uk/files/ACD6-full-report.pdf
    US-Protect:
        title: "Protective domain name system services"
        date: May, 2022
        target: https://www.nsa.gov/About/Cybersecurity-Col laboration-Center/PDNS/
    Canada-Protect:
        title: "Canadian shield offers dns-based protection against malware and phishing attacks"
        date: July, 2021
        target: https://www.cira.ca/en/canadian-shield/faq-public/
    NDSS24:
        title: "Understanding the Implementation and Security Implications of Protective DNS Services"
        date: March, 2024
        target: https://www.ndss-symposium.org/ndss-paper/understanding-the-implementation-and-security-implications-of-protective-dns-services/
    USENIX24:
        title: "Two Sides of the Shield: Understanding Protective DNS adoption factors"
        date: August, 2024
        target: https://www.usenix.org/conference/usenixsecurity23/presentation/rodriguez

--- abstract

Protective DNS identifies whether domain names requested by clients are in its maintained blocklist. For blocklisted domains, it rewrites resolution responses to point to secure resources (e.g., safe servers) to prevent user access to malicious entities.

Owing to its effective defenses, Protective DNS deployment has surged through numerous efforts. Not only have renowned DNS resolution service providers adopted this defense, but some nations have also launched national-scale deployments. Concurrently, studies have attempted to analyze Protective DNS, identifying a series of implementation inconsistencies.

Thus, this document aims to provide specific operational and security considerations for Protective DNS by synthesizing key findings. It is intended primarily for entities seeking to deploy Protective DNS for defensive purposes, offering concrete deployment recommendations.

--- middle

# Introduction

Protective DNS (also termed as PDNS) is a lightweight defensive measure deployed at recursive resolvers to proactively rewrite DNS resolution responses for malicious domains, thereby preventing users from accessing malicious resources. Specifically, when a client initiates a domain name resolution request, PDNS first performs a security check on the target domain—determining whether the domain poses a security risk by matching it against blocklists. If the domain is identified as malicious, PDNS uses DNS rewriting mechanisms to intercept the resolution request and return a secure response (e.g., a safe server address controlled by the DNS service provider), blocking users from establishing connections with malicious resources. For legitimate domains, PDNS queries and receives responses from authoritative servers and returns normal response content to the client.

The defensive benefits offered by PDNS have spurred extensive deployment efforts. Renowned DNS resolution service providers have increasingly deployed PDNS on their recursive servers. For example, Cloudflare DNS offers its standard DNS resolution service at 1.1.1.1, while deploying PDNS at 1.1.1.2 and 1.1.1.3. Moreover, some countries or regions have initiated national-level infrastructure deployments of PDNS. The UK's National Cyber Security Centre (NCSC), for instance, launched a PDNS service in 2017 to enhance cyber defenses, which has since been authorized for use by central government departments, local authorities, schools, and emergency services {{UK-NCSC-PDNS}}. Notably, statistics from the UK NCSC indicate that approximately 7.2 million individual users utilized the system in 2023 {{UK-NCSC-PDNS-Usage}}. In 2022, PDNS processed 810 billion DNS queries and blocked 11 billion queries involving 420,000 domains, accounting for approximately 2% of all queries {{UK-Defence}}.

As the deployment of PDNS continues to grow, efforts have been made to systematically analyze PDNS services, including deployment status, operational mechanism and security implications. Existing work, through active probing of PDNS services, has revealed that 9% of stable recursive resolvers deploy PDNS (in 2023) {{NDSS24}}. These implementations exhibit significant discrepancies among providers in terms of rewriting policies, blocklist selection and performance. Furthermore, security risks such as implementation flaws, over-blocking, and dangling resources have been identified, which may compromise the protective capabilities of certain PDNS deployments and even lead to severe risks such as denial of service. Building on these findings, this document presents specific technical considerations spanning both operational and security aspects of PDNS. These recommendations are targeted at all DNS providers offering Protective DNS services (including those operated by international ISPs, public DNS providers, etc.), aiming to provide practical deployment guidance that enhances both the usability and security of PDNS implementations.

Notably, this document is primarily intended for readers familiar with Protective DNS technology and somewhat aware of the potential impacts that deploying such technologies may entail. Moreover, existing documents {{USENIX24}}, {{SAC127}} are recommended for legal considerations. On this basis, this document focuses on discussing technical considerations at the deployment level.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Background

## Overview of Protective DNS

Protective DNS (PDNS) is deployed on a recursive resolver. When the PDNS resolver receives a DNS query for domain A, it first matches the domain against its maintained blocklist. The resolver then makes a decision based on the blocklist lookup result. If the domain is found in the blocklist, PDNS rewrites the DNS response to resolve the query to a "safe" result (e.g., IP address 127.0.0.1), effectively preventing the client from accessing the corresponding malicious resource.Conversely, if the domain is not in the blocklist, the resolver returns a normal response by querying authoritative servers or using local cache results to respond to the client {{RFC1034}}, {{RFC1035}}. Thus, the two functional components that underpin the critical role of PDNS are the Blocklist and the Rewriting Policy.

**Blocklist.** A Blocklist is a domain name list for which the PDNS resolver intends to rewrite resolution results for defensive purposes. Blocklist sources include multiple aspects: commercial threat intelligence (TI), open-source TI, vendor-maintained domain blacklists, and user complaints. PDNS deployments implement Blocklists in two primary forms:

1. Local Deployment: storing the blocklist directly on the PDNS server.
2. Remote Query: performing lookups via network interfaces (e.g., APIs，DNSBL {{RFC5782}}).

The types of malicious domains included in Blocklists vary by vendor definition, encompassing but not limited to: malware, botnet command-and-control, phishing, fraud, and adult content.

**Rewriting Polify.** Upon retrieving Blocklist results, the PDNS resolver must rewrite resolution results for domains marked as defensive targets. The Rewriting Policy is critical to PDNS's defensive capability. Primary implementations of the rewriting module include, but are not limited to:

1. DNS Response Policy Zones (RPZ) {{RPZ}}: Implemented as zone files {{RFC1034}}, {{RFC1035}}, this approach serves as a rewriting strategy guide, specifying both whether rewriting is required and providing domain-specific rewrite results.
2. Domain Lists: This format consists of one domain per line, indicating only whether a domain requires rewriting.

Furthermore, rewriting strategies exist in multiple forms. Based on empirical analysis of leading Protective DNS vendors, this document summarizes five specific rewriting policies.

1) Using the secure IP addresses in A record controlled by the provider:

	malicious_domain.com    A    10    controled_IP;

2) Using IP addresses with special purposes, such as the reserved address like 127.0.0.1, 0.0.0.0, 192.168.0.1 and so on:

	malicious_domain.com    A    10    127.0.0.1;

3) Utilizing the CNAME record to rewrite the request to the domain name controlled by the provider:

	malicious_domain.com    CNAME    10    controled_domain.com;

4) Using an empty Answer field in the response to prevent users from accessing malicious resources:

~~~
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                 ID (two octets)               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                QDCOUNT (one octet)            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                ANCOUNT (one octet)            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                NSCOUNT (one octet)            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                ARCOUNT (one octet)            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
;--------------- Question Section --------------;
|  Domain Name (variable length)                |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              QTYPE (two octets)               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              QCLASS (two octets)              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
;-------------- Answer Section -----------------;
|  (empty, no resource records here)            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
~~~
{: #figure2 title="Format of empty Answer fileld in Protective DNS."}

5) Using special response codes for the reply, such as NXDomain, ServerFail, etc:

~~~
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|               ID (two octets)                 |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
|  |           |  |  |  |  |        | 0  0  1  0|
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                QDCOUNT (one octet)            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                ANCOUNT (one octet)            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                NSCOUNT (one octet)            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                ARCOUNT (one octet)            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
;--------------- Question Section --------------;
|  Queried Domain Name (variable length)        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              QTYPE (two octets)               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|              QCLASS (two octets)              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
;------------- Answer Section ------------------;
|empty (as NXDomain means no such domain exists)|
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
~~~
{: #figure3 title="Format of NXDomain Response in Protective DNS."}

**Deployment Practices.** Leading DNS providers have increasingly offered Protective DNS services. Observations of practical deployments, such as Cloudflare and Quad9. For example, Cloudflare operates standard DNS services on 1.1.1.1, while PDNS servers on 1.1.1.2 and 1.1.1.3 implement differentiated protection: 1) 1.1.1.2 focuses on malware defense; 2) 1.1.1.3 defends against both malware and adult content. Additionally, recognizing PDNS's defensive efficacy, nations including the U.S. {{US-Protect}}, U.K. {{UK-NCSC-PDNS}}, and Europe {{DNS4EU}} have designated PDNS as critical defensive infrastructure for national-level deployments.

## Distinctions of Protective DNS Technology

Protective DNS constitutes a subset of DNS Blocking (or DNS Filtering), sharing the goal of security defense by leveraging known blocklists to prevent user exposure to malicious resources. Generally, DNS Blocking and DNS Filtering are considered synonymous {{SAC127}}. DNS Blocking is a broader security concept encompassing any rewriting operations of DNS resolution flows to restrict access to specific domains. Its applicability spans diverse scenarios and architectural layers, including defence at any DNS resolution role (client, recursive resolver, authoritative server) and other security use scenarios (e.g., spam filtering, gateway firewall protection). In contrast, PDNS represents a specific implementation of DNS Blocking deployed on recursive resolvers.

Several prior documents define specific techniques within DNS Blocking:

1. DNS Blacklist (DNSBL){{RFC5782}}: DNSBL represents a DNS-based blacklist query technology, serving as a concrete implementation of blocklist querying within the broader DNS Blocking paradigm (including PDNS). First, it maintains blacklists of IP addresses/domains associated with spam, malicious activities, etc. Then, they utilize DNS queries to determine whether to block related traffic.
2. DNS Response Policy Zones (RPZ) {{RPZ}}: Beyond remote blocklist querying (e.g., DNSBL), local deployment offers another blocklist deployment strategy. RPZ achieves localized blocklist querying via a zone file containing rewrite instructions for each malicious domain, often utilized in the scenario like DNS Firewall. RPZ supports multiple triggering mechanisms. Among these, QNAME trigger is the primary mode adopted by PDNS.

Another similar security concept is censorship. While censorship shares the objective of preventing end-users from accessing specific resources with DNS Blocking, its blocking strategies are far more diverse. Domain blacklist-based blocking represents just one type of DNS-layer mitigation, alongside techniques like DNS poisoning. Cross-layer mechanisms include TCP reset attacks (sending forged RST packets), IP blocking, HTTPS man-in-the-middle attacks, and Deep Packet Inspection (DPI) for payload analysis.

Additionally, as the Domain Name System serves as the starting point for most network activities, domain-based defense mechanisms have become one of the primary approaches to countering cyberattacks. Defense mechanisms at the domain level are diverse, with blocking actions occurring across various roles in the domain ecosystem. For example, during the initial domain registration process, registries and registrars can use Domain Seizure to remove malicious domains from registration data, thereby preventing their continued harm to users. Registries and registrars can also employ sinkhole technology to forcefully resolve some malicious domains to domain black holes. The Protective DNS defense mechanism focused on in this document is primarily deployed on recursive resolvers. Because recursive resolvers are closer to the user side (compared to authoritative servers, registries, and registrars), deploying this mechanism on recursive resolvers achieves more significant defense effects, which is the main focus of this document.

# Deployment Status

Due to the significant protective efficacy of Protective DNS, existing academic efforts have evaluated its deployment status through measurement. The results indicate an optimistic adoption trend of PDNS across large-scale DNS vendors, in-the-wild recursive resolvers, and even at the national level.

Existing work, through a combination of surveying publicly available documentation from widely adopted DNS service providers and active testing, confirms that two-thirds of recursive service providers already offer Protective DNS services. Notably, practices vary significantly across vendors, including differences in the types of malicious domains defended against and rewrite policies. In terms of deployment strategies, the majority of vendors employ hybrid deployments, providing both Protective DNS and regular DNS resolution on a single resolver IP address. A smaller subset deploys Protective DNS and regular DNS resolution on separate resolver IPs, and in some cases, even different resolver servers from the same vendor may defend against distinct types of malicious domains.

Furthermore, existing studies using active scanning in 2023 of the IPv4 address space confirm that approximately 9% of stable recursive resolvers have deployed Protective DNS capabilities, covering almost two-thirds of the world's countries. By analyzing the types of malicious domains defended against, research has found that Malware, botnet, Phishing, and Spam are the most common categories, with observable blocklist overlap across different recursive resolution services. In terms of rewrite policies, using safe IP addresses and special-purpose IP addresses represents the most prevalent rewriting approach.

Additionally, several countries and regions have even deployed national Protective DNS projects, including:

1. DNS4EU {{DNS4EU}}：Launched in January 2023 under the auspices of the European Union Agency for Cybersecurity (ENISA), this initiative serves as an alternative to prevailing public DNS resolution services. It is designed to deliver protective, privacy-compliant, and resilient DNS capabilities, thereby enhancing the EU's digital sovereignty and security. Any device connected to DNS4EU resolvers that attempts to access a malicious domain (e.g., one hosting malware or phishing content) is immediately blocked, preventing potential harm. Leveraging real-time threat monitoring and defense mechanisms, the project ensures that malicious domains identified in one EU jurisdiction are countered across multiple member states to contain their spread. DNS4EU provides DNS security assurances to critical sectors including EU citizens, public institutions, government entities, and operators, while also supporting voluntary adoption or opt-out by EU residents.
2. PDNS in UK {{UK-Defence}}：Supported by the UK's National Cyber Security Centre (NCSC), this initiative advises private enterprises and government agencies to adopt Protective DNS to safeguard their IT assets and network security. By blocking access to known malicious domains, it significantly reduces the effectiveness of ransomware, phishing, botnet, and malware attacks. According to NCSC statistics, in 2022, the project's PDNS service processed 810 billion DNS queries and blocked 11 billion queries involving 420,000 distinct domains {{UK-Defence}}.
3. PDNS in US {{US-Protect}}：This initiative, launched by the Cybersecurity and Infrastructure Security Agency (CISA) in 2022, is designed to provide security safeguards for the United States' national critical infrastructure. The project protects the federal government by blocking network traffic at the DNS resolution layer from reaching potentially malicious destinations, enhancing resilience against intrusions and attacks. When Protective DNS detects a DNS request matching threat intelligence indicators, the service blocks, redirects, or sinks the query response to a secure endpoint, while sending alerts to the source agency and CISA. The initiative mandates the use of this Protective DNS service by all Federal Civil Executive Branch (FCEB) agencies and offers limited availability to infrastructure participants in pilot programs.

# Operational Considerations

Considering that deployment practice is the first step in using and even maintaining the security of Protective DNS, in this section, we propose a series of operational considerations that cover multiple aspects of deployment practice, including blocklist selection, rewriting strategie construction, performance impact and offering explanation.

## Operational Consideration 1 - Blocklist Selection

One of the necessary condition for Protective DNS to achieve its defensive capability is to construct a blocklist that includes a series of malicious domain names to be blocked.

First, Protective DNS operators need to construct a Blocklist. On one hand, they should choose the Blocklist sources, such as open-source threat intelligence, commercial threat feeds, self-collected malicious domains, and user feedback. On the other hand, they should specify the types of malicious domains to block, including but not limited to malware, botnet, phishing, spam, tracking, and adult content. Most importantly, operators ideally should verify the correctness of these malicious domains to avoid false positives that could impact access to legitimate domains.

Second, PDNS operators should select an appropriate Blocklist deployment approach based on operational context (including device resource constraints and network access patterns) and application scenarios, such as deploying in RPZ format on resolvers or using network interfaces for remote querying. Remote querying approaches require preemptive consideration of potential privacy implications and impacts from network instability. Local deployments necessitate an advanced assessment of local resource limitations. Specifically, the Blocklist scale deployed on Protective DNS must be carefully defined based on the process capability. Since blocklist size directly affects both the response efficiency of Protective DNS and hardware resource consumption (e.g., CPU, memory) on the hosting device.

Most critically, operators should endeavor to avoid controversial Blocklist formats to minimize the impact of potential false positives. First, PDNS should refrain from using keywords as Blocklist entries, as this exacerbates the likelihood of introducing false positives and undermines PDNS availability. Second, PDNS providers should avoid using wildcard domains in Blocklists, as such practices may also lead to false positives. To maximize the mitigation of false positives, defense at the granularity of the minimum subdomain (i.e., FQDN) may cause the least collateral damage.

## Operational Consideration 2 - Rewriting Policy Construction

Based on the summarization of empirical analyses of popular Protective DNS providers, five primary rewriting approaches have been identified in practice: 1) Using safe IP addresses controlled by the PDNS provider; 2) Employing special-purpose IP addresses (e.g., reserved addresses like 127.0.0.1); 3) Rewriting requests to PDNS provider-controlled domains via CNAME records; 4) Sending responses with empty Answer sections ; 5) Returning special response codes (e.g., NXDomain, ServerFail). Each rewriting strategy caters to specific scenarios, requiring providers to select appropriate approaches based on their application requirements, specifically as follows:

1) Secure IP addresses: Under this policy, the rewritten target address is a server under the PDNS provider's control, enabling PDNS providers to monitor traffic. Specifically, the controlled server acts as a "honeypot" managed by the provider, capturing DNS traffic of malicious domain names for further analysis of threat behaviors (e.g., malware communications, exploit attempts). However, this approach imposes operational overhead on PDNS providers, who must actively monitor the status of these servers. Also, this scenario necessitates consideration of privacy risks arising from traffic monitoring.

2) IP addresses with special purposes (like 0.0.0.0): Due to the non-routable nature of these IP addresses on public networks, they are better suited for scenarios with strict privacy protection requirements, such as when users do not want any third parties to obtain their network behavior. However, PDNS operators must consider potential risks when using these special IP addresses. For example: a) 192.168.0.1 is typically used for local area network devices. Such configurations may lead to unintended access to internal network devices if clients mistakenly connect to them; b) 127.0.0.1 is commonly used for local inter-process communication. Redirecting to this address may cause clients to attempt connecting to local services, which could be exploited if vulnerabilities exist—such as through port scanning or service spoofing. This is particularly risky when users mistake local services for external ones, potentially exposing sensitive information or enabling attacks. Meanwhile, this approach lacks transparency for users in the event of false positives, as it cannot provide explanatory feedback, which is discussed in detail in the Security Considerations.

3) Secure CNAME: This strategy, similar to using controlled IP addresses, enables providers to dynamically monitor traffic. However, it is critical to remain vigilant against dangling resource risks arising from improper management, details shown in Security Considerations.

4) Empty Answer field: This strategy represents a minimalist defense approach, silently blocking malicious access without requiring additional processing. However, it undermines the transparency of PDNS services for users and may escalate to more aggressive implementations—such as refusing to return resolution responses— which entail denial-of-response risks detailed in the Security Considerations.

5) Special response codes (like NXDomain): This strategy is compatible with traditional DNS error scenarios, which helps prevent malware from detecting the defensive mechanisms of PDNS. Such practices may also undermine the transparency of Protective DNS services, making it difficult for users to understand the rationale behind rewriting actions.

Second, PDNS operators should consider the impact of TTL settings and appropriately configure the TTL for rewritten records. On one hand, an excessively long TTL may lead to delayed updates of defense strategies for malicious domains. On the other hand, a too-short TTL triggers frequent queries, increasing PDNS server load and potentially degrading performance.

## Operational Consideration 3 - Performance Impact

As Protective DNS services introduce an additional step to query whether a domain is malicious during standard DNS resolution, operators must anticipate potential impacts on DNS resolution performance. Specifically, factors such as Blocklist deployment method (remote vs. local), scale, and domain matching techniques (e.g., hash matching) can affect performance. Experimental results show that loading a Blocklist with five million malicious domains can still be maintained within sub-second levels, but exceeding this scale may result in loading times exceeding 10 seconds, leading to unacceptable performance impacts.

## Operational Consideration 4 - Offering Explanation

Protective DNS operates as a complete black-box service to users. Regardless of the rewriting strategy employed, users only perceive the blocking effect—i.e., the inability to access a domain. While providers can refine blocklist quality to minimize false positives, their inevitable presence significantly degrades user experience. Users may encounter unexplained inaccessibility that is indistinguishable from prevalent DNS tampering (e.g., censorship, man-in-the-middle attacks). Therefore, providing explanations for Protective DNS actions enhances usability. Operators should anticipate that omitted explanations may lead users to misperceive service instability or even switch to competing DNS providers.

This explanatory of PDNS can be realized through multiple approaches. First, to indicate that blocking originates from Protective DNS, service providers may offer a dedicated landing page explaining their protective services, helping users confirm that observed DNS rewriting is likely due to the provider’s Protective DNS. Empirical analyses show some providers rewrite to a secure IP address hosting a page notifying users of potential malicious website access. However, using a provider-controlled IP introduces risks of dangling resource takeover, detailed in Security Consideration. Second, the EDE (Extended DNS Error) {{RFC8914}}, {{Structered-Error}} protocol can be employed to specify in extension fields that rewriting results from Protective DNS defense against malicious domains.

Moreover, providing user appeal mechanisms on explanatory pages, such as providing an email address, could mitigate negative impacts from potential false positives.

# Security Considerations

Furthermore, by integrating the operational considerations, we propose some security considerations to enhance the security of Protective DNS on the basis of improving its practicality. We put forward specific considerations covering multiple dimensions, and for each consideration factor, we provide specific recommended solutions, including policy flaws, over-blocking, dangling resources, compatibility with other security practices, fault diagnosis and privacy.

## Security Consideration 1 - Policy Flaw

To prevent the protection function from flaws or even being bypassed, service providers should consider the following three aspects.

**Redundant Rdata.** According to the measurement of Protective DNS services, the configurations of Rdata in rewritten records by some providers have defects. Specifically, existing reseaerch work noticed that along with the secure rewriting records, several PDNS providers may also include the original malicious records in the DNS response. For local stub resolvers of users, the selection of the resolution result is uncontrollable, and users still have a high possibility of accessing malicious resources. Therefore, Protective DNS providers SHOULD avoid such redundant configurations to ensure the completeness of the defense effect.

**Missing Rtype.** While A records are the most common type of DNS resolution and are often the primary focus for defensive configuration by service providers—since they directly point users to malicious resources—empirical measurements have revealed that some Protective DNS providers fail to secure less common query types, such as TXT records. In these cases, the provider may return unfiltered responses, potentially exposing users to hidden threats. This oversight could be exploited to bypass PDNS protections, particularly when malicious domains embed harmful instructions within less scrutinized record types. Therefore, to ensure comprehensive defense, Protective DNS providers SHOULD configure defensive capabilities for all DNS record types, including TXT, MX, and others.

**Policy coverage.** In addition to the defensive configuration of the response results, Protective DNS service providers should ensure that the defensive functions are effective in any functional scenario. Specifically, encrypted DNS should also have the same defensive effect as non-encrypted DNS, to prevent malicious domain names from bypassing the defense by merely using encrypted DNS. Additionally, IPv6 scenarios should also be taken into consideration.

## Security Consideration 2 - Dangling Resources

For controllability considerations, some Protective DNS providers use self-controlled domains or IPs as rewriting strategies. However, mismanagement of these rewritten resources may lead to takeover risks from Dangling resources, specifically:

1. If the rewritten IP is a cloud service IP, obsolete IP addresses pose a takeover risk.
2. If the rewritten CNAME domain expires, there is an expired domain takeover risk.
3. If the rewritten CNAME domain belongs to a third-party service, subdomain takeover risks may arise.

Upon gaining control of vulnerable rewritten resources (e.g., those at expiry risk), attackers can trigger queries for malicious domains to the compromised Protective DNS server via phishing or similar tactics. They can then return modified malicious content to victims, enabling connections between victims and attacker servers.

Therefore, Protective DNS service providers should exercise caution when using third-party network resources. On one hand, they should consider the financial and management costs required for regular maintenance of these resources. On the other hand, they need to periodically verify the status of these third-party services to avoid dangling resource risks.

## Security Consideration 3 - Over-Blocking

Protective DNS rewriting should minimize over-blocking, as this introduces significant collateral damage in two primary aspects.

**Blocklist Construction.** First and foremost, Protective DNS service providers should strive to avoid errors in blocklists, as this represents the most direct cause of collateral damage to unrelated parties. Secondly, generalizing target domains for blocking in Protective DNS may also lead to collateral damage. Using keywords as blocklist entries exacerbates the likelihood of false positives, causing unintended blocking of unrelated domains and degrading PDNS availability. Employing wildcard domains in blocklists similarly introduces false positives. Meanwhile, blocking at the second-level domain (SLD) or top-level domain (TLD) tiers can also trigger false positives—for example, cloud services often host user-specific services on subdomains, so blocking the apex domain of such a cloud service would impact numerous unrelated services. Thus, defending at the granularity of the minimum subdomain (i.e., fully qualified domain name, FQDN) minimizes collateral damage. Finally, providers must promptly update blocklists to avoid false positives from delayed updates.

**Blocking Policy.** The primary defense objective of Protective DNS is to prevent users from accessing any malicious resources, i.e., intercept as many malicious domains as possible. However, empirical analysis has shown that some Protective DNS implementations exhibit over-blocking—collateral damage from overly aggressive blocking. Measurements reveal that certain Protective DNS services apply extreme defensive strategies to queries for a set of malicious domains (≥1), temporarily blocking all domain resolution for the client—including legitimate domains. This introduces denial-of-response (DoR) risks, as attackers can exploit this behavior to impose DoR on arbitrary victims. Specifically, sending a set of malicious domain queries with spoofed source addresses can force the victim’s client to lose all DNS resolution capabilities, effectively executing a denial-of-service attack.

Therefore, PDNS service providers should exercise caution when implementing aggressive defensive strategies and consider the potential impact of such approaches in advance. Concurrently, Protective DNS providers must preconfigure defense mechanisms against potential denial-of-resolution (DoR) risks. Specifically, when a client initiates a large volume of DNS queries (above a certain threshold) for malicious domains to a Protective DNS server, providers should consider the impact of directly denying all DNS query responses from the client for a period of time. To effectively mitigate denial-of-response attacks, providers can send a large DNS response to force clients to use DNS over TCP, thereby thwarting DoR attacks constructed via IP spoofing.

## Security Consideration 4 - Compatibility with other security practices

Protective DNS may interact with other security practices in the DNS architecture, such as DNSSEC {{RFC4033}}. Under normal circumstances, DNSSEC primarily operates between recursive resolvers and authoritative servers. For Protective DNS, when a malicious domain matches the blocklist, if the PDNS server does not query the authoritative server for DNSSEC records, the mutual impact between PDNS and DNSSEC remains limited. However, PDNS service providers must consider scenarios where clients request PDNS servers to perform DNSSEC queries and validation for blocked malicious domains—such as by setting the DO (DNSSEC OK) bit {{RFC4035}}. In such cases, PDNS rewriting protection may affect the normal operation of DNSSEC.Therefore, PDNS service providers should pre-emptively consider the mutual impacts between PDNS services and other security practices.

## Security Consideration 5 - Fault Diagnosis

As Protective DNS introduces new components, such as blocklists, service providers should consider fault diagnosis for denial-of-service (DoS) failures in individual components and corresponding fallback mechanisms to ensure performance stability. For example, in scenarios involving remote blocklist queries, providers should proactively diagnose the availability of remote blocklist interfaces on a regular basis. If remote blocklist query services become unavailable due to network issues or other causes, and no fallback mechanism is in place, this may render the provider’s DNS query services inoperable. Thus, providers must predefine fallback mechanisms—such as reverting to normal DNS resolution procedures.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
