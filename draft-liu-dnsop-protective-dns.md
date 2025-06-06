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
    RFC4033: # DNS Security Introduction and Requirements
    RPZ:
        title: "DNS Response Policy Zones (RPZ) draft-ietf-dnsop-dns-rpz-00"
        date: March 9, 2017
        target: https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-dns-rpz-00
    Error-Filter:
        title : "Structured Error Data for Filtered DNS draft-ietf-dnsop-structured-dns-error-13"
        date: April 24, 2025
        target: https://datatracker.ietf.org/doc/draft-ietf-dnsop-structured-dns-error/

informative:
    RFC5782: # DNS Blacklists and Whitelists
    Cisco:
        title: "DNS Security – Your New Secret Weapon in The Fight Against Cybercrime"
        date: February 27, 2024
        target: https://umbrella.cisco.com/blog/dns-security-your-new-secret-weapon-in-your-fight-against-cybercrime
    DNS4EU:
        title: "DNS4EU"
        date: May, 2025
        target: https://www.joindns4.eu/
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

Recent research work has delved deeply into a new type of DNS security service, Protective DNS, through various measurement methods, and it has been deployed in multiple DNS providers and even in national ISPs. Protective DNS identifies whether the domain names requested by customers are in the threat intelligence (blocklist) it maintains. For domain names listed in the blocklist, it rewrites the resolution results to secure resources to prevent users from accessing malicious resources, such as malicious servers (IP addresses), etc. This document summarizes the conclusions of these research works and provides specific and practical considerations and suggestions for the deployment and operation of Protective DNS. By following these considerations, Protective DNS service providers can effectively enhance the practicality and security of their services.

--- middle

# Introduction

Currently, 90% of cyber attack activities originate from domain name resolution {{Cisco}}. Therefore, the approach of blocking unintended network resource interactions based on the Domain Name System (DNS) has become a crucial network defense measure. DNS Filter {{RPZ}} is the most common blocking method in the DNS. For domain names that match the blocklist, it prevents access to unintended (especially malicious) network resources by rewriting their DNS responses, that is, rewriting the resolution results of these domain names to a securely controlled host instead of the original host address. Considering that this method can intercept attacks at the initial stage, it is commonly referred to as Protective DNS and has been deployed and implemented by multiple national governments and DNS vendors {{DNS4EU}}, {{US-Protect}}, {{Canada-Protect}}.

Recent research has explored the current deployment status and security properties of Protective DNS. This document summarizes the conclusions of these studies. These security considerations are applicable to all DNS resolvers that offer Protective DNS services (including DNS resolvers of international ISPs and well-known DNS resolution servers), aiming to provide practical deployment suggestions for Protective DNS service providers and effectively enhance the availability and security of this service.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Background

As the Domain Name System (DNS) serves as the starting point for most network activities {{RFC1034}}, {{RFC1035}}, the defense mechanisms based on domain names have become one of the main approaches to defend against cyberattacks. The defense mechanisms at the domain name level are extremely diverse, and the nodes where blocking actions occur can be found among various domain name roles. For example, in the initial process of domain name registration, the registry and the registrar can use the method of Domain Seizure to delete malicious domain names from the registration data, thus preventing them from causing further harm. The Protective DNS defense mechanism that this document focuses on is implemented based on the DNS Filter {{Error-Filter}} technology and is mainly deployed on recursive servers. Since recursive servers are closer to the user side (compared with authoritative servers, registries, and registrars), the defensive effect of deploying this mechanism on recursive servers is more obvious, which is also the main focus of this document.

~~~
          +----------------+
          | Threat         |
          | Intelligence   |
          +----------------+
                ^
                | query TI
          +----------------+
          | Protective DNS |
          +----------------+
      ^     |     ^
      |     |     | query & response
      |     |     v
+---------+  |  +----------------+
| Client  |  |  | Authoritative  |
+---------+  |  | Server         |
      |     |  +----------------+
      |     |
      |     | response (rewritten) for blacklisted domains
      |     | response for other domains
      |     v
+---------+
| Client  |
+---------+
~~~
{: #figure1 title="The workflow of Protective DNS."}

Figure 1 shows the workflow of Protective DNS. First, when the Protective DNS resolver receives a DNS query request for domain name A, it will match this domain name against the blocklist {{RFC5782} it maintains. Subsequently, once the domain name is found in the blocklist, Protective DNS will rewrite its DNS response, that is, resolve the query to a series of "safe" results (such as the safe IP address 127.0.0.1), thus effectively preventing clients from accessing the corresponding malicious resources. Conversely, if the queried domain name is not in the blocklist, a normal response will be returned. That is, it will query the authoritative server or use the locally cached results for the response.

Through investigation, 28 out of 42 popular DNS providers have already offered Protective DNS services, which run on a total of 155 resolver IP addresses {{NDSS24}}, {{USENIX24}}. Among them, 8 providers support Protective DNS services and non-Protective DNS services on different resolver addresses respectively. For example, Cloudflare's Protectgive DNS service runs on 1.1.1.2 and 1.1.1.3, while 1.1.1.1 provides the original DNS service. At the same time, considering the defensive effectiveness of Protective DNS, countries and regions such as the United States {{US-Protect}}, the United Kingdom {{DNS4EU}}, and Canada {{Canada-Protect}} have listed Protective DNS as a defense infrastructure for national-level deployment and application.

The defense strategies implemented by Protective DNS are diverse. The specific rewriting strategies mainly include secure IP addresses controlled by the providers, special-use IPs (e.g., 127.0.0.1), secure CNAMEs, responding with specific Response Codes (e.g., NXDomain, ServerFail), and providing an Empty Answer. Meanwhile, different providers' Protective DNS services focus on different types of malicious content, including advertisements, trackers, malware, phishing, and adult content.


Protective DNS is implemented based on DNS Filter technology. The two protocols most closely related to it are as follows: 1) The {{RPZ}} protocol defines the response strategies of the DNS Filter, including the setting methods of the Root Zone and the response strategies; 2)The {{Error-Filter}} defines the structural definitions for stating the filtering results and the reasons in the response.

Although the application requirements and deployment practices of Protective DNS are increasingly growing, due to the lack of guidance suggestions for deployment, Protective DNS faces serious security flaws. This document combines the conclusions of these research works with the measurement results to form some specific deployment suggestions, aiming to enhance the practicality and security of Protective DNS deployment. In the subsequent chapters, we will summarize the conclusions from the academic papers obtained through the measurement methods into conclusions that are helpful for Protective DNS service providers as a reference.

# Operational Considerations

Considering that deployment practice is the first step in using and even maintaining the security of Protective DNS, in this section, we propose a series of operational considerations that cover multiple aspects of deployment practice, including rewriting strategies, defense strategies, and transparency.


## Operational Consideration 1 - Select an appropriate rewriting mechanism

The most crucial aspect for Protective DNS to achieve its defensive capability is to adopt the rewriting strategy for DNS filtering to prevent users from accessing malicious resources. Through summarizing the empirical analysis of popular Protective DNS providers and generalizing the DNS Filter technology, there are mainly five types of rewritings that occur in practice:

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

## Operational Consideration 2 - Provider an appropriate blocklist for defense

A necessary condition for Protective DNS to achieve its defensive capability is to construct a blocklist that includes a series of malicious domain names to be blocked. The structural components of the domain name blocking list are as described in {{RPZ}}. Through the empirical analysis of popular Protective DNS vendors, these vendors currently mainly focus on a series of items related to advertisements, privacy tracking, malware, phishing, and adult content.

First, through the analysis of users of Protective DNS, Protective DNS providers SHOULD avoid using keywords for domain filtering, because this will increase the possibility of introducing false positives, which will affect the availability of Protective DNS.

Second, Protective DNS providers SHOULD avoid using wildcard blocking methods and should carry out defense at the granularity of the minimum subdomain (that is, the Fully Qualified Domain Name), so that the collateral damage caused can be minimized.

Finally, from the perspective of operational efficiency, the scale of the blocklist deployed on the Protective DNS SHOULD be carefully selected. It should not only avoid false positives but also choose an appropriate scale, as the scale of the blocklist will affect the response efficiency of the Protective DNS and the consumption of hardware resources of the device (such as CPU and memory).

## Operational Consideration 3 - Offer transparent blocking policies

Protective DNS is a completely black-box service for users. Regardless of the rewriting strategy adopted by Protective DNS, users can only perceive the effect of defensive blocking, that is, the domain name cannot be accessed. Although Protective DNS providers can refine and improve the quality of the blocklist (filtering out false positives as much as possible), the existence of false positives that slip through the net can still severely damage the user experience. From the user's perspective, the website they want to access is inexplicably inaccessible, and it is difficult to distinguish from a large number of DNS tampering behaviors on the network (such as censorship, man-in-the-middle hijacking, etc.). Therefore, from the perspective of enhancing the availability of Protective DNS, we recommend that providers MUST ensure transparency as much as possible.

On the one hand, to demonstrate that the blocking action originates from the Protective DNS, the service provider SHOULD provide a page to explain their rewriting strategy. In the results of the empirical analysis, we found that some providers rewrite by using a secure IP address and deploy a page on this IP address to indicate that the website the user is accessing may be malicious. However, using an IP address controlled by the service provider poses potential security risks, specifically the risk of Dangling resource takeover, which is elaborated in Security Consideration 3. Therefore, it is advisable for the service provider to use a dedicated page (this page should be explicitly deployed on the page provided by the service) to illustrate their defense strategy, helping users confirm that the DNS rewriting they encounter may be from the Protective DNS service provided by this provider.

On the other hand, to avoid the impact of false positives, service providers SHOULD provide users with an appeal channel on the explanatory page, such as providing an email address. Through the analysis of the measurement results of academic papers, only 14 Protective DNS deploy explanatory pages on the secure IP addresses used for defense.


# Security Considerations

Furthermore, by integrating the operational considerations, we propose some security considerations to enhance the security of Protective DNS on the basis of improving its practicality. We put forward specific considerations covering multiple dimensions, and for each consideration factor, we provide specific recommended solutions, including aspects such as security blocking strategies, rewriting strategies, and privacy protection.

## Security Consideration 1 - Avoid Improper Configuration

To prevent the protection function from failing or even being bypassed, Protective DNS service providers need to fully configure the defense as much as possible, which mainly includes two aspects.

**Avoid Redundant Configuration**. According to the measurement of Protective DNS services, the configurations of Protective DNS by some providers have defects. Specifically, along with the secure rewriting records, providers may also include the original malicious records in the DNS response. For the local stub resolver of users, the selection of the resolution result is uncontrollable, and users still have a high possibility of accessing malicious resources. Therefore, Protective DNS providers SHOULD avoid such redundant configurations to ensure the completeness of the defense effect.

**Avoid Configuration Gaps**. While A records are the most common type of DNS resolution and are often the primary focus for defensive configuration by service providers—since they directly point users to malicious resources—empirical measurements have revealed that some Protective DNS providers fail to secure less common query types, such as TXT records. In these cases, the provider may return unfiltered responses, potentially exposing users to hidden threats. This oversight could be exploited to bypass PDNS protections, particularly when malicious domains embed harmful instructions within less scrutinized record types. Therefore, to ensure comprehensive defense, Protective DNS providers SHOULD configure defensive capabilities for all DNS record types, including TXT, MX, and others. However, situations such as DNSSEC also need to be considered, and detailed explanations can be found in Security Consideration 4.

**Avoid Function Gaps**. In addition to the defensive configuration of the response results, Protective DNS service providers should ensure that the defensive functions are effective in any functional scenario. Specifically, encrypted DNS should also have the same defensive effect as non-encrypted DNS, to prevent malicious domain names from bypassing the defense by merely using encrypted DNS.

## Security Consideration 2 - Avoid Over-Blocking

The primary defense objective of Protective DNS is to prevent users from accessing any malicious resources, that is, to intercept as many malicious domain names as possible. However, through practical analysis, some Protective DNS systems exhibit the phenomenon of over-blocking, which refers to the collateral damage caused by overly aggressive blocking. In empirical measurement and analysis, it has been found that some Protective DNS services adopt overly aggressive defense strategies for DNS queries of a group (no less than one) of malicious domain names. That is, they temporarily block the domain name resolution of all requests from a client, and even legitimate domain names cannot be resolved normally. This phenomenon is called the Denial of Resolution (DoR) attack caused by Protective DNS. Attackers can exploit this phenomenon to cause a DoR effect on any victim. Specifically, by forging the source address and sending a set of queries for malicious domain names, they can prevent the victim from normally completing any domain name resolution, thus achieving the effect of a denial-of-service attack.

Therefore, Protective DNS service providers SHOULD avoid using aggressive defense strategies, such as the no-response strategy. At the same time, Protective DNS providers MUST pre-configure defense solutions against potential DoR risks. Specifically, when a client initiates a large number (higher than a certain threshold) of DNS query requests for malicious domain names to the Protective DNS server, the provider SHOULD NOT directly refuse to respond to any query requests for a certain period of time. Instead, it should send a relatively large DNS response to force the client to use DNS over TCP, effectively preventing attackers from launching DoR attacks constructed through IP spoofing.

## Security Consideration 3 - Ensure Secure Resource Usage

Out of considerations for controllability, most Protective DNS providers will adopt domain names or IP addresses under their control as a rewriting strategy. However, improper management of these rewritten resources can expose serious security risks. For instance, after a third-party attacker takes over rewritten resources with vulnerabilities (such as those with expiration risks) and gains control over these resources, the attacker can trigger query requests for malicious domain names from victims to the Protective DNS server whose resources are under the attacker's control through means like phishing, and return modified malicious content to the victims, thereby establishing a connection between the victims and the attacker's server.


Therefore, Protective DNS should strive to avoid using third-party resources as its rewriting infrastructure, such as cloud services. Even when using third-party resources, it is essential to use them with caution and regularly confirm the availability status of these resources.

## Security Consideration 4 - Possess compatibility

Since the defense mechanism implemented by Protective DNS requires rewriting the original DNS response content, this rewriting operation needs to ensure compatibility with other protocols and functions within the DNS architecture. Specifically, the rewriting performed by Protective DNS should not conflict with the processing of DNSSEC as specified in {{RFC4033}}. This is because if the rewriting of the DNS response by Protective DNS does not follow certain specifications, it may interfere with the verification process of DNSSEC. For example, if Protective DNS deletes or modifies DNSSEC-related records when rewriting the response, it may lead to the failure of DNSSEC verification. Therefore, when Protective DNS rewrites the response, it should handle DNSSEC records correctly and maintain their integrity to avoid conflicts with the DNSSEC mechanism. This item mainly focuses on DNSSEC-related records and does not conflict with Security Consideration 1.



# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
