# OSCP Tech Notes ITA [last update 09/2024]

Table of contents
- [Recon](#Recon)
- [Recon](#Recon)


## Recon

Information Gathering, search engine:
| Search Engine         | Description                       |
|-----------------------|-----------------------------------|
| https://google.com    | Info about company, people, contacts, other domain, media info, external services, projects. Google Dork help tp search files and other resources |
| https://yandex.com    | Search by images                  |
| https://stract.com    | Community, forums, blogs          |
| https://github.com    |                                   |
| https://gist.github.com   |                               |
| https://about.gitlab.com  |                               |
| https://sourceforge.net   |                               |

DNS Enumeration web-tools:
| Tool                              | Description                       |
|-----------------------------------|-----------------------------------|
| https://searchdns.netcraft.com    |                                   |
| https://dnsdumpster.com           |                                   |
| https://shodan.io                 | Info about technologies, subnet, service emumeration, vulnerabilities, service provider, technical informations |
| https://search.censys.io          |                                   |
| https://securityheaders.com       |                                   |

Domain Information:
``` bash
# DNS query
host $TARGET_DOMAIN
host -C $TARGET_DOMAIN
host -t MX $TARGET_DOMAIN   ## MX record details
host -t TXT $TARGET_DOMAIN  ## TXT record details
dig MX $TARGET_DOMAIN
dig TXT $TARGET_DOMAIN

# whois query
whois $TARGET_DOMAIN
whois $TARGET_DOMAIN -h $WHOIS_SERVER_IP
```

Subdomain Discovery:
``` bash
fierce --domain $TARGET_DOMAIN --dns-server $DNS_SERVER_IP
dnsenum $TARGET_DOMAIN
dnsrecon $TARGET_DOMAIN
gobuster vhost -w $WORDLIST -u $TARGET_DOMAIN
```

