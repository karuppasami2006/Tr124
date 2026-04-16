# Local intelligence fallback for reliable hackathon demos
LOCAL_THREAT_INTEL = {
    "apache-commons": {
        "1.1.2": {
            "cve_id": "CVE-2021-44228",
            "severity": "Critical",
            "cvss_score": 10.0,
            "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "safe_version": "2.17.0+"
        }
    },
    "requests": {
        "2.25.1": {
            "cve_id": "CVE-2023-32681",
            "severity": "High",
            "cvss_score": 7.5,
            "description": "Incorrect Authorization header preservation during redirects.",
            "safe_version": "2.31.0+"
        }
    }
}
