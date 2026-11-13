function FindProxyForURL(url, host) {
    // Direct access for internal hosts
    if (isPlainHostName(host)) {
        return "DIRECT";
    }

    // Direct access for local network
    if (isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0")) {
        return "DIRECT";
    }

    // Direct access for specific domains
    if (dnsDomainIs(host, ".internal.company.com") ||
        dnsDomainIs(host, ".localhost")) {
        return "DIRECT";
    }

    // Route Microsoft traffic through specific proxy
    if (shExpMatch(host, "*.microsoft.com") ||
        shExpMatch(host, "*.office365.com") ||
        shExpMatch(host, "*.office.com")) {
        return "PROXY proxy-ms.company.com:8080; DIRECT";
    }

    // Route AWS/Azure through cloud proxy
    if (shExpMatch(host, "*.amazonaws.com") ||
        shExpMatch(host, "*.azure.com") ||
        shExpMatch(host, "*.cloudfront.net")) {
        return "PROXY proxy-cloud.company.com:8080; DIRECT";
    }

    // Default: use main proxy
    return "PROXY proxy.company.com:8080; PROXY proxy-backup.company.com:8080; DIRECT";
}
