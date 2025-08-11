#include "getIpMac.h"



struct ifreq perform_ioctl(const std::string& interfaceName, int request) {
    if (interfaceName.length() >= IFNAMSIZ) {
        throw std::runtime_error("Interface name is too long");
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("Socket creation failed: " + std::string(strerror(errno)));
    }

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, request, &ifr) < 0) {
        close(sock);
        throw std::runtime_error("ioctl call failed (" + interfaceName + "): " + std::string(strerror(errno)));
    }

    close(sock);
    return ifr;
}

std::string getMyIp(const std::string& interfaceName) {
    struct ifreq ifr = perform_ioctl(interfaceName, SIOCGIFADDR);
    
    struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipaddr->sin_addr, ip_str, sizeof(ip_str));
    
    return std::string(ip_str);
}

std::string getMyMac(const std::string& interfaceName) {
    struct ifreq ifr = perform_ioctl(interfaceName, SIOCGIFHWADDR);
    
    unsigned char* mac_addr = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac_addr[i]);
        if (i < 5) {
            ss << ":";
        }
    }
    
    return ss.str();
}