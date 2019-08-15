/*
  2019 WeakNet Labs
  Douglas Berdeaux
  WeakNetLabs@Gmail.com
  
  AP Search Tool utilizes RSSI in Radiotap Header.
  You must set your sepcific offset in the code below before compiling. 
  This can be found using Wireshark and counting the bytes from the first byte in the packet to the BSSID byte.
  You must also set your frequency beforehand using something like,
  iwconfig wlan0mon 11 # for channel 11
  Compile with root@demon:~# gcc apsearchtool.c -lpcap -o apsearchtool.exe
*/
#include<stdio.h>
#include<stdlib.h> // for exit();
#include<pcap.h> // packet capture library
#include<netinet/in.h> // for the uint8_t
#include<string.h> // for strcat() BSSID to BPF (Berkley Packet Filter)
#include <signal.h> // handle CTRL+c

// explain the usage of the app:
void usage(){
	printf("Usage: ./apsearchtool.exe (MAC|0) wlan0dev\n\t* MAC: BSSID of AP\n\t0: Disable BSSID filtering\n\n");
	exit(1);
}

void sigintHandler(int sig_num)
{
    signal(SIGINT, sigintHandler);
		fflush(stdout);
		printf("\n[!] exiting ... \n\n");
		exit(1);
}

// handle each packet:
void packetHandler(u_char *args,const struct pcap_pkhdr *header,const u_char *packet){
	struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
		uint8_t it_rev; // Revision: Version of RadioTap
		uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
		uint16_t it_len;// Length: 26 - entire length of RadioTap header
	};

	signal(SIGINT, sigintHandler); // handle CTRL+c

	const u_char *rssi; // received signal strength
	const u_char *bssid; // bssid
	const u_char *essid; // name of AP "Free Public WiFi"
	const u_char *essidLen; // length of ESSID
	// NOTE TO DEVELOPERS: Use Wireshark on wlan0mon to find the offset specific to your driver/radiotap_headers.
	//  I am using Atheros ath9k with a USB ALFA adapter.
	// The following is a "tagged" parameter. The first byte (number) is the length of the ESSID 1-32 bytes I believe.
	// The next number (next byte in the sequence) is the essid string offset.
	essid = packet + 74; // store the ESSID (this is 74 bytes away from the first byte of the packet)
	essidLen = packet + 73; // store the ESSID length // this can be used to avoid looping bytes until >0x1 as belo

	// Generate the actual ESSID string:
	char *ssid = malloc(63); // 63 byte limit
	unsigned int i = 0; // used in loop below:
	while(essid[i] > 0x1){ // uncomment these to see each byte individually:
		//printf ("hex byte: %x\n",essid[i]); // view byte
		//printf ("hex char: %c\n",essid[i]); // view ASCII
		ssid[i] = essid[i]; // store the ESSID bytes in *ssid
		i++; // POSTFIX
	}
	ssid[i] = '\0'; // terminate the string

	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len; // 26 bytes on my machine

	bssid = packet + 52; // store the BSSID/AP MAC addr, 36 byte offset is transmitter address
	rssi = packet + 34; // this is hex and this value is subtracted from 256 to get -X dbm.
	signed int rssiDbm = rssi[0] - 256;
	// DEBUG:
	// fprintf(stdout,"[!] Packet detected. RSSI: %d dBm, BSSID: %02X:%02X:%02X:%02X:%02X:%02X, ESSID: %s\n",rssiDbm,bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],ssid);
	printf("\r[!] RSSID: %d                   ",rssiDbm);
}

// The main app:
int main(int argc,char* argv[]){
	printf("\n*** AP Search Tool ***\n2019 - WeakNetLabs\n\n");
	if(argc<3){ // not enough arguments:
		usage();
	}else{ // we have enough arguments, continue:
		char * dev = argv[2];
		char * mac2Search = argv[1];
		printf("[i] Device: %s\n",argv[2]);
		printf("[i] MAC to detect: %s\n",mac2Search);
		char *errorBuffer;
		pcap_t *handle; // create a file descriptor (handle) for WiFi device
		handle = pcap_open_live(dev, BUFSIZ, 0, 500, errorBuffer); // open the device
		// There is a BUG with pcap_open_live I found. A segmentation Fault occurs instead of errorBuffer being populated.
		char filter[64] = "type mgt subtype beacon"; // place to put our BPF string
		if(strlen(mac2Search)>1){ // use "0" or single byte for argv[1] to avoid filtering
			strcat(filter," and ether src "); // beacon frame WLAN
			strcat(filter,mac2Search); // concatenate the BSSID onto the end
		}
		struct bpf_program fp; // Berkley Packet Filter
		bpf_u_int32 netp;
		if(pcap_compile(handle,&fp,filter,0,netp)==-1) // -1 means failed
			fprintf(stderr,"Error compiling Libpcap filter, %s\n",filter);
		if(pcap_setfilter(handle,&fp)==-1) // -1 means failed - but we don't exit(1)
			fprintf(stderr,"Error setting Libpcap filter, %s\n",filter); // same as above
		pcap_loop(handle, 0, packetHandler, NULL); // dispatch to call upon packet
	}
	return 0;
}
