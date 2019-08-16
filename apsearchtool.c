/*
  2019 WeakNet Labs
  Douglas Berdeaux
  WeakNetLabs@Gmail.com

  This AP Search Tool utilizes RSSI in the Radiotap Header.
  * You must set your specific offset in the code below before compiling.
      This can be found using Wireshark and counting the bytes from the first byte in the packet to the BSSID byte.
  * You must also set your frequency beforehand using something like,
      iwconfig wlan0mon 11 # for channel 11
  * Compile with:
      root@demon:~# gcc apsearchtool.c -lpcap -o apsearchtool.exe
*/
#include<stdio.h>
#include<stdlib.h> // for exit();
#include<pcap.h> // packet capture library
#include<netinet/in.h> // for the uint8_t
#include<string.h> // for strcat() BSSID to BPF (Berkley Packet Filter)
#include<signal.h> // handle CTRL+c
#include<stdbool.h> //  for Booleans

// ANSI Colors for cute terminal output:
#define GREEN "\033[1;32m"
#define RED "\033[1;31m"
#define YELLOW "\033[1;33m"
#define RESET "\033[0m"
#define CYAN "\033[1;36m"
#define BOLD "\033[1;39m"
#define BLOCK "\xe2\x96\xae" // for signal strength
#define WHITESPACE "                                          "

// explain the usage of the app with an example:
void usage(){
  printf(" %s[E] - Error %s SEE USAGE BELOW: \n",RED,RESET);
	printf(" %sUsage:%s ./apsearchtool.exe (MAC|0) (device)\n\t%s*%s MAC: BSSID of AP ",BOLD,RESET,BOLD,RESET);
  printf("(0: Disable BSSID filtering)\n\t%s*%s Device: wlan0mon, wlan1, eth1, etc",BOLD,RESET);
  printf("\n\t%s*%s Example: ./apsearchtool.exe 00:11:22:33:44:55 wlan0",BOLD,RESET);
  printf("\n\t%s*%s CTRL+c to exit.\n\n",BOLD,RESET);
	exit(1);
}

// Prototype this data BEFORE accessing it anywhere to be used properly:
typedef struct PcapLoopData { // definition must be outside of main()
  char * bssid;
  bool filter;
}PcapLoopData; // This redundancy needs explained to me ...

void sigintHandler(int sig_num)
{
    signal(SIGINT, sigintHandler);
		fflush(stdout);
		printf("\n\n%s[E]%s exiting ... \n\n",RED,RESET);
		exit(1);
}

// handle each packet:
void packetHandler(void *args,const struct pcap_pkhdr *header,const u_char *packet){
	struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
		uint8_t it_rev; // Revision: Version of RadioTap
		uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
		uint16_t it_len;// Length: 26 - entire length of RadioTap header
	};

  //struct my_struct *something = (struct my_struct *)args;
  //struct PcapLoopData *pcap_loop_data = (struct PcapLoopData *)args;

  struct PcapLoopData *pcap_loop_data = (struct PcapLoopData *)args;

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

	//int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	//offset = rtaphdr->it_len; // 26 bytes on my machine

	bssid = packet + 52; // store the BSSID/AP MAC addr, 36 byte offset is transmitter address
	rssi = packet + 34; // this is hex and this value is subtracted from 256 to get -X dbm.
	signed int rssiDbm = rssi[0] - 256;
  // Develop and show strength bar:
  int barLength = rssiDbm;
  barLength = 100 + (barLength);
  barLength = (barLength / 10) * 2; // (-45RSSI = 55 / 5 * 2 = 10 bars AND -80RSSI = 20/10 = 2 * 2 = 4 bars. get it?
  if(barLength<1)
    barLength=1;
  int l;
  // Show the BSSID if we are scanning for ALL:
  printf("\r%s\xe2\x9e\x9c%s ",GREEN,RESET);
  if(pcap_loop_data->filter==false){
    fprintf(stdout," BSSID: %s%02X:%02X:%02X:%02X:%02X:%02X%s -> ",GREEN,bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],RESET);
  }

  printf("RSSI(%d): ",rssiDbm);

  // Let's color the bar now:
  if(barLength<=3){ // 1,2,3
    printf("%s",RED);
  }else if(barLength>=4 && barLength<=7){ // 4,5,6,7
    printf("%s",YELLOW);
  }else{ // 8,9,10
    printf("%s",GREEN);
  }
  // print the bar in ANSI BLOCKs:
  for(l=0;l<barLength;l++){
    printf("%s",BLOCK);
  }
  printf("%s%s",RESET,WHITESPACE);
}


// The main() workflow of the C app:
int main(int argc,char* argv[]){ // This takes arguments from the command line into argv[]

  struct PcapLoopData pcap_loop_data; // This is the struct of data that we will pass to the pcap_loop() packet handler

	printf("\n %s\xe2\x9a\xa1%s AP Search Tool %s\xe2\x9a\xa1%s\n 2019 - WeakNetLabs%s\n\n",YELLOW,BOLD,YELLOW,BOLD,RESET);
	if(argc<3){ // not enough arguments:
		usage();
	}else{ // we have enough arguments, continue:
		char * dev = argv[2];
		char * mac2Search = argv[1];
		printf("[+] Device: %s\n",argv[2]);
    if(strlen(mac2Search)>1){
      printf("[+] MAC to detect: %s\n\n",mac2Search);
    }else{
      printf("[+] BSSID filtering disabled. Showing any RSSI.\n\n");
    }
		char *errorBuffer;
		pcap_t *handle; // create a file descriptor (handle) for WiFi device
		handle = pcap_open_live(dev, BUFSIZ, 0, 500, errorBuffer); // open the device
		// There is a BUG with pcap_open_live I found. A segmentation Fault occurs instead of errorBuffer being populated.
		char filter[64] = "type mgt subtype beacon"; // place to put our BPF string
		if(strlen(mac2Search)>1){ // use "0" or single byte for argv[1] to avoid filtering
			strcat(filter," and ether src "); // beacon frame WLAN
			strcat(filter,mac2Search); // concatenate the BSSID onto the end
      pcap_loop_data.filter = true; // set the boolean
		}
		struct bpf_program fp; // Berkley Packet Filter
		bpf_u_int32 netp;
		if(pcap_compile(handle,&fp,filter,0,netp)==-1) // -1 means failed
			fprintf(stderr,"Error compiling Libpcap filter, %s\n",filter);
		if(pcap_setfilter(handle,&fp)==-1) // -1 means failed - but we don't exit(1)
			fprintf(stderr,"Error setting Libpcap filter, %s\n",filter); // same as above
		pcap_loop(handle, 0, packetHandler, (u_char*)&pcap_loop_data); // dispatch to call upon packet
	}
	return 0;
}
