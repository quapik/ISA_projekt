#include <stdio.h>
#include <openssl/aes.h>
#include <string.h>	 
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_ntop
#include <netdb.h>	 //sockaddr
#include <netinet/ip_icmp.h>
#include <ctype.h>
#include <unistd.h>
#include<iostream>
#include <fstream>
#include <pcap.h>
using std::ifstream;
int n = 0;





void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
	{	

		return &(((struct sockaddr_in *)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}
unsigned char* CryptFunction(std::string s){
	
	AES_KEY encryptkey;
	AES_KEY decryptkey;
	AES_set_encrypt_key((const unsigned char *)"xsimav01", 256, &encryptkey); //AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
	AES_set_decrypt_key((const unsigned char *)"xsimav01", 256, &decryptkey);
	int inputlen = s.length();
	unsigned char input[inputlen + 1];
	int i, j;
    for (i = 0; i < sizeof(input); i++) 
	{
        input[i] = s[i];
    }
	unsigned char input44[AES_BLOCK_SIZE];
	unsigned char *output44 =(unsigned char *)calloc(AES_BLOCK_SIZE,1);
	unsigned char *output = (unsigned char *)calloc(inputlen +(AES_BLOCK_SIZE - (inputlen % AES_BLOCK_SIZE)),1); //neblizsi nasobek
	
	for (i = 0; i < sizeof(input); i=i+AES_BLOCK_SIZE) 
	{
		for (j=0; j < AES_BLOCK_SIZE; j++)
		{
			input44[j]=input[i+j];
		}
		
		AES_encrypt(input44,output44,&encryptkey);
		for (j=0; j < AES_BLOCK_SIZE; j++)
		{
			output[i+j]=output44[j];
		}
	
	}
	
	
	printf("Puvodni: %s\n",input);
	printf("Sifrovano: %s\n",output);
	/*for (unsigned i =0; i< AES_BLOCK_SIZE; i++)
	{
		printf("%X " ,output[i]);
	}
	*/

	for (i = 0; i < sizeof(output); i=i+AES_BLOCK_SIZE) 
		{
			for (j=0; j < AES_BLOCK_SIZE; j++)
			{
				output44[j]=output[i+j];
			}
			
			AES_decrypt(output44,input44,&decryptkey);
			for (j=0; j < AES_BLOCK_SIZE; j++)
			{
				input[i+j]=input44[j];
			}
		
		}
	printf("\nDesifrovano: %s\n",input);
	return output;
	}
//--------------------------------

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ip *my_ip;               // pointer to the beginning of IP header
  struct ether_header *eptr;      // pointer to the beginning of Ethernet header
  const struct tcphdr *my_tcp;    // pointer to the beginning of TCP header
  const struct udphdr *my_udp;    // pointer to the beginning of UDP header
  u_int size_ip;
  n++;
  printf("Packet no. %d:\n",n);
  printf("\tLength %d, received at %s",header->len,ctime((const time_t*)&header->ts.tv_sec));  
}



int main(int argc, char **argv){
	char *pom="google.com";
	char *filename;
	int rflag = 0;
  	int sflag = 0;
	bool lflag = false;
	int c;
	while ((c = getopt (argc, argv, "r:s:l")) != -1){
		
		switch (c)
		{
		case('r'):
			printf("R arg %s\n",optarg);
			filename=optarg;
			rflag=1;
			break;
		
		case ('s'):
			printf("S arg %s\n",optarg);
			pom=optarg;
			sflag=1;
			break;

		case ('l'):
			printf("L arg \n");
			lflag=true;
			break;
		case ('?'):
		if (optopt=='s'||optopt=='r' )
		{
			printf("Chybi arguument u -%c",optopt);
		}
		}
		
	}

	if (lflag) {
		printf("SERVER\n");
		char *devname;    
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle;                 // packet capture handle 
		pcap_if_t *alldev, *dev ;       // a list of all input devices
		struct in_addr a,b;
		bpf_u_int32 netaddr;            // network address configured at the input device
		bpf_u_int32 mask;               // network mask of the input device
		struct bpf_program fp;          // the compiled filter

		// open the input devices (interfaces) to sniff data
		if (pcap_findalldevs(&alldev, errbuf))
		{
			printf("Can't open input device(s)");
		}
    	

		// list the available input devices
		printf("Available input devices are: ");
		for (dev = alldev; dev != NULL; dev = dev->next){
			printf("%s ",dev->name);
		}
		printf("\n");
		devname = alldev->name;
		printf("Selected devname: %s\n",devname);

		 // get IP address and mask of the sniffing interface
		if (pcap_lookupnet(devname,&netaddr,&mask,errbuf) == -1)
			printf("pcap_lookupnet() failed");

		a.s_addr=netaddr;
		printf("Opening interface \"%s\" with net address %s,",devname,inet_ntoa(a));
		b.s_addr=mask;
		printf("mask %s for listening...\n",inet_ntoa(b));

				// open the interface for live sniffing
		if ((handle = pcap_open_live(devname,BUFSIZ,1,1000,errbuf)) == NULL)
			printf("pcap_open_live() failed");
		
		// compile the filter
		if (pcap_compile(handle,&fp,"icmp",0,netaddr) == -1)
			printf("pcap_compile() failed");
		
		// set the filter to the packet capture handle
		if (pcap_setfilter(handle,&fp) == -1)
			printf("pcap_setfilter() failed");

		if (pcap_loop(handle,-1,mypcap_handler,NULL) == -1)
   			printf("pcap_loop() failed");
		
		pcap_close(handle);
		pcap_freealldevs(alldev);
		return 0;
			}

	else //- jedna se o klienta
	{
		struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_RAW;  //?
	int addrinfo = getaddrinfo(pom, NULL, &hints, &res);

    if (addrinfo != 0)  //getaddrinfo() returns 0 if it succeeds
	{
		fprintf(stderr, "%s \n", gai_strerror(addrinfo)); //The gai_strerror() function translates these error codes to a string
		return 1;
	}

    char ipaddress[50];

	inet_ntop(res->ai_family, get_in_addr(res->ai_addr), ipaddress, 50); //inet_ntop - convert IPv4 and IPv6 addresses from binary to text
	// 50 - he buffer dst must be at least INET6_ADDRSTRLEN bytes long (46)
	if (ipaddress!=NULL)
	{
		printf("ip: %s\n", ipaddress);
	}


	int protocol;
	int maxvelpacketu=1472; //ipv4 (1500-20(ipv4 hlavicka)-8(sizeof icmph))
	if (res->ai_family == AF_INET) //nastaveni protokolu na zaklade family
		{
			protocol = IPPROTO_ICMP;
		}
	else
		{
			protocol= IPPROTO_ICMPV6;
		}

	//printf("Protokol %d \n",protocol); //DEBUG 
	int mysocket = socket(res->ai_family,res->ai_socktype,protocol); // int socket(int domain, int type, int protocol);

	if (mysocket==-1)
	{
		fprintf(stderr,"Chyba pri vytvareni socketu\n");
		return 1;
	}


	ifstream my_file;
	std::string my_file_data = "";
	my_file.open(filename); // opens the file
    if(!my_file) { // file couldn't be opened
      printf("Error: file could not be opened\n");
      exit(1);
   	}
	else {
		char ch;
		unsigned int counter=0;
		while (1) {
			my_file >> ch;
			if (my_file.eof())
				break;
			
			my_file_data.append(1,ch);
			counter++;
		}
		printf("Length %lu\n",my_file_data.length());
				
		}
	my_file.close();

	//std::cout << s << "\n";
	std::string my_file_data_splitted;
	while(my_file_data!="")
	{
		
		if (my_file_data.length()<maxvelpacketu)
		{
			my_file_data_splitted=my_file_data.substr(0,my_file_data.length());
			my_file_data.erase(my_file_data.begin(),my_file_data.begin()+my_file_data.length());
		}
		else
		{
			my_file_data_splitted=my_file_data.substr(0,maxvelpacketu);
			my_file_data.erase(my_file_data.begin(),my_file_data.begin()+maxvelpacketu);
		}

		unsigned char* CryptedData= CryptFunction(my_file_data_splitted);
		char packet[maxvelpacketu];
		memset(&packet, 0,maxvelpacketu);
		struct icmphdr* icmp =(struct icmphdr *)packet;
		icmp->code=ICMP_ECHO;
		icmp->type=8; //ECHO
		memcpy(packet+sizeof(struct icmphdr),CryptedData,strlen((char*)CryptedData));

		/*ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
				const struct sockaddr *dest_addr, socklen_t addrlen);
				*/

		if (sendto(mysocket,packet,sizeof(struct icmp)+strlen((char*)CryptedData),0,res->ai_addr,res->ai_addrlen) <=1)
		{
			fprintf(stderr,"Chyba pri posilani"); //Locally detected errors are indicated by a return value of -1.
			return 1;
		}
		std::cout << "Send packet \n";
		std::cout << packet;
	}
	
    return 0;
	
	}
	
}
