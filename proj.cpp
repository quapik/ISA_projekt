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
#include <netinet/ether.h> 

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

using std::ifstream;
using namespace std;
int n = 0;
#define __FAVOR_BSD    

//globalni promenne pro server
bool FileWasOopened=false;
int pocetfrompacket=0;
std::string filenamefrompacket;



void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
	{	

		return &(((struct sockaddr_in *)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

unsigned char* DecryptFunction(unsigned char* input)
{
	AES_KEY decryptkey;
	AES_set_decrypt_key((const unsigned char *)"xsimav01", 256, &decryptkey);
	unsigned char input32[AES_BLOCK_SIZE];
	unsigned char *output32 =(unsigned char *)calloc(AES_BLOCK_SIZE,1);
	unsigned char *output = (unsigned char *)calloc(strlen((char *)input) +(AES_BLOCK_SIZE - (strlen((char *)input) % AES_BLOCK_SIZE)),1); //neblizsi nasobek
	int i, j;
	printf("%ld sizeof\n",strlen((char *)input));
	for (i = 0; i < strlen((char *)input); i=i+AES_BLOCK_SIZE) 
	{
		for (j=0; j < AES_BLOCK_SIZE; j++)
		{
			input32[j]=input[i+j];
		}
		
		AES_decrypt(input32,output32,&decryptkey);
		for (j=0; j < AES_BLOCK_SIZE; j++)
		{
			output[i+j]=output32[j];
		}
	
	}
	return output;

}
unsigned char* CryptFunction(std::string s){
	
	AES_KEY encryptkey;

	AES_set_encrypt_key((const unsigned char *)"xsimav01", 256, &encryptkey); //AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
	
	int inputlen = s.length();
	unsigned char input[inputlen + 1];
	int i, j;
    for (i = 0; i < sizeof(input); i++) 
	{
        input[i] = s[i];
    }
	unsigned char input32[AES_BLOCK_SIZE];
	unsigned char *output32 =(unsigned char *)calloc(AES_BLOCK_SIZE,1);
	unsigned char *output = (unsigned char *)calloc(inputlen +(AES_BLOCK_SIZE - (inputlen % AES_BLOCK_SIZE)),1); //neblizsi nasobek
	
	for (i = 0; i < sizeof(input); i=i+AES_BLOCK_SIZE) 
	{
		for (j=0; j < AES_BLOCK_SIZE; j++)
		{
			input32[j]=input[i+j];
		}
		
		AES_encrypt(input32,output32,&encryptkey);
		for (j=0; j < AES_BLOCK_SIZE; j++)
		{
			output[i+j]=output32[j];
		}
	
	}
	
	
	printf("Puvodni: %s\n",input);
	printf("Sifrovano: %s\n",output);
	/*for (unsigned i =0; i< AES_BLOCK_SIZE; i++)
	{
		printf("%X " ,output[i]);
	}
	*/

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
  eptr = (struct ether_header *) packet+2;
  printf("\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
  printf("\tDestination MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));



    my_ip = (struct ip*) (packet+16);        // skip Ethernet header
    size_ip = my_ip->ip_hl*4;                           // length of IP header
	struct icmphdr *icmp = (struct icmphdr *)(packet+16+20);
	unsigned char *data=(u_char*)(packet+16+20+8);	


    printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n",ntohs(my_ip->ip_id),size_ip,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
    std::string src = inet_ntoa(my_ip->ip_src);
	std::string dst = inet_ntoa(my_ip->ip_dst);
	std::cout << src << "\n";
	std::cout << dst << "\n";
	std::cout << std::to_string(icmp->type) << "\n";
	std::cout << std::to_string(icmp->code) << "\n";
	std::cout << data << "\n";
	data=DecryptFunction(data);
	printf("Desifrovano: %s\n",data);
	char checkfirst[8];

	


	//kontrola zda se se jedna o prvni packet
	if (strlen((char*)data)>7  && strlen((char*)data)<100)
	{
		for (int i=0; i<8; i++){
		checkfirst[i]=data[i];

		}
		if (strcmp(checkfirst,"FILENAME")==0)
		{
			char *token = strtok((char*)data, ";");
					token = strtok(NULL, ";");
					filenamefrompacket=token;
					std::cout << filenamefrompacket << " Filename from packet\n";
					token = strtok(NULL, ";");
					pocetfrompacket= atoi(token);
					std::cout << pocetfrompacket << " Pocet packetu\n";
					// otevrit (vytvorit soubor) a pak ho vypraznit (kvuli naslednemu appendovani)
					fstream MyFile("ser_"+filenamefrompacket);
					MyFile.close();
					FileWasOopened=true;
					std::ofstream ofs;
					ofs.open("ser_"+filenamefrompacket, std::ofstream::out | std::ofstream::trunc | ios::binary);
					ofs.close();
					return;
					
		}
	}

	if(FileWasOopened && pocetfrompacket>0)
	{	
		fstream myfile;
   		myfile.open("ser_"+filenamefrompacket,ios::app| ios::binary);  // open a file to perform write operation using file object
		if(myfile.is_open()) //checking whether the file is open
		{
			myfile<<data << std::endl;   //inserting text
			pocetfrompacket--;
			if (pocetfrompacket==0)
			{
				FileWasOopened=false;
			}
			myfile.close();    //close the file object
		}

		



	}
	
	
  

  
}



int main(int argc, char **argv){
	char *pom;
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
		if (pcap_lookupnet(NULL,&netaddr,&mask,errbuf) == -1)
			printf("pcap_lookupnet() failed");

		a.s_addr=netaddr;
		printf("Opening interface \"%s\" with net address %s,",devname,inet_ntoa(a));
		b.s_addr=mask;
		printf("mask %s for listening...\n",inet_ntoa(b));

				// open the interface for live sniffing
		if ((handle = pcap_open_live("any",BUFSIZ,1,1000,errbuf)) == NULL)
			printf("pcap_open_live() failed");
		
		// compile the filter
		if (pcap_compile(handle,&fp,"icmp or icmp6",0,netaddr) == -1)
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
	int maxvelpacketu=1430; //ipv4 (1500-20(ipv4 hlavicka)-8(sizeof icmph)-32)
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



	  string my_file_data;	
	  fstream myfile;
      myfile.open(filename,ios::in  | ios::binary);
	  if (myfile.is_open()){   //checking whether the file is open
      string tp;
      while(getline(myfile, tp)){ //read data from file object and put it into string.
         my_file_data.append(tp);
      }
      myfile.close(); //close the file object.
	  }

	   	char * buffer;
		long size;
		ifstream file (filename, ios::in|ios::binary|ios::ate);
		size = file.tellg();
		file.seekg (0, ios::beg);
		buffer = new char [size];
		file.read (buffer, size);
		file.close();
		cout << size << "VS" << my_file_data.length() << "\n";
		cout << "the complete file is in a buffer\n";
		for (long x= 0; x <size; x++){
			cout << buffer[x];
		}



	
	// Zjisteni v kolika packetech budou data poslany
	int pocetpacketu=0;
	if (my_file_data.length() % 1430==0) { pocetpacketu=my_file_data.length() / 1430;}
	else {pocetpacketu=my_file_data.length() / 1430 +1;}

	char packet[maxvelpacketu];
	memset(&packet, 0,maxvelpacketu);
	struct icmphdr* icmp =(struct icmphdr *)packet;
	icmp->code=ICMP_ECHO;
	icmp->type=8; //ECHO
	std::string firstpacketvalue = "FILENAME;";
	firstpacketvalue.append(filename);
	firstpacketvalue.append(";");
	firstpacketvalue.append(std::to_string(pocetpacketu));
	unsigned char* CryptedData= CryptFunction(firstpacketvalue);

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

		CryptedData= CryptFunction(my_file_data_splitted);
		printf("Velikost pri poslani %ld\n",strlen((char *)CryptedData));
		printf("Length %lu\n",my_file_data.length());
	
		 
		
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
	}
		
	std::cout << "celkem bude packetu  "<<  pocetpacketu << '\n';
    return 0;
	
	}
	
}
