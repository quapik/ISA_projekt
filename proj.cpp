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
long n = 0;
#define __FAVOR_BSD    
int bytusifrovano=16;
//globalni promenne pro server
bool FileWasOopened=false;
long pocetfrompacket=0;
int velikostposlednihopaketu=0;
std::string filenamefrompacket;

//https://github.com/thlorenz/beejs-guide-to-network-samples/blob/master/lib/get_in_addr.c
void *get_in_addr(struct sockaddr *sa) {
  return sa->sa_family == AF_INET
    ? (void *) &(((struct sockaddr_in*)sa)->sin_addr)
    : (void *) &(((struct sockaddr_in6*)sa)->sin6_addr);
}

unsigned char* DecryptFunction(unsigned char* input,int size)
{	
	AES_KEY decryptkey;
	AES_set_decrypt_key((const unsigned char *)"xsimav01", 128, &decryptkey);
	unsigned char *output = (unsigned char *)calloc((size +(bytusifrovano - (size % bytusifrovano)))*sizeof(unsigned char* ),1);
	int i,j;
	int counter = 0;
	while (size > 0)
	{
		if (size > bytusifrovano)
		{
			unsigned char* input16 = (unsigned char *)calloc(bytusifrovano*sizeof(unsigned char*),1);
			for (i=0; i<bytusifrovano; i++)
			{
				input16[i]=input[bytusifrovano*counter+i];
			}
			AES_decrypt(input16,output+bytusifrovano*counter,&decryptkey);
			free(input16);
			size=size-bytusifrovano;
			counter++;
		}
		else
		{
			unsigned char* input16 = (unsigned char *)calloc(size*sizeof(unsigned char*),1);
			for (i=0; i<size; i++)
			{
				input16[i]=input[bytusifrovano*counter+i];
			}
			AES_decrypt(input16,output+bytusifrovano*counter,&decryptkey);
			free(input16);
			size=0;
		}
	
	}
	return output;

}
unsigned char* CryptFunction(char * input, long size){
	//cout << size << "velikost klient \n";
	AES_KEY encryptkey;
	AES_set_encrypt_key((const unsigned char *)"xsimav01", 128, &encryptkey); //AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
	unsigned char *output = (unsigned char *)calloc((size +(bytusifrovano - (size % bytusifrovano)))*sizeof(unsigned char* ),1); //neblizsi nasobek
	//cout << "size input " << size << " size output" <<  size +(16 - (size % 16)) << "\n";
	int i;
	int counter = 0;
	int pomsize=size;
	while (size > 0)
	{
		if (size > bytusifrovano)
		{
			unsigned char* input16 = (unsigned char *)calloc(bytusifrovano*sizeof(unsigned char*),1);
			for (i=0; i<bytusifrovano; i++)
			{
				input16[i]=input[bytusifrovano*counter+i];
			}
			AES_encrypt(input16,output+bytusifrovano*counter,&encryptkey);
			free(input16);
			size=size-bytusifrovano;
			counter++;
		}
		else
		{
			unsigned char* input16 = (unsigned char *)calloc(size*sizeof(unsigned char*),1);
			for (i=0; i<size; i++)
			{
				input16[i]=input[bytusifrovano*counter+i];
			}
			AES_encrypt(input16,output+bytusifrovano*counter,&encryptkey);
			free(input16);
			size=0;
		}
	
	}
	/*cout << "sifrovano\n";
	for (int p = 0; p < pomsize +(16 - (pomsize % 16)); p++)
	{
		cout << output[p];
	}*/

	return output;
	}
//--------------------------------

void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ip *my_ip;               // pointer to the beginning of IP header
  u_int size_ip;
  n++;
  
  //printf("Packet no. %d:\n",n);
  //printf("\tLength %d, received at %s",header->len,ctime((const time_t*)&header->ts.tv_sec));  
//printf("\tSource MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_shost)) ;
 //printf("\tDestination MAC: %s\n",ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));



    my_ip = (struct ip*) (packet+16);        //  uvodniho linuxuvskeho bordelu
	struct icmphdr *icmp = (struct icmphdr *)(packet+16+20);
	unsigned char *data=(u_char*)(packet+16+20+8);	


    //printf("\tIP: id 0x%x, hlen %d bytes, version %d, total length %d bytes, TTL %d\n",ntohs(my_ip->ip_id),size_ip,my_ip->ip_v,ntohs(my_ip->ip_len),my_ip->ip_ttl);
    //std::string src = inet_ntoa(my_ip->ip_src);
	//std::string dst = inet_ntoa(my_ip->ip_dst);
	//std::cout << data << "\n";
	int sizedata = ntohs(my_ip->ip_len) - 16 - 8 - 20;
	//cout << sizedata << "velikost server \n"; 
	data=DecryptFunction(data,sizedata);
	
	//printf("Desifrovano: %s\n",data);
	char checkfirst[8];
	

	


	// Kontrola zda se se jedna o prvni packet
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
					token = strtok(NULL, ";");
					velikostposlednihopaketu= atoi(token);
					std::cout << pocetfrompacket << " Pocet packetu\n";
					std::cout << velikostposlednihopaketu<< " Velikost posledniho packetu\n";


					// otevrit (vytvorit soubor) a pak ho vypraznit (kvuli naslednemu appendovani)
					fstream myfilecreate(filenamefrompacket);
					myfilecreate.close();
					std::ofstream myfileempty; 
					myfileempty.open(filenamefrompacket, std::ofstream::out | std::ofstream::trunc | ios::binary);
					myfileempty.close();
					cout << filenamefrompacket << "\n";
					return;
					
		}
	}
	// Pokud jsou jeste nejake pakety ktere maji prijit, zapiseou data z tohoto packetu do fouboru
	if(pocetfrompacket>0)
	{	
		ofstream myfilewrite; 
   		myfilewrite.open(filenamefrompacket,ios::app| ios::out |ios::binary);  
		if(myfilewrite.is_open()) 
		{	
			if(pocetfrompacket==1) 
			{	//cout << velikostposlednihopaketu << "  check velukost\n";
				sizedata=velikostposlednihopaketu;
				myfilewrite.write((char * )data,sizedata);
			}
			else
			{
				//cout <<  "writefulll\n " << pocetfrompacket << "  pocet from packet\n";
				sizedata=1424;
				myfilewrite.write((char * )data,sizedata);

			}
			  
			myfilewrite.close();
		}
		pocetfrompacket--;
		
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
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle;                 // packet capture handle 
		bpf_u_int32 netaddr;            // network address configured at the input device
		struct bpf_program fp;          // the compiled filter

		//Otevreni any rozhrani (kvulo loopbacku)
		if ((handle = pcap_open_live("any",BUFSIZ,1,1000,errbuf)) == NULL)
			printf("pcap_open_live() failed");
		
		//Icmp or icmp6 filtr
		if (pcap_compile(handle,&fp,"icmp or icmp6",0,netaddr) == -1)
			printf("pcap_compile() failed");
		
		// Nastavení filtrů a následný loop pro zachytávání paketů
		if (pcap_setfilter(handle,&fp) == -1)
			printf("pcap_setfilter() failed");

		if (pcap_loop(handle,-1,mypcap_handler,NULL) == -1)
   			printf("pcap_loop() failed");
		
		pcap_close(handle);
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
	int maxvelpacketu=1424; //ipv4 (1500-20(ipv4 hlavicka)-8(sizeof icmph)-16)
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
		// Otevření zadaného souboru a načtení jeho dat do bufferu
	   	char * buffer;
		long size;
		ifstream file (filename, ios::in|ios::binary|ios::ate);
		if (file.fail())
			{
				std::cerr << "Neexistující soubor pro poslání" << std::endl;
				return 1;
			}
		size = file.tellg(); //velikost dat (v bytech)
		file.seekg (0, ios::beg);
		buffer = new char [size];
		file.read (buffer, size);
		file.close();
		/*cout << size << "VS" << my_file_data.length() << "\n";
		cout << "the complete file is in a buffer\n";
		for (long x= 0; x <size; x++){
			cout << buffer[x];
		}*/

	
	// Zjisteni v kolika packetech budou data poslany
	long pocetpacketu=0;
	if (size % maxvelpacketu==0) { pocetpacketu=size / maxvelpacketu;}
	else {pocetpacketu=(size / maxvelpacketu) +1;}

	char packet[maxvelpacketu];
	memset(&packet, 0,maxvelpacketu);
	struct icmphdr* icmp =(struct icmphdr *)packet;
	icmp->code=ICMP_ECHO;
	icmp->type=8; //ECHO

	// Vytvareni prvniho packetu ktery bude obsahovat nazev souboru a pocet packetu
	std::string firstpacketvalue = "FILENAME;";
	std::string filename_string(filename);
	std::string base_filename = filename_string.substr(filename_string.find_last_of("/\\") + 1);
	firstpacketvalue.append(base_filename );
	firstpacketvalue.append(";");
	firstpacketvalue.append(std::to_string(pocetpacketu));
	firstpacketvalue.append(";");
	firstpacketvalue.append(std::to_string(size%1424));
	cout << firstpacketvalue << "First packet value \n";
	char *cstr = new char[firstpacketvalue.length() + 1];
	strcpy(cstr, firstpacketvalue.c_str());

	unsigned char* CryptedData= CryptFunction(cstr,firstpacketvalue.length());
	cout << firstpacketvalue.length() << "lenght\n";
	cout << (firstpacketvalue.length() +(bytusifrovano - (firstpacketvalue.length()  % bytusifrovano))) << "strlen\n";
	delete [] cstr;
	memcpy(packet+sizeof(struct icmphdr),CryptedData,(firstpacketvalue.length() +(bytusifrovano - (firstpacketvalue.length()  % bytusifrovano))));

		/*ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
				const struct sockaddr *dest_addr, socklen_t addrlen);
				*/
		
		if (sendto(mysocket,packet,sizeof(struct icmp)+(firstpacketvalue.length() +(bytusifrovano - (firstpacketvalue.length()  % bytusifrovano))),0,res->ai_addr,res->ai_addrlen) <=1)
		{
			fprintf(stderr,"Chyba pri posilani uvodniho packetu"); //Locally detected errors are indicated by a return value of -1.
			return 1;
		}
	
		//std::cout << "Send packet \n";

	long done = 0;
	while (done < size)
	{
			long available;
			if (maxvelpacketu < (size-done)) {available=maxvelpacketu;}
			else {available=size-done;}

			char *buff1430 = (char * )malloc(sizeof(char) * available);
			memcpy(buff1430, buffer + done, available);
			done += available;		
			CryptedData= CryptFunction(buff1430,available);
			free(buff1430);
					 
		memcpy(packet+sizeof(struct icmphdr),CryptedData,available+(bytusifrovano - (available% bytusifrovano)));

		/*ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
				const struct sockaddr *dest_addr, socklen_t addrlen);
				*/

		if (sendto(mysocket,packet,sizeof(struct icmp)+available+(bytusifrovano - (available% bytusifrovano)),0,res->ai_addr,res->ai_addrlen) <=1)
		{
			fprintf(stderr,"Chyba pri posilani"); //Locally detected errors are indicated by a return value of -1.
			return 1;
		}
		//std::cout << "Send packet \n";
	}
    return 0;
	}
	
}
