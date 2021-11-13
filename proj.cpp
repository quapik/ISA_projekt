#include "secret.h"

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
	int i;
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
  n++;
  

    my_ip = (struct ip*) (packet+16);        //  Přeskočení Linux Linux cooked capture
	unsigned char *data=(u_char*)(packet+16+20+8);	

	int sizedata = ntohs(my_ip->ip_len) - 16 - 8 - 20;
	data=DecryptFunction(data,sizedata);

	char checkfirst[8];


	// Kontrola zda se se jedna o prvni packet
	if (strlen((char*)data)>7  && strlen((char*)data)<200) //pouze prvni a posledni paket pric
	{
		for (int i=0; i<8; i++){
		checkfirst[i]=data[i];

		}
		if (strcmp(checkfirst,"F1LEN4ME")==0)
		{
			char *token = strtok((char*)data, ";");
					token = strtok(NULL, ";");
					filenamefrompacket=token;
					//std::cout << filenamefrompacket << " Filename from packet\n";
					token = strtok(NULL, ";");
					pocetfrompacket= atoi(token);
					token = strtok(NULL, ";");
					velikostposlednihopaketu= atoi(token);
					//std::cout << pocetfrompacket << " Pocet packetu\n";
					//std::cout << velikostposlednihopaketu<< " Velikost posledniho packetu\n";


					// otevrit (vytvorit soubor) a pak ho vypraznit (kvuli naslednemu appendovani)
					fstream myfilecreate(filenamefrompacket);
					myfilecreate.close();
					std::ofstream myfileempty; 
					myfileempty.open(filenamefrompacket, std::ofstream::out | std::ofstream::trunc | ios::binary);
					myfileempty.close();
					
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
			{	
				sizedata=velikostposlednihopaketu;
				myfilewrite.write((char * )data,sizedata);
			}
			else
			{
				
				sizedata=1424;
				myfilewrite.write((char * )data,sizedata);

			}
			  
			myfilewrite.close();
		}
		pocetfrompacket--;
		
	}
}


int main(int argc, char **argv){
	char *adresa;
	char *filename;
	int rflag = 0;
  	int sflag = 0;
	bool lflag = false;
	int c;
	while ((c = getopt (argc, argv, "r:s:l")) != -1){
		
		switch (c)
		{
		case('r'):
			
			filename=optarg;
			rflag=1;
			break;
		
		case ('s'):
			
			adresa=optarg;
			sflag=1;
			break;

		case ('l'):
			
			lflag=true;
			break;
		case ('?'):
		if (optopt=='s'||optopt=='r' )
		{
			fprintf(stderr,"Chybí argument i přepínače -%c",optopt);
			return 1;
		}
		}
		
	}

	if (lflag) {
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *handle;                 // packet capture handle 
		bpf_u_int32 netaddr;            // network address configured at the input device
		struct bpf_program fp;          // the compiled filter  bpf_u_it32 mask;      
		bpf_u_int32 mask;      

		 if (pcap_lookupnet("any",&netaddr,&mask,errbuf) == -1){
			fprintf(stderr,"pcap_open_live() selhalo");
			return 1;
		 }
    		
		//Otevreni any rozhrani (kvuli loopbacku)
		if ((handle = pcap_open_live("any",BUFSIZ,1,1000,errbuf)) == NULL){
			fprintf(stderr,"pcap_open_live() selhalo");
			return 1;
		}
			
		
		//Icmp or icmp6 filtr
		if (pcap_compile(handle,&fp,"icmp or icmp6",0,netaddr) == -1)
		{
			fprintf(stderr,"pcap_compile() selhalo");
			return 1;
		}
			
		
		// Nastavení filtrů a následný loop pro zachytávání paketů
		if (pcap_setfilter(handle,&fp) == -1){
			fprintf(stderr,"pcap_setfilter() selhalo");
			return 1;
		}
			

		if (pcap_loop(handle,-1,mypcap_handler,NULL) == -1) {
			fprintf(stderr,"pcap_loop() selhalo");
			return 1;
		}
   			
		
		pcap_close(handle);
		return 0;
			}

	else //- jedna se o klienta
	{
		if(!sflag || !rflag )
		{
			fprintf(stderr,"Chybí argument\n");
			return 1;
		}
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_RAW;  //?
	int addrinfo = getaddrinfo(adresa, NULL, &hints, &res);

    if (addrinfo != 0)  //getaddrinfo() returns 0 if it succeeds
	{
		fprintf(stderr, "%s \n", gai_strerror(addrinfo)); //The gai_strerror() function translates these error codes to a string
		return 1;
	}

    char ipaddress[50];

	inet_ntop(res->ai_family, get_in_addr(res->ai_addr), ipaddress, 50); //inet_ntop - convert IPv4 and IPv6 addresses from binary to text
	// 50 - he buffer dst must be at least INET6_ADDRSTRLEN bytes long (46)

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
				fprintf(stderr,"Neexistující soubor pro poslání\n");
				return 1;
			}
		size = file.tellg(); //velikost dat (v bytech)
		file.seekg (0, ios::beg);
		buffer = new char [size];
		file.read (buffer, size);
		file.close();

	
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
	std::string firstpacketvalue = "F1LEN4ME;";
	std::string filename_string(filename);
	std::string base_filename = filename_string.substr(filename_string.find_last_of("/\\") + 1);
	firstpacketvalue.append(base_filename );
	firstpacketvalue.append(";");
	firstpacketvalue.append(std::to_string(pocetpacketu));
	firstpacketvalue.append(";");
	firstpacketvalue.append(std::to_string(size%1424));
	
	char *cstr = new char[firstpacketvalue.length() + 1];
	strcpy(cstr, firstpacketvalue.c_str());

	unsigned char* CryptedData= CryptFunction(cstr,firstpacketvalue.length());
	delete [] cstr;
	memcpy(packet+sizeof(struct icmphdr),CryptedData,(firstpacketvalue.length() +(bytusifrovano - (firstpacketvalue.length()  % bytusifrovano))));

		/*ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
				const struct sockaddr *dest_addr, socklen_t addrlen);
				*/
		
		if (sendto(mysocket,packet,sizeof(struct icmp)+(firstpacketvalue.length() +(bytusifrovano - (firstpacketvalue.length()  % bytusifrovano))),0,res->ai_addr,res->ai_addrlen) <=1)
		{
			fprintf(stderr,"Chyba pri posilani uvodniho packetu\n"); //Locally detected errors are indicated by a return value of -1.
			return 1;
		}
	
		

	long done = 0;
	while (done < size)
	{
			long available;
			if (maxvelpacketu < (size-done)) {available=maxvelpacketu;}
			else {available=size-done;}

			char *buff1424 = (char * )malloc(sizeof(char) * available);
			memcpy(buff1424, buffer + done, available);
			done += available;		
			CryptedData= CryptFunction(buff1424,available);
			free(buff1424);
					 
		memcpy(packet+sizeof(struct icmphdr),CryptedData,available+(bytusifrovano - (available% bytusifrovano)));



		if (sendto(mysocket,packet,sizeof(struct icmp)+available+(bytusifrovano - (available% bytusifrovano)),0,res->ai_addr,res->ai_addrlen) <=1)
		{
			fprintf(stderr,"Chyba pri posilani\n"); //Locally detected errors are indicated by a return value of -1.
			return 1;
		}

	}
    return 0;
	}
	
}
