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
using std::ifstream;




void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
	{	

		return &(((struct sockaddr_in *)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}


int main(int argc, char **argv){
	char *pom="google.com";
	int rflag = 0;
  	int sflag = 0;
	int c;
	while ((c = getopt (argc, argv, "r:s:")) != -1){
		
		switch (c)
		{
		case('r'):
			printf("R arg %s\n",optarg);
			rflag=1;
			break;
		
		case ('s'):
			printf("S arg %s\n",optarg);
			pom=optarg;
			sflag=1;
			break;
		case ('?'):
		if (optopt=='s'||optopt=='r' )
		{
			printf("Chybi arguument u -%c",optopt);
		}
		}
	}
    
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
	int maxvelpacketu=1500;
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

	char packet[maxvelpacketu];
	memset(&packet, 0,maxvelpacketu);
	char zprava[]="a";
	struct icmphdr* icmp;
	icmp = (struct icmphdr*)(packet + sizeof(struct icmphdr));
	icmp->code=ICMP_ECHO;
	memcpy(packet,zprava,strlen(zprava));

	/*ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen);
			   */

	if (sendto(mysocket,packet,sizeof(struct icmp)+strlen(zprava),0,res->ai_addr,res->ai_addrlen) <=1)
	{
		fprintf(stderr,"Chyba pri posilani"); //Locally detected errors are indicated by a return value of -1.
		return 1;
	}

	unsigned char input [] = "AhojAhojAhojAhojAhojAhojAhojAhojAhojAHoj";
	int inputlen = 40;
	AES_KEY encryptkey;
	AES_KEY decryptkey;
	AES_set_encrypt_key((const unsigned char *)"xsimav01", 256, &encryptkey); //AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
	AES_set_decrypt_key((const unsigned char *)"xsimav01", 256, &decryptkey);

	unsigned char *output = (unsigned char *)calloc(inputlen +(inputlen % AES_BLOCK_SIZE),1);//TODO? naopak?
	printf("%s\n",input);
	AES_encrypt(input,output,&encryptkey);
	printf("%s\n",output);
	for (unsigned i =0; i< AES_BLOCK_SIZE; i++){
		printf("%X " ,output[i]);
	}
	AES_decrypt(output,input,&decryptkey);
	printf("\n%s\n",input);

	ifstream my_file;
	std::string s = "";
	my_file.open("text.txt"); // opens the file
    if(!my_file) { // file couldn't be opened
      printf("Error: file could not be opened\n");
      exit(1);
   	}
	else {
		char ch;

		while (1) {
			my_file >> ch;
			if (my_file.eof())
				break;
			
			s.append(1,ch);
		}
		std::cout << s;
		printf("Size of %lu\n",sizeof(s));
		for (int i = 0; i < sizeof(s);i++)
		{
			printf("Char %c\n",s[i]);
		}
		
			
		}
	my_file.close();

	

    return 0;
}