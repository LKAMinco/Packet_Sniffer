/************************
 * Title: Packet Sniffing
 * Author: Milan Hrabovský
 * Login: xhrabo15
 * Subject: IPK
 * Sources:
 * Pcap library - https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
 * convert time - https://www.epochconverter.com/programming/c
 * getting ip - https://stackoverflow.com/questions/21222369/getting-ip-address-of-a-packet-in-pcap-file
 * getting mac adress - https://stackoverflow.com/questions/4526576/how-do-i-capture-mac-address-of-access-points-and-hosts-connected-to-it
************************/
#include "iostream"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>
#include <netinet/ip6.h>

using namespace std;


class ArgumentParser {
public:
    ArgumentParser(int argc, char **argv);

    const char *interface = "";
    string filter;
    bool print_interface = true;
    int n = 1;
private:
    int port = -1;
    bool tcp = false;
    bool udp = false;
    bool arp = false;
    bool icmp = false;

    static bool isValidInt(char *argument);

    static bool isValidString(char *argument);

    void makeFilter();
};

ArgumentParser::ArgumentParser(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--interface")) { //TODO pridat kontrolu či ma dalši argument
            if (i + 1 > argc - 1)
                continue;
            if (isValidString(argv[i + 1])) { //validate next parameter
                this->interface = argv[i + 1];
                i = i + 1;
                print_interface = false;
                continue;
            } else
                continue;
        } else if (!strcmp(argv[i], "-p")) {
            if (i + 1 <= argc - 1) {
                if (isValidInt(argv[i + 1]) and
                    atoi(argv[i + 1]) <= 65535) { //check whether the port is unsigned int in range 0 - 65535
                    port = atoi(argv[i + 1]);
                    i = i + 1;
                    continue;
                } else {
                    cerr << "Wrong port number" << endl;
                    exit(1);
                }
            } else {
                cerr << "Missing port number" << endl;
                exit(1);
            }
        } else if (!strcmp(argv[i], "--tcp") || !strcmp(argv[i], "-t"))
            tcp = true;
        else if (!strcmp(argv[i], "--udp") || !strcmp(argv[i], "-u"))
            udp = true;
        else if (!strcmp(argv[i], "--arp"))
            arp = true;
        else if (!strcmp(argv[i], "--icmp"))
            icmp = true;
        else if (!strcmp(argv[i], "-n")) {
            if (isValidInt(argv[i + 1])) {
                n = atoi(argv[i + 1]);
                if (n >= 0) {
                    i = i + 1;
                    continue;
                } else {
                    cerr << "Wrong number of packets" << endl;
                    exit(1);
                }
            }
        } else { //return erro if there is unknown argument
            cerr << "Invalid argument" << endl;
            exit(1);
        }
    }
    makeFilter();
}


bool ArgumentParser::isValidInt(char *argument) {
    char *p;
    int convert = strtol(argument, &p, 10);
    if (*p == 0)
        return convert >= 0;
    else
        return false;
}


bool ArgumentParser::isValidString(char *argument) {
    return strncmp(argument, "--", 2);
}

void ArgumentParser::makeFilter() {
    string filter;
    if (!tcp and !udp and !arp and !icmp)
        tcp = udp = arp = icmp = true;
    //set filter for tcp
    if (tcp) {
        if (!filter.empty())
            filter += " or ";
        filter += "(tcp and ";
        if (port != -1)
            filter += "port " + to_string(port) + ")"; //set specified port
        else
            filter += "portrange 0-65535)";
    }
    //set filter for udp
    if (udp) {
        if (!filter.empty())
            filter += " or ";
        filter += "(udp and ";
        if (port != -1)
            filter += "port " + to_string(port) + ")"; //set specified port
        else
            filter += "portrange 0-65535)";
    }
    //set filter for arp
    if (arp) {
        if (!filter.empty())
            filter += " or ";
        filter += "(arp)";
    }
    //set filter for icmp
    if (icmp) {
        if (!filter.empty())
            filter += " or ";
        filter += "(icmp or icmp6)";
    }
    this->filter = filter;
}

void formatTime(struct timeval stamp) {
    struct tm ts;
    char buf[80];
    // Format time, "ddd yyyy-mm-dd hh:mm:ss zzz"
    auto new_stamp = (const time_t *) &stamp;
    ts = *localtime(new_stamp); //get the local time
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &ts); //convert timestamp to formated time
    printf("timestamp: %s.%03ld", buf, stamp.tv_usec / 1000);
    strftime(buf, sizeof(buf), "%z", &ts);
    buf[3] = ':';
    buf[5] = '0';
    buf[6] = '\0';
    printf("%s\n", buf);
}

#define SIZE_ETHERNET 14


void printIPV4(const u_char *packet) {
    auto ip = (struct ip *) (packet + SIZE_ETHERNET);
    char srcname[100];
    strcpy(srcname, inet_ntoa(ip->ip_src)); //get source ip adress
    char dstname[100];
    strcpy(dstname, inet_ntoa(ip->ip_dst));//get destination ip adress
    printf("src IP: %s\ndst IP: %s\n", srcname, dstname);

    if (ip->ip_p == IPPROTO_ICMP) {
        return;// exit the function if protocol is icmp
    } else {//print ports
        if (ip->ip_p == IPPROTO_TCP) {
            auto port = (struct tcphdr *) (packet + SIZE_ETHERNET + ip->ip_hl * 4);
            u_short srcport = ntohs(port->th_sport);
            u_short dstport = ntohs(port->th_dport);
            printf("src port: %d\ndst port: %d\n", srcport, dstport);
        } else if(ip->ip_p == IPPROTO_UDP) {
            auto port = (struct udphdr *) (packet + SIZE_ETHERNET + ip->ip_hl * 4);
            u_short srcport = ntohs(port->uh_sport);
            u_short dstport = ntohs(port->uh_dport);
            printf("src port: %d\ndst port: %d\n", srcport, dstport);
        }
    }
}

void printIPV6(const u_char *packet) {
    auto ipv6 = (struct ip6_hdr *) (packet + SIZE_ETHERNET);
    char srcname[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6->ip6_src, srcname, INET6_ADDRSTRLEN); //get source ip adress
    char dstname[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ipv6->ip6_dst, dstname, INET6_ADDRSTRLEN); //get destination ip adress
    printf("src IP: %s\ndst IP: %s\n", srcname, dstname);

    if (ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6) {
        return; // exit the function if protocol is icmp6
    } else {//print ports
        if (ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP) {
            auto port = (struct tcphdr *) (packet + SIZE_ETHERNET + 40);
            u_short srcport = ntohs(port->th_sport);
            u_short dstport = ntohs(port->th_dport);
            printf("src port: %d\ndst port: %d\n", srcport, dstport);
        } else if(ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP) {
            auto port = (struct udphdr *) (packet + SIZE_ETHERNET + 40);
            u_short srcport = ntohs(port->uh_sport);
            u_short dstport = ntohs(port->uh_dport);
            printf("src port: %d\ndst port: %d\n", srcport, dstport);
        }
    }
}

void printData(const struct pcap_pkthdr *pkthdr, const u_char *
packet) {
    const u_char *ptr = packet;
    printf("0x0000:  ");
    int line = 0;
    for (unsigned int j = 0; j < pkthdr->len; j++) {
        if (j % 8 == 0 and j != 0)
            printf("  ");
        if (j % 16 == 0 and j != 0) {
            for (unsigned int k = j - 16; k < j; k++) {
                // print bytes in ascii value, if it is unprintable, it will print . instead
                printf("%c", (ptr[k] < 32 or ptr[k] > 127) ? 46 : ptr[k]); //46 is ascii value for .
            }
            printf("\n");
            line++;
            printf("0x%04x:  ", line * 16); //print number of line in hex format
        }
        printf("%02x ", ptr[j]);
        //calc and print spaces for last line format
        if (j == pkthdr->len - 1) {
            if (j % 16 != 0) {
                int x = (16 - (j % 16)) * 3;
                if (j % 16 >= 8)
                    x -= 2;
                for (int y = 0; y <= x; y++)
                    printf(" ");
            }
            for (unsigned int k = j - j % 16; k <= j; k++) {
                printf("%c", (ptr[k] <= 31 or ptr[k] >= 127) ? 46 : ptr[k]); //46 is ascii value for .
            }
        }
    }
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *
packet) {
    struct ether_header *eptr;
    formatTime(pkthdr->ts);

    eptr = (struct ether_header *) packet; //converts packet to ether_header struct, which extract src mac, dst mac, type of port

    int i;
    uint8_t *ptr;

    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    printf("src MAC: ");
    do {
        printf("%s%02x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
    } while (--i > 0);
    printf("\n");

    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf("dst MAC: ");
    do {
        printf("%s%02x", (i == ETHER_ADDR_LEN) ? " " : ":", *ptr++);
    } while (--i > 0);
    printf("\n");

    printf("frame length: %d bytes\n", pkthdr->len);

    //checks type of ethernet
    if (ntohs(eptr->ether_type) == ETHERTYPE_IP) {
        printIPV4(packet);
        cout << endl;
    } else if (ntohs(eptr->ether_type) == ETHERTYPE_IPV6) {
        printIPV6(packet);
        cout << endl;
    } else if (ntohs(eptr->ether_type) == ETHERTYPE_ARP) {
        cout << endl;
    } else {
        printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
        exit(1);
    }
    printData(pkthdr, packet);
    cout << endl << endl;
}

int main(int argc, char *argv[]) {
    //parsing arguments from comand line
    ArgumentParser config = ArgumentParser(argc, argv);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    struct bpf_program fp;        /* to hold compiled program */
    bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
    pcap_if_t *alldevs, *d;
    int i = 0;

    //finding available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error in pcap_findalldevs: " << errbuf << endl;
        exit(1);
    }

    //print device when interface is not specified
    if (config.print_interface) {
        for (d = alldevs; d; d = d->next) {
            printf("%d. %s\n", ++i, d->name);
        }
        exit(0);
    } else {
        bool found = false;
        for (d = alldevs; d; d = d->next) {
            if (strcmp(d->name, config.interface)) {
                found = true;
                break;
            }
        }
        if (!found) {
            cerr << "Error selected interface not found" << endl;
            exit(1);
        }
    }

    // fetch the network address and network mask
    pcap_lookupnet(config.interface, &pNet, &pMask, errbuf);


    // Now, open device for sniffing
    descr = pcap_open_live(config.interface, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL) {
        cerr << "pcap_open_live() failed due to " << errbuf << endl;
        exit(1);
    }

    // Compile the filter expression
    //config.filter.c_str()
    if (pcap_compile(descr, &fp, "ip6", 0, pNet) == -1) {
        cerr << "pcap_compile() failed" << endl;
        exit(1);
    }

    // Set the filter compiled aboveS
    if (pcap_setfilter(descr, &fp) == -1) {
        cerr << "pcap_setfilter() failed" << endl;
        exit(1);
    }

    // For every packet received, call the callback function
    // For now, maximum limit on number of packets is specified
    // by user.
    pcap_loop(descr, config.n, callback, NULL);

    return 0;
}