
//router lo ethernet packet receive cheskunnaka, ye line std::cout<<"Ethernet payload size= "<<receivedPacket->size<<"\n"; deggara segmentation fault ochesthundi
/*-------------------------------------------------------*/
/* CHAITANYA NAIDU PINDI - cp22k */
#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
//#include "ether.h"
#include "ip.h"
#include <unistd.h> // For readlink
#include <iostream>
#include <sstream>
#include <iomanip>
#include <queue>
/*----------------------------------------------------------------*/

#define BUFFER_SIZE 1024
#define ETHER_PKT_HEADER_SIZE 16 // this is only the header length
/*----------------------------------------------------------------*/
/* station : gets hooked to all the lans in its ifaces file, sends/recvs pkts */
/* usage: station <-no -route> interface routingtable hostname */

// Define a structure to pair Ethernet packet with next-hop IP
struct EthernetPacketWithNextHop {
    EtherPkt* packet;
    IPAddr nextHop;
};
//network interface data structure
struct NetworkInterface {
    std::string name;
    IPAddr ipAddress;
    IPAddr subnetMask;
    MacAddr macAddress;
    std::string bridgeName;
};

//routing table data structure
struct RouteEntry {
    IPAddr networkId;
    IPAddr nextHopIpAddress;
    IPAddr networkMask;
    std::string associatedInterface;
};

bool router = false;

std::vector<RouteEntry> routingTable; // Create a vector to store routing table entries
std::vector<Arpc> arp_cache;
std::vector<NetworkInterface> interfaces; // Create a vector to store the network interfaces
std::map<std::string, int> serv_fd; // Map to associate bridge names with serv fd
std::queue<EthernetPacketWithNextHop> ethernetPacketQueue; 	// Create a queue for Ethernet packets

void printDottedIP(IPAddr ipAddress);

void printIPPacket(IP_PKT* ipPacket) {
	
    std::cout << "Ip packet data:"<< ipPacket->dstip<< std::endl;
    std::cout << "Source IP: "<< ipPacket->srcip<< std::endl;
    std::cout << "Protocol: " << ipPacket->protocol << std::endl;
    std::cout << "Sequence Number: " << ipPacket->sequenceno << std::endl;
    std::cout << "Length: " << std::dec << ipPacket->length << std::endl;

    // Print data in hexadecimal format
	/*
    std::cout << "Data: ";
    for (int i = 0; i < ipPacket->length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ipPacket->data[i]) << " ";
    }
	*/
    std::cout << std::dec << std::endl;
}

void cleanup() {
    // Close socket connections
    for (const auto& entry : serv_fd) {
        close(entry.second);
    }
    serv_fd.clear();  // Clear the map

    // Delete dynamically allocated memory in arp_cache
    arp_cache.clear();  // Assuming Arpc is a simple structure with no dynamic memory

    // Delete dynamically allocated memory in routingTable if needed
    routingTable.clear();  // Assuming RouteEntry is a simple structure with no dynamic memory

    // Delete dynamically allocated memory in interfaces if needed
    interfaces.clear();  // Assuming NetworkInterface is a simple structure with no dynamic memory

    // Delete other dynamically allocated memory
    // Add cleanup code for other dynamically allocated resources if needed
}

// Function to print EtherPkt data
void printEtherPktData(EtherPkt* pkt) {
	std::cout << "Data in EtherPkt: \n";
    std::cout << "Destination MAC: ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pkt->dst[i]);
        if (i < 5) {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    std::cout << "Source MAC: ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(pkt->src[i]);
        if (i < 5) {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    std::cout << "Type: " << pkt->type << std::endl;
    std::cout << "Size: " << std::dec << pkt->size << std::endl;

    // Assuming 'dat' points to a valid memory location
    // Note: This assumes 'dat' contains ASCII characters; adjust if it's binary data
}

void printDottedIP(IPAddr ipAddress) {
    struct in_addr addr;
    addr.s_addr = ipAddress;
    // Using inet_ntoa to convert and print the dotted IP
    std::cout << "IP: " << inet_ntoa(addr) << std::endl;
}

// Function to encapsulate the provided code
void processRoutingTable(const std::string& message,EtherPkt* ethernetPacket, IP_PKT* ipPacket, IPAddr destinationIP ) 
{
	IPAddr nextHopIP; 
	bool foundInArpCache = false;
	// Find matching entry in the routing table
	std::cout<<"In processRoutingTable\n";
	
	for (RouteEntry entry : routingTable) {
		IPAddr destinationNetwork = destinationIP & entry.networkMask;
		std::cout<<"destinationNetwork:";
		printDottedIP(destinationNetwork);
		std::cout<<"entry.networkId:";
		printDottedIP(entry.networkId);
		if (destinationNetwork == entry.networkId) {
			// Retrieve source MAC and IP addresses from the network interfaces
			nextHopIP = entry.nextHopIpAddress;
			std::cout<<"nextHopIP";
			printDottedIP(nextHopIP);
			for (NetworkInterface iface : interfaces) {
				if (iface.name == entry.associatedInterface) {
					memcpy(ethernetPacket->src, iface.macAddress, sizeof(MacAddr));
					if(!router){
						ipPacket->srcip = iface.ipAddress;
						ipPacket->dstip = destinationIP;
						ipPacket->protocol = 6; // TCP protocol
						ipPacket->sequenceno = 12345;
						ipPacket->length = message.size();
						memcpy(ipPacket->data, message.c_str(), message.size());

						// Serialize the IP packet data
						char serializedIPPacket[sizeof(IP_PKT)]; 
						memcpy(serializedIPPacket, ipPacket, sizeof(IP_PKT));
						// Assign IP packet as data to Ethernet packet
						ethernetPacket->size = sizeof(IP_PKT);
						ethernetPacket->ipPkt = (*ipPacket);
						/*
						ethernetPacket->dat = new char[ethernetPacket->size]; // Allocate memory for the serialized data
						memcpy(ethernetPacket->dat, serializedIPPacket, ethernetPacket->size);
						*/
						printIPPacket (ipPacket);
					}
					
					std::cout<<"destination ip = ";
					printDottedIP(destinationIP);

					// Search ARP cache for next-hop IP address
					IPAddr zeroIPAddress = 0;
					std::cout<<"nextHopIP = ";
					
					printDottedIP(nextHopIP);
					if(nextHopIP == zeroIPAddress){
						std::cout<<"next hop ip is 0. Assigning dest ip\n";
						nextHopIP = destinationIP;
					}
					for (const Arpc& arpEntry : arp_cache) {
						if (arpEntry.ipaddr == nextHopIP) {
							memcpy(ethernetPacket->dst, arpEntry.macaddr, sizeof(MacAddr));
							foundInArpCache = true;
							break;
						}
					}
					std::cout << "iface.bridgeName: " << iface.bridgeName << "\n";
					std::cout << "serv_fd map contents:";
					// Iterate through the serv_fd map and print each key-value pair
					for (const auto& pair : serv_fd) {
						std::cout << "{" << pair.first << ": " << pair.second << "} ";
					}
					int bridgeSockfd = serv_fd[iface.bridgeName];
					std::cout<<"bridgeSockfd="<<bridgeSockfd<<"\n";
					if (!foundInArpCache) {
						// ARP not found
						//push current ethernet packet to queue.
						printEtherPktData(ethernetPacket);
						EthernetPacketWithNextHop queuePKT = {ethernetPacket,nextHopIP};
						ethernetPacketQueue.push(queuePKT); 
						// Construct ARP request packet
						ARP_PKT arpRequest;
						arpRequest.op = 0; // ARP request
						arpRequest.srcip = iface.ipAddress;
						memcpy(arpRequest.srcmac, ethernetPacket->src, sizeof(MacAddr));
						arpRequest.dstip = nextHopIP;
						std::cout<<"arpRequest.dstip = ";
					
						printDottedIP(arpRequest.dstip );
						memset(arpRequest.dstmac, 0xFF, sizeof(MacAddr)); 
						// Broadcast MAC address
						// Send ARP request to the bridge
						send(bridgeSockfd, &arpRequest, sizeof(ARP_PKT), 0);
						std::cout<<"sending arp request. sent " << std::dec << sizeof(ARP_PKT) <<"bytes\n";
					}
					else{
						//ARP found
						//send(bridgeSockfd, ethernetPacket, ETHER_PKT_HEADER_SIZE+(ethernetPacket->size), 0);
						send(bridgeSockfd, ethernetPacket, sizeof(EtherPkt), 0);
						std::cout<<"sending out the ethernet packet. Ethernet packet total data size = "<<std::dec<<sizeof(EtherPkt)<<"\n";
					}
					break;
				}
			}
			break;
		}
	}
	std::cout<<"exiting from processRoutingTable\n";
}


int main (int argc, char *argv[])
{
	if (argc != 5) {
        std::cerr <<"usage: station <-no -route> interface routingtable hostname\n";
        return(1);
    }
	
	//check if the command is for router
	if(strcmp(argv[1], "-route")==0){
		router = true;
	}
	
	uint32_t defaultGatewayIp;
	int anySet = 0;
  /* initialization of hosts, interface, and routing tables */
  
  //intializing hosts file
    std::ifstream hostsFile(argv[4]); // Open the hosts file

    if (!hostsFile.is_open()) {
        std::cerr << "Failed to open the hosts file." << std::endl;
        return 1;
    }
    
	std::map<std::string, IPAddr> hostIPMap; // Create a map to store host-to-IP mappings in decimal format
	
	std::string line;
	timeval select_timeout;
    while (std::getline(hostsFile, line)) { // make sure there are only tabs but not spaces in hosts file
        if (!line.empty()) {
            size_t pos = line.find('\t'); // Assuming the entries are separated by a tab character
            if (pos != std::string::npos) {
                std::string host = line.substr(0, pos);
                std::string ipAddress = line.substr(pos + 1);
				//std::cout<<ipAddress<<"\n";
                struct in_addr addr;
                if (inet_aton(ipAddress.c_str(), &addr) != 0) {
                    hostIPMap[host] = addr.s_addr;
                } else {
                    std::cerr << "Invalid IP address: " << ipAddress << std::endl;
                }
            }
        }
    }

    hostsFile.close(); // Close the file
	
	//intializing interface file
	std::ifstream interfaceFile(argv[2]); // Open the interface file
	
	if (!interfaceFile.is_open()) {
        std::cerr << "Failed to open the interface file." << std::endl;
        return 1;
    }
	
	line.clear();
	//std::string line;
    while (std::getline(interfaceFile, line)) {
        if (!line.empty()) {
            std::istringstream iss(line);
            NetworkInterface interface;
						std::string ipaddress;
						std::string subnetmask;
						std::string macaddress;
            iss >> interface.name >> ipaddress >> subnetmask >> macaddress >> interface.bridgeName;
			std::cout<<"macaddress: "<<macaddress.c_str()<<"\n";
			struct in_addr addr;
			//convert ip address from string to decimal
			inet_aton(ipaddress.c_str(), &addr);
			interface.ipAddress= addr.s_addr;
			inet_aton(subnetmask.c_str(), &addr);
			interface.subnetMask= addr.s_addr;
			// Read MAC address
			int result=std::sscanf((const char*)macaddress.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    &interface.macAddress[0], &interface.macAddress[1], &interface.macAddress[2], &interface.macAddress[3], &interface.macAddress[4], &interface.macAddress[5]);
			if (result != 6) {
				std::cerr << "Error: Failed to parse MAC address." << std::endl;
			}
			// Print the parsed MAC address
			
			// std::cout << "Parsed MAC address: ";
			// for (int i = 0; i < 6; ++i) {
			// 	std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(interface.macAddress[i]);
			// 	if (i < 5) {
			// 		std::cout << ":";
			// 	}
			// }
			std::cout << std::endl;
			std::cout<<"interface.bridgeName="<<interface.bridgeName<<"\n";
            interfaces.push_back(interface);
        }
    }
	
	// Print the stored network interfaces
	/*
    for (const NetworkInterface& iface : interfaces) {
        std::cout << "Name: " << iface.name << std::endl;
        std::cout << "IP Address: " << iface.ipAddress << std::endl;
        std::cout << "Subnet Mask: " << iface.subnetMask << std::endl;
        std::cout << "MAC Address: " << iface.macAddress << std::endl;
        std::cout << "Description: " << iface.bridgeName << std::endl;
        std::cout << "--------------------------" << std::endl;
    }
	*/
    interfaceFile.close(); // Close the file

    std::ifstream routingTableFile(argv[3]); // Open the routing table file

    if (!routingTableFile.is_open()) {
        std::cerr << "Failed to open the routing table file." << std::endl;
        return 1;
    }
	
	line.clear();
	while (std::getline(routingTableFile, line)) {
        if (!line.empty()) {
            std::istringstream iss(line);
            RouteEntry entry;

            // Read and set IP addresses
            std::string networkIdStr, nextHopIpAddressStr, networkMaskStr;
            iss >> networkIdStr >> nextHopIpAddressStr >> networkMaskStr >> entry.associatedInterface;

            struct in_addr addr;
			
						//get default gateway
						if (networkIdStr == "0.0.0.0") {
                struct in_addr addr;
                if (inet_aton(nextHopIpAddressStr.c_str(), &addr) != 0) {
                    defaultGatewayIp = addr.s_addr;
                } else {
                    std::cerr << "Invalid default gateway IP address: " << entry.nextHopIpAddress << std::endl;
                    return 1; // Exit if invalid default gateway IP
                }
            }

						//get network id
            if (inet_aton(networkIdStr.c_str(), &addr) != 0) {
                entry.networkId = addr.s_addr;
				
            } else {
                std::cerr << "Invalid network ID: " << networkIdStr << std::endl;
                return 1; // Handle the error, maybe exit the program or take appropriate action
            }
			
						//get next hop ip address
            if (inet_aton(nextHopIpAddressStr.c_str(), &addr) != 0) {
                entry.nextHopIpAddress = addr.s_addr;
            } else {
                std::cerr << "Invalid next hop IP address: " << nextHopIpAddressStr << std::endl;
                return 1; // Handle the error, maybe exit the program or take appropriate action
            }

						//get network mask
            if (inet_aton(networkMaskStr.c_str(), &addr) != 0) {
                entry.networkMask = addr.s_addr;
            } else {
                std::cerr << "Invalid network mask: " << networkMaskStr << std::endl;
                return 1; // Handle the error, maybe exit the program or take appropriate action
            }

            routingTable.push_back(entry);
        }
    }
	
    // Print the stored routing table entries
	
  //   for (const RouteEntry& entry : routingTable) {
  //       std::cout << "Network ID: ";
	// 			printDottedIP(entry.networkId);
  //       std::cout << "Next Hop IP Address: ";
	// 			printDottedIP(entry.nextHopIpAddress);
  //       std::cout << "Network Mask: " ;
	// 			printDottedIP(entry.networkMask);
  //       std::cout << "Associated Interface: " << entry.associatedInterface << std::endl;
  //       std::cout << "--------------------------" << std::endl;
  //   }
	
	// std::cout << "defaultGatewayIp: " ;
	// printDottedIP(defaultGatewayIp);
	
  routingTableFile.close(); // Close the file
	
  /* hook to the lans that the station should connected to
   * note that a station may need to be connected to multilple lans
   */
   
	int num_interfaces = interfaces.size();
	// std::cout << "number of interfaces = " << num_interfaces << "\n";
	
	fd_set readfds, masterfds;
	FD_ZERO(&masterfds);
	FD_ZERO(&readfds);
	int maxfd=-1;
	// add stdin also the read fds set. we need it to read user input from the terminal
	int stdin_fd = fileno(stdin);
	FD_SET(stdin_fd, &masterfds);
	
	if(stdin_fd>maxfd) {
		maxfd=stdin_fd;
	}
	
    for(int i=0;i<num_interfaces;i++){
		std::cout << "interfaces[i].bridgeName=" << interfaces[i].bridgeName <<std::endl;
	  //using bridgename string in interface structure, do readlink bridgename.addr and bridgename.port and do server connection to that bridges on ip addr and port number got from readlink of bridgename.addr and bridgename.port
	   
	  //note that there are already created symlink files for bridgename.addr and bridgename.port in the same folder
	  std::string bridgeAddrLink = interfaces[i].bridgeName + ".addr";
    std::string bridgePortLink = interfaces[i].bridgeName + ".port";

    char addrBuffer[256];
    char portBuffer[256];
		std::cout<<"bridgeAddrLink:"<<bridgeAddrLink<<"\n";
		std::cout<<"bridgePortLink:"<<bridgePortLink<<"\n";

    // Read symbolic links for IP address and port
		
    ssize_t addrLen = readlink(bridgeAddrLink.c_str(), addrBuffer, sizeof(addrBuffer) - 1);
    ssize_t portLen = readlink(bridgePortLink.c_str(), portBuffer, sizeof(portBuffer) - 1);
		if (addrLen <0 || portLen <0) {
			std::cerr << "Error reading symbolic links for interface " << interfaces[i].name << std::endl;
		}
		addrBuffer[addrLen] = '\0';
		portBuffer[portLen] = '\0';
		std::cout<<"serv ip:"<<addrBuffer<<"\n";
		std::cout<<"serv port:"<<portBuffer<<"\n";
		std::string ipAddressStr(addrBuffer);
		std::string portStr(portBuffer);
		
		struct in_addr addr;
		inet_aton(ipAddressStr.c_str(), &addr);
		int serv_port = atoi(portStr.c_str());
		
		struct sockaddr_in serverAddr;
		memset(&serverAddr, 0, sizeof(serverAddr));
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_addr.s_addr = addr.s_addr;
		serverAddr.sin_port = htons(serv_port);  // Convert port to network byte order
		
		// Create a socket
		int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd == -1) {
			perror("Error creating socket");
			return EXIT_FAILURE;
		}
		// std::cout<<"servip:"<<serverAddr.sin_addr.s_addr<<" port:"<<serverAddr.sin_port<<"\n";

		// Connect to the server
		std::cout<<"Trying to connect to the server\n";
		if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
			perror("Error connecting to the server");
			close(sockfd);
			return EXIT_FAILURE;
		}
		
		serv_fd[interfaces[i].bridgeName] = sockfd;
		std::cout<<"server connection sockfd ="<<sockfd<<"\n";
		FD_SET(sockfd, &masterfds);
		if(sockfd>maxfd){
			maxfd = sockfd ;
		}
		
		// Receive and print message from the server
		char buffer[BUFFER_SIZE];
		ssize_t bytesRead = recv(sockfd, buffer, sizeof(buffer) - 1, 0);

		if (bytesRead == -1) {
			perror("Error receiving message from the server");
		} else if (bytesRead == 0) {
			printf("Server closed the connection\n");
		} else {
			buffer[bytesRead] = '\0'; // Null-terminate the received data
			printf("Received message from the server: %s\n", buffer);
		}

		// Close the socket when done
		//close(sockfd);
    }
	
	// start checking for data from all the connected bridges
	select_timeout.tv_sec = 1;
  select_timeout.tv_usec = 0;
  while (true) {
		readfds = masterfds;
		// select is a blocking call. So, we should have a timeout value for how long it should wait for a connection.
		// select is a blocking call. So, we should have a timeout value for how long it should wait for a connection.
		//std::cout<<"maxfd="<<maxfd<<"\n";
		
		if (select(maxfd + 1, &readfds, nullptr, nullptr, &select_timeout) < 0) { // here timeout should be NULL. while listening for packets on clients we should have timeout.
			std::cerr << "Error with select" << std::endl;
			return 1;
		}
		
		int i;
		//monitoring input from users and bridges
	    for (i = 0; i <= maxfd; i++) {
			 // FD_ISSET checks if the specific file descriptor (Socket) is in our readfds set and ready for read
			if (FD_ISSET(i, &readfds)) {
				//from user: analyze the user input and send to the destination if necessary
				if(i==stdin_fd){
					std::string input; //user input
    
					// Get user input
					//std::cout << "Enter a command: ";
					std::getline(std::cin, input);

					if (input == "show arp") {
						// Code to display ARP cache
						for (const Arpc& arpEntry : arp_cache) {
								std::cout << "IP: ";
								printDottedIP(arpEntry.ipaddr);
								std::cout << ", MAC: ";
								for (int i = 0; i < 6; ++i) {
									std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(arpEntry.macaddr[i]);
									if (i < 5) {
											std::cout << ":";
									}
								}
								// printEtherPktData(reinterpret_cast<EtherPkt*>(&arpEntry.macaddr));
								std::cout << std::endl;
						}
					} else if (input == "show pq") {
							// Code to display packet queue
							// Add appropriate code here
							std::cout << "Pending Queue Contents:\n";
   	 					int queueSize = ethernetPacketQueue.size();
    					for (int i = 0; i < queueSize; ++i) {
							EthernetPacketWithNextHop entry = ethernetPacketQueue.front();
							ethernetPacketQueue.pop();
							std::cout << "Queue Entry " << i + 1 << ":\n";
							std::cout << "  Next Hop IP Address: ";
							printDottedIP(entry.nextHop);
							std::cout << "  Ethernet Packet Data: ";
							printEtherPktData(entry.packet);
							std::cout << "\n";
							ethernetPacketQueue.push(entry); // Restore the entry to the queue after printing
						}
					} else if (input == "show host") {
							// Code to display host information
							for (const auto& entry : hostIPMap) {
									std::cout << "Host: " << entry.first << ", IP Address: ";
									printDottedIP(entry.second);
									std::cout << std::endl;
							}
					} else if (input == "show iface") {
							// Code to display interface information
							for (const NetworkInterface& iface : interfaces) {
									std::cout << "Interface: " << iface.name << ", IP Address: ";
									printDottedIP(iface.ipAddress);
									std::cout << ", MAC Address: ";
									for (int i = 0; i < 6; ++i) {
										std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(iface.macAddress[i]);
										if (i < 5) {
												std::cout << ":";
										}
									}
									// printEtherPktData(reinterpret_cast<EtherPkt*>(&iface.macAddress));
									std::cout << ", Bridge Name: " << iface.bridgeName << std::endl;
							}
					} else if (input == "show rtable") {
							// Code to display routing table
							for (const RouteEntry& entry : routingTable) {
									std::cout << "Network ID: ";
									printDottedIP(entry.networkId);
									std::cout << ", Next Hop IP: ";
									printDottedIP(entry.nextHopIpAddress);
									std::cout << ", Network Mask: ";
									printDottedIP(entry.networkMask);
									std::cout << ", Associated Interface: " << entry.associatedInterface << std::endl;
							}
					} else if (input == "quit") {
							// Code to clean up resources and exit the program
							// Add appropriate cleanup code here
							// return 0;
							cleanup();
							exit(1);
					} 
					
					// Check if the input starts with "send"
					else if ((input.find("send") == 0) && (!router))  {
						// Extract destination and message from the input
						size_t spacePos = input.find(' ');
						if (spacePos != std::string::npos) {
							std::string destination = input.substr(spacePos + 1, input.find(' ', spacePos + 1) - spacePos - 1);
							std::string message = input.substr(input.find(' ', spacePos + 1) + 1);
							std::cout << "Destination:" <<destination<<"\n" ;
							
							// for (const auto& entry : hostIPMap) {
							// 	std::cout << "Host: " << entry.first << ", IP Address: " ; printDottedIP( entry.second);
							// }
							
							// Retrieve destination IP address from the hosts file
							IPAddr destinationIP = hostIPMap[destination];
							if(destinationIP==0){
								std::cout << "Destination ip is 0.0.0.0 which is invalid\n" ;
								// return 0;
							}
							// Create Ethernet packet
							EtherPkt* ethernetPacket = new EtherPkt;
							// Create IP packet
							IP_PKT* ipPacket = new IP_PKT;

							// do routing and ARP get 
							processRoutingTable(message,ethernetPacket, ipPacket, destinationIP); 

						} else {
							std::cout << "Invalid command format. Usage: send <destination> <message>" << std::endl;
						}
					} 
					else {
						// here you should check if they are show commands. and display appropriate messages
						std::cout << "Invalid command." << std::endl;
					}
					
				}
				else{
					//from bridge: check if it is for the station. Note two types of data in the ethernet frame: ARP packet and IP packet.
					// Assuming serv_fd is a std::map<std::string, int>
					//std::cout<<"recievied data from one of the bridges\n";
					IPAddr currentIpaddress;
					MacAddr currentMac;
					std::string currentBridgeName;
					int currentfd = -1;
					for (auto it = serv_fd.begin(); it != serv_fd.end(); ++it) {
						// 'it->first' is the key (bridgeName)
						// 'it->second' is the value (socket fd)
						
						// Check if the socket fd matches the current socket fd you are processing
						if (it->second == i) {
							// 'it->first' contains the bridgeName associated with the current socket fd
							currentBridgeName = it->first;
							currentfd = it->second;
							// Now you can use 'currentBridgeName' as needed
							// For example, you can access the corresponding NetworkInterface:
							for (NetworkInterface iface : interfaces) {
								if (iface.bridgeName == currentBridgeName) {
									// Now 'iface' is the NetworkInterface associated with the current socket fd
									// You can access 'iface.macAddress' or other attributes as needed
									memcpy(currentMac, &iface.macAddress, sizeof(MacAddr));
									currentIpaddress = iface.ipAddress;

									break;  // Assuming there is only one matching interface
								}
							}
							// Add your logic here based on the currentBridgeName or corresponding NetworkInterface
							break;  // Assuming there is only one matching socket fd
						}
					}
					
					char buffer[1024]; // Adjust the buffer size accordingly
					ssize_t bytesRead = recv(i, buffer, sizeof(buffer), 0);

					if (bytesRead == sizeof(ARP_PKT)) {
						std::cout<<"received packet is an arp packet\n";
						ARP_PKT* arpPacket = reinterpret_cast<ARP_PKT*>(buffer);

						std::cout << "received source address: ";
						for (int i = 0; i < 6; ++i) {
							std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(arpPacket->srcmac[i]);
							if (i < 5) {
								std::cout << ":";
							}
						}
						MacAddr srcArp;
						memcpy(srcArp, arpPacket->srcmac, sizeof(MacAddr));
						std::cout << "\n";
						bool foundInArpCache = false;
						for (const Arpc& arpEntry : arp_cache) {
							if (memcmp(srcArp, arpEntry.macaddr, sizeof(MacAddr)) == 0) {
								// The srcArp is found in the arp_cache
								foundInArpCache = true;
								// You can access the corresponding entry in arpEntry here if needed
								break;
							}
						}

						if (!foundInArpCache) {
							// The srcArp is not in the arp_cache, so add it
							Arpc newArpEntry;
							//memcpy(newArpEntry.ipaddr, arpPacket->srcip, sizeof(IPAddr));
							newArpEntry.ipaddr = arpPacket->srcip;
							memcpy(newArpEntry.macaddr, srcArp, sizeof(MacAddr));
							// You may want to set other fields in newArpEntry if needed
							arp_cache.push_back(newArpEntry);
						}
						if (arpPacket->op == ARP_REQUEST) {
							std::cout<<"received ARP request\n";
							
							//check if the destination ip on the packet is matching with my current interface ip. If yes, save the src ip and src mac on the packet and use them for destination IP and MAC. Update the response packet with src ip and src MAC details of the current interface. And, set arp response flag in the pkt.send this packet to the current bridge
							
							//If no, donot respond. Yes print a message saying received wrong arp request
											
							// Check if the destination IP matches the current interface IP
							if (arpPacket->dstip == currentIpaddress) {
								// Save source IP and source MAC addresses
								
								IPAddr sourceIP = arpPacket->srcip;
								MacAddr sourceMAC;
								memcpy(sourceMAC, arpPacket->srcmac, sizeof(MacAddr));

								// Update ARP response packet with source IP and source MAC
								arpPacket->dstip = sourceIP;
								memcpy(arpPacket->dstmac, sourceMAC, sizeof(MacAddr));

								arpPacket->srcip = currentIpaddress;
								memcpy(arpPacket->srcmac, currentMac, sizeof(MacAddr));
								// Set ARP response flag
								arpPacket->op = ARP_RESPONSE;

								// Send the modified ARP response packet to the current bridge
								send(i, arpPacket, sizeof(ARP_PKT), 0);
							} else {	
								// Print a message for receiving a wrong ARP request
								std::cout << "Received wrong ARP request for destination IP: ";printDottedIP(arpPacket->dstip);

							}
							

						}
						else if (arpPacket->op == ARP_RESPONSE) {
							std::cout<<"received ARP response\n";
							//now, In a loop, check for the MAC address of nexthop ip address from dequeue data in arp cache. If found, update the packet with destination MAC address and send out the ethernet packet to the current bridge and break the loop. If not found, Push the dequeuePKT to the queue.  
							while (!ethernetPacketQueue.empty()) {
								EthernetPacketWithNextHop dequeuePKT = ethernetPacketQueue.front();
								ethernetPacketQueue.pop();

								// Loop through the ARP cache to find the MAC address for the next hop IP
								bool foundInArpCache = false;
								for (const Arpc& arpEntry : arp_cache) {
									if (arpEntry.ipaddr == dequeuePKT.nextHop) {
										// MAC address found in ARP cache
										foundInArpCache = true;
										// Update the packet with the destination MAC address
										/*
										if(dequeuePKT.packet != NULL){
																						
										}
										else{
											std::cout<<"dequeuePKT.packet is NULL";
										}
										*/
										EtherPkt* pkt = dequeuePKT.packet;
										printEtherPktData(pkt);
										printIPPacket(reinterpret_cast<IP_PKT*>(&pkt->ipPkt));
										memcpy(pkt->dst, arpEntry.macaddr, sizeof(MacAddr));
										// Send out the Ethernet packet to the current bridge
										std::cout<<"current fd="<<currentfd<<"\n";
										
										send(currentfd, pkt, sizeof(EtherPkt), 0);
										// std::cout<<"test2\n";

										// Break the loop as the packet is sent
										std::cout<<"sending out the ethernet packet. Ethernet packet total data size = "<<std::dec<<sizeof(EtherPkt)<<"\n";
										break;
									}
								}

								if (!foundInArpCache) {
									// MAC address not found in ARP cache, push the packet back to the queue
									std::cout<<"Arp not found\n";
									ethernetPacketQueue.push(dequeuePKT);
								}else{
									break;
								}
							}
						}
					
					}
					else if(bytesRead == sizeof(EtherPkt)){
						
						std::cout<<"Recieved ethernet packet. Bytes received = "<< std::dec << bytesRead<<"\n";
						EtherPkt* receivedPacket = new EtherPkt;
						//reinterpret_cast<EtherPkt*>(buffer);
						memcpy(receivedPacket, buffer, sizeof(EtherPkt));
						// Allocate memory for the data and copy it
						//receivedPacket->dat = new char[receivedPacket->size];
						//memcpy(receivedPacket->dat, buffer + 16, receivedPacket->size);
						printEtherPktData(receivedPacket);
						//printEtherPktData(EtherPkt);
						//IP_PKT* ipPacket = new IP_PKT;
						std::cout<<"sizeof(IP_PKT) = "<<std::dec<<sizeof(IP_PKT)<<"\n";
						std::cout<<"receivedPacket->size = "<<std::dec<<receivedPacket->size<<"\n";
						// std::cout<<"flow 1\n";

						
						IP_PKT ipPacket = receivedPacket->ipPkt;
						
						//memcpy(ipPacket,&buffer[16],receivedPacket->size);

						// std::cout<<"flow 2\n";

						//memcpy(ipPacket,deserializedIPPacket,sizeof(IP_PKT));
						// std::cout<<"flow 3\n";

						std::cout<<"Ethernet payload size= "<<receivedPacket->size<<"\n";

						if(router){
							std::cout<<"case 1\n";
							std::string tempMsg = "Chaitu";
					
							printIPPacket(&ipPacket);
				
							processRoutingTable(tempMsg, receivedPacket, &ipPacket, ipPacket.dstip); 
						}	
						else{ 
							//in station
							// Check if the destination IP address in the IP packet matches with currentIpaddress
							// Check if the destination IP address on the received packet is matching with the currentIpaddress. If yes, extract the message in the packet and the source ip. Match the source IP from the hosts database and get the hostname. Print the received message and the source host name.
							if (ipPacket.dstip == currentIpaddress) {
								// Extract the message and source IP from the IP packet
								IPAddr sourceIP = ipPacket.srcip;
								// Assuming the message is stored in the 'data' field of the IP packet
								std::string message(ipPacket.data, ipPacket.length);

								// Match the source IP from the hosts database to get the hostname
								std::string sourceHostName;
								for (const auto& pair : hostIPMap) {
									if (pair.second == sourceIP) {
										sourceHostName = pair.first;
										break;
									}
								}

								// Print the received message and the source host name
								std::cout << "Received message from " << sourceHostName << ": " << message << std::endl;
							}
							else{
								std::cout << "Received wrong packet\n";
							}
						}
					}
					else if(bytesRead <= 0) {
						if (bytesRead == 0) {
							// Server closed the connection
							std::cout << "Server closed the connection on socket " << i << std::endl;
						}
						else {
								perror("Error receiving message from the server");
						}
						// Close the socket and remove it from the file descriptor set
						close(i);
						FD_CLR(i, &masterfds);

						// Update maxfd if needed
						if (i == maxfd) {
							while (!FD_ISSET(maxfd, &masterfds) && maxfd >= 0) {
									maxfd--;
							}
						}
						std::cout << "The maxfd now is  " << maxfd << std::endl;
						for (int j = 0; j < maxfd; ++j) {
        			if (FD_ISSET(j, &masterfds)) {
								anySet = 1;
								break;
        			}
				    }

						if(anySet != 1) {
							exit(1);
						}
						anySet = 0;
					}
				}
			}
		}
	}

	cleanup();
  return 0;
}
