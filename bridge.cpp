/* CHAITANYA NAIDU PINDI - cp22k */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <cstring>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <net/if.h>
// #include "ether.h"
#include "ip.h"
#include <iostream>
#include <iomanip>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <chrono>
#include <ctime>
#include <thread>
#include <csignal>

struct SL_entry {
    MacAddr macentry;
    int client_Fd;
    std::chrono::time_point<std::chrono::system_clock> lastUpdate;
};

std::map<std::string, SL_entry> selfLearnTable;

char addr_file[100];
char port_file[100];
int bridgeSocket;

// Function to convert MacAddr to string
std::string macToString(const MacAddr& mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        oss << std::setw(2) << static_cast<int>(mac[i]);
        if (i < 5) {
            oss << ":";
        }
    }
    return oss.str();
}

void updateSelfLearnTable(const MacAddr& srcMac, int clientFd) {
    // Convert the MAC address to a string for map lookup
    std::string srcMacString = macToString(srcMac);
    //std::cout << "Received source MAC in string format: " << srcMacString << "\n";

    auto it = selfLearnTable.find(srcMacString);

    if (it == selfLearnTable.end()) {
        // If not found, add it to the self-learning table
        std::cout << "Source MAC not found. Adding it to the SL table\n";
        SL_entry entry;
        memcpy(entry.macentry, srcMac, sizeof(MacAddr));
        entry.client_Fd = clientFd;
        entry.lastUpdate = std::chrono::system_clock::now();
        selfLearnTable[srcMacString] = entry;
    }
}

void removeInactiveEntries() {
    auto currentTime = std::chrono::system_clock::now();

    for (auto it = selfLearnTable.begin(); it != selfLearnTable.end();) {
        auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - it->second.lastUpdate).count();

        if (elapsedTime >= 60) {
            std::cout << "Removing inactive entry from the SL table\n";
            it = selfLearnTable.erase(it);
        } else {
            ++it;
        }
    }
}

// Function to search for the destination MAC address in the routing table
int searchDestinationMac(const MacAddr& destinationMac) {

    // Search for the destination IP in the routing table
	std::string dstMacString = macToString(destinationMac);
    auto it = selfLearnTable.find(dstMacString);

    // Check if the destination IP is found in the routing table
    if (it != selfLearnTable.end()) {
        // Destination IP found, return the corresponding next hop MAC address
        return (it->second).client_Fd;
    } else {
        // Destination mac not found in sl table.
		return -1;
    }
}

// Function to send a packet to all connected clients except the specified client fd
void sendPacketToAllExcept(int senderFd, int* ports, int maxPorts, const char* buffer, size_t bufferSize) {
    for (int j = 0; j < maxPorts; j++) {
        if (ports[j] != senderFd) {
            send(ports[j], buffer, bufferSize, 0);
        }
    }
}

void handleTerminationSignal(int signum) {

    // Close the bridge socket
    close(bridgeSocket);

    // Unlink symbolic links
    unlink(addr_file);
    unlink(port_file);

    std::cout << "Closing the server.\n";
    exit(0);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: bridge lan-name num-ports" << std::endl;
        return 1;
    }

	// Self-learning table to store MAC addresses and associated client sockets

    char* lanName = argv[1]; // Bridge name
	std::string jtmp = argv[2]; // ports
    int maxPorts = stoi(jtmp);
    int curNumPorts = 0; // number of client connections in use
    int newSocket;
    struct sockaddr_in serverAddr;
    struct sockaddr_storage clientAddr;
    socklen_t addrSize;
    char buffer[1024];
    char portnum[10];
    socklen_t sock_len;
    char lanFile[64];
    char read_link_res[1024];
    fd_set readfds, masterfds;
    timeval select_timeout;
    int i;

    // check if a bridge with the same name exists
    int linkvar = readlink(lanFile, read_link_res, sizeof(read_link_res) - 1);

    if (linkvar != -1) {
        std::cerr << lanName << " already exists!" << std::endl;
        return 1;
    }

    // Initialize port information
    int ports[maxPorts];
    for (i = 0; i < maxPorts; i++) {
        ports[i] = -1;
    }

    // Create a socket for the bridge
    bridgeSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (bridgeSocket == -1) {
        perror("Error creating socket");
        return 1;
    }

    // Set up the server address structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(0);  // Use port 0 to let the OS choose a free port
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); //Takes localhost IP address
	//serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the server address
    if (bind(bridgeSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Error binding socket");
        close(bridgeSocket);
        exit(1);
    }
	
	// Listen for incoming connections
    if (listen(bridgeSocket, maxPorts) == -1) {
        perror("Error listening for connections");
        close(bridgeSocket);
        exit(1);
    }
	
    FD_ZERO(&masterfds);
    FD_SET(bridgeSocket, &masterfds);
    // Here in the future add stdin also to get show commands from the terminal

    int maxfd = bridgeSocket;

    // Get the assigned port number
    addrSize = sizeof(serverAddr);
    getsockname(bridgeSocket, (struct sockaddr*) &serverAddr, &addrSize);
	// std::cout<<"servip:"<<serverAddr.sin_addr.s_addr<<" port:"<<serverAddr.sin_port<<"\n";
    int port = ntohs(serverAddr.sin_port);

	std::cout<<"Running bridge on IP:"<< inet_ntoa(serverAddr.sin_addr) <<" port: "<<port<<"\n";
    // Create symbolic links to store IP address and port number

    sprintf(addr_file, "%s.addr", lanName);
    symlink(inet_ntoa(serverAddr.sin_addr), addr_file);

    // Create a symbolic link for the port number
    sprintf(port_file, "%s.port", lanName);
    sprintf(portnum, "%d", port);
    symlink(portnum, port_file);

    signal(SIGINT, handleTerminationSignal);
    signal(SIGTERM, handleTerminationSignal);

    select_timeout.tv_sec = 1;
    select_timeout.tv_usec = 0;

    while (true) {
        readfds = masterfds;
        FD_SET(STDIN_FILENO, &readfds);
        // select is a blocking call. So, we should have a timeout value for how long it should wait for a connection.
		
        if (select(maxfd + 1, &readfds, nullptr, nullptr, nullptr) < 0) { // here timeout should be NULL. while listening for packets on clients we should have timeout.
            std::cerr << "Error with select" << std::endl;
            return 1;
        }
		
        for (i = 0; i <= maxfd; i++) {
            // FD_ISSET checks if the specific file descriptor (Socket) is in our readfds set and ready for read
            if (FD_ISSET(i, &readfds)) {
				//std::cout<<"in if\n"; 
                // check if there are any new incoming client connection requests
                if (i == bridgeSocket) {
                    sock_len = sizeof(clientAddr);
					std::cout<<"waiting for incoming connection\n";
                    int clientfd = accept(bridgeSocket, (struct sockaddr*) &clientAddr, &sock_len);
                    if (clientfd < 0) {
                        perror("accept");
                        return 1;
                    } else if (curNumPorts == maxPorts) {
                        std::cout << "All ports are occupied!! No free ports are available." << std::endl;
                        write(clientfd, "reject", 7);
                        close(clientfd);
                    } else {
                        int j;
                        for (j = 0; j < maxPorts; j++) {
                            if (ports[j] == -1) {
                                ports[j] = clientfd;
                                break;
                            }
                        }
                        curNumPorts = curNumPorts + 1; // update the current number of ports
                        std::cout << "Accepted new client connection on socket fd " << clientfd << std::endl;
                        write(clientfd, "Accept", 7);
                        FD_SET(clientfd, &masterfds); // Adding the client to the master set
                        if (maxfd < clientfd) {
                            maxfd = clientfd;
                        }
                    }
                } 
                else if (i == STDIN_FILENO) {
                    // Handle user input from stdin
                    std::string userInput;
                    std::getline(std::cin, userInput);

                    if (userInput == "show sl") {
                        // Print the self-learning table
                        std::cout << "Self-Learning Table:\n";
                        for (const auto& entry : selfLearnTable) {
                            std::cout << "MAC: " << entry.first << "  Client FD: " << entry.second.client_Fd << "\n";
                        }
                    }
                    else if (userInput == "quit") {
                        // Close all connected ports and exit the program
                        for (int j = 0; j < maxPorts; j++) {
                            if (ports[j] != -1) {
                                close(ports[j]);
                                FD_CLR(ports[j], &masterfds);
                            }
                        }
                        close(bridgeSocket);
                        unlink(addr_file);
                        unlink(port_file);
                        std::cout << "Server closed. Exiting program.\n";
                        return 0;
                    }
                    else {
                        std::cout << "Unknown command\n";
                    }
                } 
                else {
                    // The rest of the sockets are already connected client fds. If these sockets are ready for read, that means this is a packet
					// Receive data from the bridge
					char buffer[2048]; // Adjust the buffer size accordingly
					ssize_t bytesRead = recv(i, buffer, sizeof(buffer), 0);
					
					//std::cout<<"bytes recieved="<<bytesRead<<"sizeof(ARP_PKT) ="<<sizeof(ARP_PKT)<<"\n";
					if (bytesRead == sizeof(ARP_PKT)) {
						std::cout<<"received packet is an arp packet\n";
						ARP_PKT* arpPacket = reinterpret_cast<ARP_PKT*>(buffer);
									
						// Print the received source MAC address
						std::cout << "received source address: ";
						for (int i = 0; i < 6; ++i) {
							std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(arpPacket->srcmac[i]);
							if (i < 5) {
								std::cout << ":";
							}
						}
						
						std::cout << "\n";
						
						// Check if the source MAC address is in the self-learning table and update it
						updateSelfLearnTable(arpPacket->srcmac, i);
                        removeInactiveEntries();
											
						if (arpPacket->op == ARP_REQUEST) {
							std::cout<<"received ARP request\n";
							
							// Handle ARP request
							// Send the packet to all connected clients except the one where the ARP request is received
							// Call the function to send the packet to all connected clients except the sender
							//cout<<"sending arp request to all the connected ports\n";
							sendPacketToAllExcept(i, ports, maxPorts, buffer, bytesRead);
						} 
						else if (arpPacket->op == ARP_RESPONSE) {
							//
							//check destination MAC and get the client fd.
							std::cout<<"received ARP response\n";

							int destFd = searchDestinationMac(arpPacket->dstmac);
							if(destFd!=-1){
								std::cout<<"sending arp response to destined port\n";
								send(destFd, buffer, bytesRead, 0);
							}
							else{
								std::cout<<"did not find dest mac in routing table\n";
							}
						}
						else{
							std::cout<<"Not able to identify ARP type\n";
						}
					}
					else if(bytesRead > 0){
						std::cout<<"recieved Ethernet Pkt\n";
						std::cout<<"bytes recieved="<<std::dec << bytesRead<<"\n";

						EtherPkt* receivedPacket = reinterpret_cast<EtherPkt*>(buffer);
						updateSelfLearnTable(receivedPacket->src, i);
                        removeInactiveEntries();
						//now check if the destination mac address is found in self learning table. If yes,send the packet to that specific client fd. Else, send the packet to all the clients.
						int destFd = searchDestinationMac(receivedPacket->dst);
						//std::cout<<"destFd="<<destFd<<"\n";
						if(destFd!=-1){
							send(destFd, buffer, bytesRead, 0);
						}
						else{
							// Call the function to send the packet to all connected clients except the sender
							sendPacketToAllExcept(i, ports, maxPorts, buffer, bytesRead);
						}
					}
                }
            }
            // removeInactiveEntries();
        }
        static auto lastCleanupTime = std::chrono::steady_clock::now();
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(currentTime - lastCleanupTime).count();

        if (elapsedTime >= 5) {  // Adjust the interval as needed
            removeInactiveEntries();
            lastCleanupTime = currentTime;
        }

        std::this_thread::sleep_for(std::chrono::seconds(5)); 
        // removeInactiveEntries();
    }

    return 0;
}


