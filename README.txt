1. Author
	Srija Reddy Timmayyagari

2. How to compile the code
	
		Run make command to create bridge and station executables.
		make all command will create the bridge and station executables.
		make clean command clears the executable files.

3. Commands:

   3.1. Station specific command

	   send <destination> <message> // send message to a destination host

   3.2 Commands for stations and routers:

	   show	arp 		// show the ARP cache table information
	   show	pq 		// show the pending_queue
	   show	host 		// show the IP/name mapping table
	   show	iface 		// show the interface information
	   show	rtable 		// show the contents of routing table
	   quit // close the router

   3.3 bridges:

	   show sl 		// show the contents of self-learning table
	   quit // close the bridge

4. To start the emulation, run the following commands

  To run bridges:
		./bridge cs1 8 //Runs bridge cs1 with 8 available ports.
		./bridge cs2 8 //Runs bridge cs2 with 8 available ports.
		./bridge cs3 8 //Runs bridge cs3 with 8 available ports.

	To run stations:
		./station -no ifaces/ifaces.a rtables/rtable.a hosts // Station A
		./station -no ifaces/ifaces.b rtables/rtable.b hosts // Station B
		./station -no ifaces/ifaces.c rtables/rtable.c hosts // Station C
		./station -no ifaces/ifaces.d rtables/rtable.d hosts // Station D
		./station -no ifaces/ifaces.e rtables/rtable.e hosts // Station E
	
	To run routers:
		./station -route ifaces/ifaces.r1 rtables/rtable.r1 hosts // Router R1
		./station -route ifaces/ifaces.r2 rtables/rtable.r2 hosts // Router R2

  The above commands emulates the following network topology
   
          B              C                D
          |              |                |
         cs1-----R1------cs2------R2-----cs3
          |              |                |
          -------A--------                E

    cs1, cs2, and cs3 are bridges.
    R1 and R2 are routers.
    A to E are hosts/stations.

