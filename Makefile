all:
	gcc -pthread -fpermissive -lstdc++ -std=c++11 -o bridge bridge.cpp
	gcc -pthread -fpermissive -lstdc++ -std=c++11 -o station station.cpp

bridge: bridge.cpp
	gcc -pthread -fpermissive -lstdc++ -std=c++11 -o bridge bridge.cpp

station: station.cpp
	gcc -pthread -fpermissive -lstdc++ -std=c++11 -o station station.cpp

clean:
	rm -rf bridge station .*.addr .*.port 

