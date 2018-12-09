CC = g++
CFLAGS = -std=c++14 -I headers/
LIBS = -lpcap
OBJS = src/main.cpp \
 			 src/connectionHandler.cpp \
			 src/IPv6Packet.cpp \
			 src/EthFrame.cpp \
			 src/ICMPv6Packet.cpp \
			 src/TcpPacket.cpp \
			 src/HttpPacket.cpp

HEADERS = headers/connectionHandler.h \
			 		headers/IPv6Packet.h \
			 		headers/EthFrame.h \
			 		headers/ICMPv6Packet.h \
			 		headers/TcpPacket.h \
			 		headers/HttpPacket.h

stack: ${OBJS} ${HEADERS}
	${CC} ${CFLAGS} ${INCLUDES} -o $@ ${OBJS} ${LIBS}

clean:
	-rm -f *.o stack

.cpp.o:
	${CC} ${CFLAGS} ${INCLUDES} -c $<
