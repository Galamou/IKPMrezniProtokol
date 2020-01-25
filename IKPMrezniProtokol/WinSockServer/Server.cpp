#include <winsock2.h>
#include <stdio.h>

#define SERVER_PORT 15000
#define SERVER_SLEEP_TIME 100
#define ACCESS_BUFFER_SIZE 1024
#define IP_ADDRESS_LEN 16

#include "../Common/Common.hpp"


// Duzina segmenta (tj BUFFER_SIZE) treba da je 64KB (64000B) (Ali za sad koristimo manje da bi mogli da vidimo 
// sta se desava)
#define BUFFER_SIZE 11
#define SEGMENT_CONTENT_LENGTH (BUFFER_SIZE - 2*sizeof(int) - sizeof(char)) // Duzina poruke u segmentu
#define BUFFER_NUMBER 10			// Proizvoljno, za sad je 10 dovoljno (za testiranje moze i vise 100-tina)

// Struktura za prenosenje i segmenta i CRC za segment
#pragma pack(push,1)
struct Segment {
	int SegmentLength;
	char SegmentContent[SEGMENT_CONTENT_LENGTH];
	int SegmentIndex;
	char SegmentCRC;
};
#pragma pack(pop)

// Buffer za smestanje jednog segmenta. 
// Ima pokazivac na memoriju gde je smesten jedan segment poruke.
// Ima polje usingSegment koje nam kaze da li je buffer zauzet.
#pragma pack(push,1)
struct Buffer {
	struct Segment* pBuffer;		// bufferi su velicine jednog segmenta
	bool usingBuffer;				// da li je u bufferu ACKovana poruka?
};
#pragma pack(pop)


// Struktura za ACK. Mislim da ne mora da se koristi CRC za ACK.
#pragma pack(push,1)
struct ACK {
	int SegmentIndex;
	bool SegmentACK;                        // Da li je segment ACKovan
};
#pragma pack(pop)

// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();

int main(int argc, char* argv[])
{
	// Server address
	sockaddr_in serverAddress;
	// Server's socket
	int serverPort = SERVER_PORT;
	// size of sockaddr structure
	int sockAddrLen = sizeof(struct sockaddr);
	// buffer we will use to receive client message
	// ovde ce ici bufferPool

	// variable used to store function return value
	int iResult;

	if (InitializeWindowsSockets() == false)
	{
		// we won't log anything since it will be logged
		// by InitializeWindowsSockets() function
		return 1;
	}

	// Initialize serverAddress structure used by bind
	memset((char*)&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET; /*set server address protocol family*/
	serverAddress.sin_addr.s_addr = INADDR_ANY;
	serverAddress.sin_port = htons(serverPort);

	// create a socket
	SOCKET serverSocket = socket(AF_INET,      // IPv4 address famly
		SOCK_DGRAM,   // datagram socket
		IPPROTO_UDP); // UDP

// check if socket creation succeeded
	if (serverSocket == INVALID_SOCKET)
	{
		printf("Creating socket failed with error: %d\n", WSAGetLastError());
		WSACleanup();
		return 1;
	}

	// Bind port number and local address to socket
	iResult = bind(serverSocket, (LPSOCKADDR)&serverAddress, sizeof(serverAddress));

	if (iResult == SOCKET_ERROR)
	{
		printf("Socket bind failed with error: %d\n", WSAGetLastError());
		closesocket(serverSocket);
		WSACleanup();
		return 1;
	}

	printf("Simple UDP server started and waiting client messages.\n");

	// Main server loop
	while (1)
	{
		// RECEIVE ----------------------------------------------------------------
		// clientAddress will be set from recvfrom
		sockaddr_in clientAddress;
		memset(&clientAddress, 0, sizeof(sockaddr_in));

		// set whole buffer to zero
		struct Segment seg;
		memset(&seg, 0, sizeof(struct Segment));

		// MARKOV KOD
		//int flags = 0;

		//// receive client message
		//protocol_comm_data pcd;
		//pcd = recvfrom_w_crc(&serverSocket,
		//	accessBuffer,
		//	ACCESS_BUFFER_SIZE,
		//	&flags,
		//	&clientAddress,
		//	&sockAddrLen);

		//if (pcd.iResult == SOCKET_ERROR)
		//{
		//	printf("recvfrom failed with error: %d\n", WSAGetLastError());
		//	continue;
		//}

		//if (pcd.rem != 0)
		//{
		//	printf("crc check failed when recieving!\n");
		//	continue;
		//}

		//char ipAddress[IP_ADDRESS_LEN];
		//// copy client ip to local char[]
		//strcpy_s(ipAddress, sizeof(ipAddress), inet_ntoa(clientAddress.sin_addr));
		//// convert port number from TCP/IP byte order to
		//// little endian byte order
		//int clientPort = ntohs((u_short)clientAddress.sin_port);

		//printf("Client connected from ip: %s, port: %d, sent: %s.\n", ipAddress, clientPort, accessBuffer);

		////=======================================================================================================
		//// Sending an 'ACK' message back to the client.
		//pcd = sendto_w_crc(&serverSocket,
		//	ACK_MESSAGE,
		//	strlen(ACK_MESSAGE),
		//	&flags,
		//	&clientAddress,
		//	&sockAddrLen);

		//if (pcd.iResult == SOCKET_ERROR)
		//{
		//	printf("sendto ACK failed with error: %d\n", WSAGetLastError());
		//	closesocket(serverSocket);
		//	WSACleanup();
		//	return 1;
		//}

		// receive client message
		iResult = recvfrom(serverSocket,
			(char*)&seg,
			sizeof(struct Segment),
			0,
			(LPSOCKADDR)&clientAddress,
			&sockAddrLen);

		if (iResult == SOCKET_ERROR)
		{
			printf("recvfrom failed with error: %d\n", WSAGetLastError());
			continue;
		}

		// Ispis poslate poruke. (dodajemo na kraj '\0' da moze da se ispise)
		char content[SEGMENT_CONTENT_LENGTH + 1];
		memcpy(content, seg.SegmentContent, seg.SegmentLength);
		content[seg.SegmentLength] = '\0';
		printf("Received message: %s.\n", content);

		// SEND ACK ---------------------------------------------------------------
		struct ACK ack;
		memset(&ack, 0, sizeof(struct ACK));
		
		// Racunanje CRC za pristigli segment
		int remainder = crc((char*)&seg, sizeof(struct Segment));

		// Popunjavanje strukture za ACK
		ack.SegmentACK = (remainder == 0) ? 1 : 0;
		ack.SegmentIndex = seg.SegmentIndex;

		// Za sad salje ACK i kad je CRC propao cisto da se na klijentu ispise da nije uspelo. 
		// Posle ce samo odbaciti segment.
		iResult = sendto(serverSocket,
			(char*)&ack,
			sizeof(struct ACK),
			0,
			(LPSOCKADDR)&clientAddress,
			sockAddrLen);

		if (iResult == SOCKET_ERROR)
		{
			printf("sendto failed with error: %d\n", WSAGetLastError());
			closesocket(serverSocket);
			WSACleanup();
			return 1;
		}

		printf("Sent ACK = %d\n", ack.SegmentACK);

		// possible message processing logic could be placed here
	}

	// if we are here, it means that server is shutting down
	// close socket and unintialize WinSock2 library
	iResult = closesocket(serverSocket);
	if (iResult == SOCKET_ERROR)
	{
		printf("closesocket failed with error: %ld\n", WSAGetLastError());
		return 1;
	}

	iResult = WSACleanup();
	if (iResult == SOCKET_ERROR)
	{
		printf("WSACleanup failed with error: %ld\n", WSAGetLastError());
		return 1;
	}

	printf("Server successfully shut down.\n");
	return 0;
}

bool InitializeWindowsSockets()
{
	WSADATA wsaData;
	// Initialize windows sockets library for this process
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("WSAStartup failed with error: %d\n", WSAGetLastError());
		return false;
	}
	return true;
}
