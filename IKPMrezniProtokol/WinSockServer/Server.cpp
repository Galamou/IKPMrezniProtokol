#include <winsock2.h>
#include <stdio.h>
#include <conio.h>
#include <windows.h>

#define SERVER_PORT 15000
#define SERVER_SLEEP_TIME 100
#define ACCESS_BUFFER_SIZE 1024
#define IP_ADDRESS_LEN 16

#include "../Common/Common.hpp"

// Povratna vrednost funkcije recv na serveru kad klijent zatvori svoj socket
#define CLIENT_SHUTDOWN 0

// Duzina segmenta (tj BUFFER_SIZE) treba da je 64KB (64000B) (Ali za sad koristimo manje da bi mogli da vidimo 
// sta se desava)
#define BUFFER_SIZE 11
#define SEGMENT_CONTENT_LENGTH (BUFFER_SIZE - 2*sizeof(int) - sizeof(char)) // Duzina poruke u segmentu
#define BUFFER_NUMBER 100			// Proizvoljno, za sad je 10 dovoljno (za testiranje moze i vise 100-tina)

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

// Struktura za recieve i sendack threadove
#pragma pack(push,1)
struct ThreadParameters {
	SOCKET* socket;
	Buffer* bufferPool;
};
#pragma pack(pop)

// Initializes WinSock2 library
// Returns true if succeeded, false otherwise.
bool InitializeWindowsSockets();
DWORD WINAPI Recieve(LPVOID lpParam);
DWORD WINAPI SendAck(LPVOID lpParam);

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

	// Testiranje velicine segmenta
	Segment segmentic;
	/*
	printf("%d\n", sizeof(struct Segment));
	printf("%d\n", sizeof(segmentic.SegmentIndex));
	printf("%d\n", sizeof(segmentic.SegmentLength));
	printf("%d\n", sizeof(segmentic.SegmentCRC));
	printf("%d\n", sizeof(segmentic.SegmentContent));
	*/

	int sizeofSeg = sizeof(segmentic.SegmentIndex) + sizeof(segmentic.SegmentLength) 
				  + sizeof(segmentic.SegmentCRC) + sizeof(segmentic.SegmentContent);

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

	// Alociranje memorije za buffer.
	// Postavlja vrednost polja usingBuffer svakog buffera u bufferPoolu na false.
	struct Buffer bufferPool[BUFFER_NUMBER];
	for (int i = 0; i < BUFFER_NUMBER; i++)
	{
		bufferPool[i].usingBuffer = false;
		bufferPool[i].pBuffer = (struct Segment*)malloc(sizeof(struct Segment));
		memset(bufferPool[i].pBuffer, 0, sizeof(struct Segment));
		if (!bufferPool[i].pBuffer)
		{
			printf("ERROR: Failed to allocate memory for buffer pool.");
			exit(-1);
		}
	}

	printf("Simple UDP server started and waiting client messages.\n");

	// Main server loop
	int test = 0; // svaki 2. segment 'nece' dobro proci (radi testiranja ACKa)
	int totalNumberOfSegments = -1, numberOfSegmentsRecieved = 0;
	while (1)
	{
		// RECEIVE ----------------------------------------------------------------
		// clientAddress will be set from recvfrom
		sockaddr_in clientAddress;
		memset(&clientAddress, 0, sizeof(sockaddr_in));

		if (totalNumberOfSegments == -1)
		{
			// receive client message
			iResult = recvfrom(serverSocket,
				(char*)&totalNumberOfSegments,
				sizeof(int),
				0,
				(LPSOCKADDR)&clientAddress,
				&sockAddrLen);

			if (iResult == SOCKET_ERROR)
			{
				printf("recvfrom failed with error: %d\n", WSAGetLastError());
				continue;
			}

			printf("Message arriving: Expecting %d segments!\n", totalNumberOfSegments);
		}
		else
		{
			// set whole buffer to zero
			struct Buffer* buf;
			// memset(&seg, 0, sizeof(struct Segment));

			bool bufferFilled = true;
			for (int i = 0; i < BUFFER_NUMBER; ++i)
			{
				if (!bufferPool[i].usingBuffer)
				{
					bufferFilled = false;
					buf = &bufferPool[i];
					break;
				}
			}

			if (bufferFilled || totalNumberOfSegments == numberOfSegmentsRecieved)
			{
				printf("Message recieved:\n");

				// Ispisi poruku
				for (int i = 0; i < BUFFER_NUMBER && i < totalNumberOfSegments; ++i)
				{
					// Ispis poslate poruke. (dodajemo na kraj '\0' da moze da se ispise)
					char content[SEGMENT_CONTENT_LENGTH + 1];
					memcpy(content, bufferPool[i].pBuffer->SegmentContent, bufferPool[i].pBuffer->SegmentLength);
					content[bufferPool[i].pBuffer->SegmentLength] = '\0';
					printf("%s", content);
				}

				printf("\n\n");

				// Oslobodi bufferPool
				for (int i = 0; i < BUFFER_NUMBER && i < totalNumberOfSegments; ++i)
				{
					bufferPool[i].usingBuffer = false;
					memset(bufferPool[i].pBuffer, 0, sizeof(struct Segment));
				}

				totalNumberOfSegments = -1;
				numberOfSegmentsRecieved = 0;
				continue;
			}

			// receive client message
			iResult = recvfrom(serverSocket,
				(char*)buf->pBuffer,
				sizeof(struct Segment),
				0,
				(LPSOCKADDR)&clientAddress,
				&sockAddrLen);

			if (iResult == SOCKET_ERROR)
			{
				printf("recvfrom failed with error: %d\n", WSAGetLastError());
				continue;
			}
			else if (iResult == CLIENT_SHUTDOWN)
			{
				printf("Client socket shut down.\n");
				break;
			}

			// SEND ACK ---------------------------------------------------------------
			struct ACK ack;
			memset(&ack, 0, sizeof(struct ACK));

			// Racunanje CRC za pristigli segment
			int remainder = crc((char*)buf->pBuffer, sizeofSeg);

			// Popunjavanje strukture za ACK
			ack.SegmentACK = (remainder + test == 0) ? 1 : 0;
			ack.SegmentIndex = buf->pBuffer->SegmentIndex;

			if (test > 1) test = 0;

			if (ack.SegmentACK == 1)
			{
				buf->usingBuffer = true;
				++numberOfSegmentsRecieved;
			}

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
		}
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

	printf("Press Enter to close application...");
	_getch();

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

// Thread recieve message function (acceptSocket, bufferPool)
/*
\	recvfrom -> buffer
/   if_okay -> usingBuffer = true
\	else -> usingBuffer = false
*/
DWORD WINAPI Recieve(LPVOID lpParam)
{
	// size of sockaddr structure
	int sockAddrLen = sizeof(struct sockaddr);

	Segment segmentic;
	/*
	printf("%d\n", sizeof(struct Segment));
	printf("%d\n", sizeof(segmentic.SegmentIndex));
	printf("%d\n", sizeof(segmentic.SegmentLength));
	printf("%d\n", sizeof(segmentic.SegmentCRC));
	printf("%d\n", sizeof(segmentic.SegmentContent));
	*/

	int sizeofSeg = sizeof(segmentic.SegmentIndex) + sizeof(segmentic.SegmentLength)
				  + sizeof(segmentic.SegmentCRC)   + sizeof(segmentic.SegmentContent);

	ThreadParameters tp = *(ThreadParameters*)lpParam;

	// Main recieve loop
	int iResult = -1;
	while (1)
	{
		// clientAddress will be populated from recvfrom
		sockaddr_in clientAddress;
		memset(&clientAddress, 0, sizeof(sockaddr_in));

		// set whole buffer to zero
		// memset(accessBuffer, 0, ACCESS_BUFFER_SIZE);

		// Initialize select parameters
		FD_SET set;
		timeval timeVal;

		FD_ZERO(&set);
		// Add socket we will wait to read from
		FD_SET(*tp.socket, &set);

		// Set timeouts to zero since we want select to return
		// instantaneously
		timeVal.tv_sec = 0;
		timeVal.tv_usec = 0;

		iResult = select(0 /* ignored */, &set, NULL, NULL, &timeVal);

		// lets check if there was an error during select
		if (iResult == SOCKET_ERROR)
		{
			fprintf(stderr, "select failed with error: %ld\n", WSAGetLastError());
			continue;
		}

		// now, lets check if there are any sockets ready
		if (iResult == 0)
		{
			// there are no ready sockets, sleep for a while and check again
			Sleep(SERVER_SLEEP_TIME);
			continue;
		}

		// set whole buffer to zero
		struct Buffer* buf;

		for (int i = 0; i < BUFFER_NUMBER; ++i)
		{
			if (!tp.bufferPool[i].usingBuffer)
			{
				buf = &tp.bufferPool[i];
				break;
			}
		}

		iResult = recvfrom(*tp.socket,
			(char*)buf->pBuffer,
			ACCESS_BUFFER_SIZE,
			0,
			(LPSOCKADDR)&clientAddress,
			&sockAddrLen);

		if (iResult == SOCKET_ERROR)
		{
			printf("recvfrom failed with error: %d\n", WSAGetLastError());
			continue;
		}

		// Racunanje CRC za pristigli segment
		int remainder = crc((char*)buf->pBuffer, sizeofSeg);
		if (remainder == 0)
		{
			buf->usingBuffer = true;
		}
	}
}

// Thread send message (ACK) function (sendSocket, bufferPool)
/*
\   
/
\
*/
DWORD WINAPI SendAck(LPVOID lpParam)
{
	// size of sockaddr structure
	int sockAddrLen = sizeof(struct sockaddr);

	Segment segmentic;
	/*
	printf("%d\n", sizeof(struct Segment));
	printf("%d\n", sizeof(segmentic.SegmentIndex));
	printf("%d\n", sizeof(segmentic.SegmentLength));
	printf("%d\n", sizeof(segmentic.SegmentCRC));
	printf("%d\n", sizeof(segmentic.SegmentContent));
	*/

	int sizeofSeg = sizeof(segmentic.SegmentIndex) + sizeof(segmentic.SegmentLength)
				  + sizeof(segmentic.SegmentCRC) + sizeof(segmentic.SegmentContent);

	ThreadParameters tp = *(ThreadParameters*)lpParam;

	// Main recieve loop
	int iResult = -1;
	while (1)
	{
		// clientAddress will be populated from recvfrom
		sockaddr_in clientAddress;
		memset(&clientAddress, 0, sizeof(sockaddr_in));

		// set whole buffer to zero
		// memset(accessBuffer, 0, ACCESS_BUFFER_SIZE);

		// Initialize select parameters
		FD_SET set;
		timeval timeVal;

		FD_ZERO(&set);
		// Add socket we will wait to read from
		FD_SET(*tp.socket, &set);

		// Set timeouts to zero since we want select to return
		// instantaneously
		timeVal.tv_sec = 0;
		timeVal.tv_usec = 0;

		iResult = select(0 /* ignored */, NULL, &set, NULL, &timeVal);

		// lets check if there was an error during select
		if (iResult == SOCKET_ERROR)
		{
			fprintf(stderr, "select failed with error: %ld\n", WSAGetLastError());
			continue;
		}

		// now, lets check if there are any sockets ready
		if (iResult == 0)
		{
			// there are no ready sockets, sleep for a while and check again
			Sleep(SERVER_SLEEP_TIME);
			continue;
		}

		// SEND ACK ---------------------------------------------------------------
		struct ACK ack;
		memset(&ack, 0, sizeof(struct ACK));

		int lastSegmentArrivedIndex = -1;
		for (int i = 0; i < BUFFER_NUMBER; ++i) 
		{
			if (tp.bufferPool[i].usingBuffer)
			{
				lastSegmentArrivedIndex = tp.bufferPool[i].pBuffer->SegmentIndex;
				tp.bufferPool[i].usingBuffer = false;
				break;
			}
		}

		// Popunjavanje strukture za ACK
		ack.SegmentACK = 1;
		ack.SegmentIndex = lastSegmentArrivedIndex;

		// Za sad salje ACK i kad je CRC propao cisto da se na klijentu ispise da nije uspelo. 
		// Posle ce samo odbaciti segment.
		iResult = sendto(*tp.socket,
			(char*)&ack,
			sizeof(struct ACK),
			0,
			(LPSOCKADDR)&clientAddress,
			sockAddrLen);

		if (iResult == SOCKET_ERROR)
		{
			printf("sendto failed with error: %d\n", WSAGetLastError());
			closesocket(*tp.socket);
			WSACleanup();
			return 1;
		}

		printf("Sent ACK = %d\n", ack.SegmentACK);
	}
}