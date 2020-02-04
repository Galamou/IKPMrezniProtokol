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
DWORD WINAPI AckTimer(LPVOID param);

// Global
// clientAddress will be populated from recvfrom
sockaddr_in clientAddress;
// If an ACK should be sent
bool shouldSendAck = false;
HANDLE hAckSemaphore;

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

	memset(&clientAddress, 0, sizeof(sockaddr_in));

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

	printf("Simple UDP server started and waiting client messages.\nPress enter to exit...");

	// Main server loop
	DWORD recieveID, sendID;
	HANDLE hRecieve, hSend;

	ThreadParameters tp;

	tp.bufferPool = bufferPool;
	tp.socket = &serverSocket;

	hRecieve = CreateThread(NULL, 0, &Recieve, &tp, 0, &recieveID);
	hSend = CreateThread(NULL, 0, &SendAck, &tp, 0, &sendID);

	while (1)
	{
		int liI = getchar();
		
		if (liI == 10 || liI == 13) break;
	}

	CloseHandle(hRecieve);
	CloseHandle(hSend);

	// DEALLOCATE MEMORY FOR BUFFER POOL
	for (int i = 0; i < BUFFER_NUMBER; i++)
	{
		free(bufferPool[i].pBuffer);
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

	DWORD ackTimerID;
	HANDLE hAckTimer;

	hAckSemaphore = CreateSemaphore(0, 0, 1, NULL);                 
	hAckTimer = CreateThread(NULL, 0, &AckTimer, NULL, 0, &ackTimerID);

	// Main recieve loop
	int iResult = -1;
	while (1)
	{
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
			CloseHandle(hAckTimer);
			CloseHandle(hAckSemaphore);
			return SOCKET_ERROR;
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

		ReleaseSemaphore(hAckSemaphore, 1, 0);
	}

	CloseHandle(hAckTimer);
	CloseHandle(hAckSemaphore);

	return 0;
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
		if (shouldSendAck)
		{
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
				return SOCKET_ERROR;
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
					// Ispis poslate poruke. (dodajemo na kraj '\0' da moze da se ispise)
					char content[SEGMENT_CONTENT_LENGTH + 1];
					memcpy(content, tp.bufferPool[i].pBuffer->SegmentContent, tp.bufferPool[i].pBuffer->SegmentLength);
					content[tp.bufferPool[i].pBuffer->SegmentLength] = '\0';
					printf("\nMessage: %s", content);

					lastSegmentArrivedIndex = tp.bufferPool[i].pBuffer->SegmentIndex;
					tp.bufferPool[i].usingBuffer = false;
					break;
				}
			}

			if (lastSegmentArrivedIndex != -1)
			{
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

				printf("\nSent ACK = %d", ack.SegmentACK);
			}
		}
		else
		{
			Sleep(SERVER_SLEEP_TIME);
			continue;
		}
	}

	return 0;
}

DWORD WINAPI AckTimer(LPVOID param) 
{
	DWORD result;         
	while (1) 
	{                
		result = WaitForSingleObject(hAckSemaphore, 1000);
		switch (result)
		{
		case WAIT_OBJECT_0:
			shouldSendAck = false;
			break;
		case WAIT_TIMEOUT:
			shouldSendAck = true;
		}
		Sleep(SERVER_SLEEP_TIME);
	}
	return 0;
}