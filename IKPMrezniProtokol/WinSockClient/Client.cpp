#include <winsock2.h>
#include <stdio.h>
#include <conio.h>

#define SERVER_PORT 15000
#define OUTGOING_BUFFER_SIZE 1024
#define IP_ADDRESS_LEN 16

#include "../Common/Common.hpp"


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


bool InitializeWindowsSockets();

// Deli pocetnu poruku na segmente i smesta segmente u bufferPool.
int CreateSegments(char[], struct Buffer[BUFFER_NUMBER]);

// for demonstration purposes we will hard code
// local host ip address
#define SERVER_IP_ADDERESS "127.0.0.1"

// UDP client that uses blocking sockets
int main(int argc, char* argv[])
{
	// Server address
	sockaddr_in serverAddress;
	// size of sockaddr structure
	int sockAddrLen = sizeof(struct sockaddr);
	// server port we will send data to
	int serverPort = SERVER_PORT;
	// variable used to store function return value
	int iResult;

	// Initialize windows sockets for this process
	InitializeWindowsSockets();

	// Initialize serverAddress structure
	memset((char*)&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP_ADDERESS);
	serverAddress.sin_port = htons((u_short)serverPort);

	// create a socket
	SOCKET clientSocket = socket(AF_INET,      // IPv4 address famly
		SOCK_DGRAM,   // datagram socket
		IPPROTO_UDP); // UDP

// check if socket creation succeeded
	if (clientSocket == INVALID_SOCKET)
	{
		printf("Creating socket failed with error: %d\n", WSAGetLastError());
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

	printf("Press enter to start...\n");
	_getch();

	// Trenutno se salje jedna te ista poruka.
	while (1)
	{
		// CREATE MESSAGE ---------------------------------------------------------
		char* message = "01234567891011121314151617181920212223";		// za sad kratka poruka da bi mogli da testiramo da li sve radi

		// DIVIDE MESSAGE ---------------------------------------------------------
		
		// Deli pocetnu poruku na segmente i smesta ih u bufferPool.
		// Postavlja tim segmentima u bufferPoolu vrednost SegmentContent i SegmentLength. 
		// Postavlja vrednost polja usingBuffer buffera iz bufferPoola na true za one buffere u koje je smestio segmente.
		// Ne moraju svi bufferi iz bufferPoola biti zauzeti (ako je poruka kraca).
		int numberOfSegments = CreateSegments(message, bufferPool);

		// TODO: Poslati broj segmenata serveru pre samih segmenata.
		iResult = sendto(clientSocket,
			(char*)&numberOfSegments,
			sizeof(int),
			0,
			(LPSOCKADDR)&serverAddress,
			sockAddrLen);

		if (iResult == SOCKET_ERROR)
		{
			printf("sendto failed with error: %d\n", WSAGetLastError());
			closesocket(clientSocket);
			WSACleanup();
			return 1;
		}

		bool repeatSend;
		do
		{
			repeatSend = false;

			// SEND -------------------------------------------------------------------
			// Salju se svi segmenti jedne poruke jedan po jedan.
			for (int i = 0; i < BUFFER_NUMBER; i++)
			{
				if (bufferPool[i].usingBuffer)
				{
					// Ako je usingBuffer false, to znaci da se taj buffer ne koristi.
					// Ako je true, znaci da se u tom bufferu nalazi jedan segment poruke i njega zelimo da posaljemo.

					// Postavlja se vrednost SegmentIndex segmentu koji se trenutno salje.
					bufferPool[i].pBuffer->SegmentIndex = i;

					// Postavlja se vrednost SegmentCRC uz pomoc tvoje metode. 
					// Prosledi mu se Segment bez polja SegmentCRC, a izracunati CRC se onda stavi u polje SegmentCRC.
					int remainder = crc((char*)bufferPool[i].pBuffer, sizeof(struct Segment) - sizeof(char));
					bufferPool[i].pBuffer->SegmentCRC = remainder;

					// Slanje jednog segmenta iz bufferPoola.
					iResult = sendto(clientSocket,
						(char*)(bufferPool[i].pBuffer),
						sizeof(struct Segment),
						0,
						(LPSOCKADDR)&serverAddress,
						sockAddrLen);

					if (iResult == SOCKET_ERROR)
					{
						printf("sendto failed with error: %d\n", WSAGetLastError());
						closesocket(clientSocket);
						WSACleanup();
						return 1;
					}

					// Ispis poslate poruke. (dodajemo na kraj '\0' da moze da se ispise)
					char content[SEGMENT_CONTENT_LENGTH + 1];
					memcpy(content, bufferPool[i].pBuffer->SegmentContent, bufferPool[i].pBuffer->SegmentLength);
					content[bufferPool[i].pBuffer->SegmentLength] = '\0';
					printf("Sent message: %s\n", content);

					// RECEIVE ----------------------------------------------------------------
					struct ACK ack;
					memset(&ack, 0, sizeof(struct ACK));
					// receive server message
					iResult = recvfrom(clientSocket,
						(char*)&ack,
						sizeof(struct ACK),
						0,
						(LPSOCKADDR)&serverAddress,
						&sockAddrLen);

					if (iResult == SOCKET_ERROR)
					{
						printf("recvfrom failed with error: %d\n", WSAGetLastError());
						continue;
					}

					printf("Received ACK = %d\n", ack.SegmentACK);

					if (ack.SegmentACK == 1)
					{
						// Poruka je ACKovana, i buffer moze da se oslobodi
						bufferPool[i].usingBuffer = false;
						memset(bufferPool[i].pBuffer, 0, sizeof(struct Segment));
					}
				}
			}

			for (int i = 0; i < BUFFER_NUMBER; ++i)
			{
				if (bufferPool[i].usingBuffer)
				{
					repeatSend = true;
					break;
				}
			}
		} 
		while (repeatSend);

		// END --------------------------------------------------------------------
		printf("Message sent to server, press Enter to continue, press Q key to exit.\n");
		char exitKey = _getch();
		if (exitKey == 'q' || exitKey == 'Q')
			break;
	}

	// DEALLOCATE MEMORY FOR BUFFER POOL
	for (int i = 0; i < BUFFER_NUMBER; i++)
	{
		free(bufferPool[i].pBuffer);
	}

	iResult = closesocket(clientSocket);
	if (iResult == SOCKET_ERROR)
	{
		printf("closesocket failed with error: %d\n", WSAGetLastError());
		return 1;
	}

	iResult = WSACleanup();
	if (iResult == SOCKET_ERROR)
	{
		printf("closesocket failed with error: %ld\n", WSAGetLastError());
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

int CreateSegments(char message[], struct Buffer bufferPool[BUFFER_NUMBER])
{
	int messageLength = strlen(message);

	int numberOfBuffers = messageLength / SEGMENT_CONTENT_LENGTH;

	// da li je poruka deljiva sa brojem buffera
	int lengthOfLastSegment = messageLength - (numberOfBuffers*SEGMENT_CONTENT_LENGTH);
	if (lengthOfLastSegment != 0)
	{
		numberOfBuffers++;
	}

	int i, j;
	for (i = 0, j = 0; j < numberOfBuffers - 1; i += SEGMENT_CONTENT_LENGTH, j++)
	{
		memcpy(bufferPool[j].pBuffer->SegmentContent, message + i, SEGMENT_CONTENT_LENGTH);
		bufferPool[j].pBuffer->SegmentLength = SEGMENT_CONTENT_LENGTH;
		bufferPool[j].usingBuffer = true;
	}
	memcpy(bufferPool[j].pBuffer->SegmentContent, message + i, lengthOfLastSegment);
	bufferPool[j].pBuffer->SegmentLength = lengthOfLastSegment;
	bufferPool[j].usingBuffer = true;

	return numberOfBuffers;
}
