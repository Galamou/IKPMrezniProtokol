#include <winsock2.h>
#include <stdio.h>
#include <conio.h>

#define SERVER_PORT 15000
#define OUTGOING_BUFFER_SIZE 1024
#define IP_ADDRESS_LEN 16

#define CLIENT_SLEEP_TIME 100

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

// Struktura za TIMEOUT. Mislim da ne mora da se koristi CRC za TIMEOUT.
#pragma pack(push,1)
struct TIMEOUT {
	int SegmentIndex;
	DWORD SegmentSent;                        // Kad je segment poslat
};
#pragma pack(pop)

// Struktura za threadove
#pragma pack(push,1)
struct ThreadParameters {
	SOCKET* clientSocket;
	int* ackIndex;
	TIMEOUT* timeouts;
	int* numberOfSegments;
};

bool InitializeWindowsSockets();
DWORD WINAPI Send(LPVOID lpParam);
DWORD WINAPI ReceiveAck(LPVOID lpParam);
DWORD WINAPI AckTimer(LPVOID param);
int CreateSegments(char[], struct Buffer[BUFFER_NUMBER]); // Deli pocetnu poruku na segmente i smesta segmente u bufferPool.

// Global
// Index from which client sends messages.
// ReceiveACK thread sets ackIndex to last sequentially (every index ACKed before this index) ACKed index.
CRITICAL_SECTION csAckIndex;
CRITICAL_SECTION csTimeouts;
CRITICAL_SECTION csNumberOfSegments;
bool run = true;

// for demonstration purposes we will hard code
// local host ip address
#define SERVER_IP_ADDERESS "127.0.0.1"

// UDP client that uses blocking sockets
int main(int argc, char* argv[])
{
	// Initialize windows sockets for this process
	InitializeWindowsSockets();
	// variable used to store function return value
	int iResult;

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

	// Timeouts
	TIMEOUT timeouts[BUFFER_NUMBER];
	memset(timeouts, 0, sizeof(TIMEOUT) * BUFFER_NUMBER);

	printf("Press enter to start...\n");
	_getch();

	// Main client loop
	DWORD receiveID, sendID;
	HANDLE hReceive, hSend;

	ThreadParameters tp;
	int ackIndex = -1;
	int numberOfSegments = -1;

	tp.clientSocket = &clientSocket;
	tp.ackIndex = &ackIndex;
	tp.numberOfSegments = &numberOfSegments;
	tp.timeouts = timeouts;

	InitializeCriticalSection(&csAckIndex);
	InitializeCriticalSection(&csNumberOfSegments);
	InitializeCriticalSection(&csTimeouts);

	hReceive = CreateThread(NULL, 0, &Send, &tp, 0, &sendID);
	hSend = CreateThread(NULL, 0, &ReceiveAck, &tp, 0, &receiveID);

	while (run)
	{
		Sleep(CLIENT_SLEEP_TIME);
		/*int liI = getchar();

		if (liI == 10 || liI == 13) break;*/
	}

	DeleteCriticalSection(&csAckIndex);
	DeleteCriticalSection(&csNumberOfSegments);
	DeleteCriticalSection(&csTimeouts);

	CloseHandle(hReceive);
	CloseHandle(hSend);

	// If we are here, it means client is shutting down.
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

// Thread send message function (clientSocket, ackIndex, numberOfSegments, timeouts)
/*
\	ackIndex = -1		sve je ok, salji sledeci segment
/   ackIndex = -2		poslednji segment je ackovan
\	ackIndex =  n		n-tom segmentu je istekao timeout, salji ponovo od n-tog segmenta
*/
DWORD WINAPI Send(LPVOID lpParam)
{
	ThreadParameters tp = *(ThreadParameters*)lpParam;

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
	
	// variable used to store function return value
	int iResult;
	// server address
	sockaddr_in serverAddress;
	// size of sockaddr structure
	int sockAddrLen = sizeof(struct sockaddr);
	// server port we will send data to
	int serverPort = SERVER_PORT;

	// Initialize serverAddress structure
	memset((char*)&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP_ADDERESS);
	serverAddress.sin_port = htons((u_short)serverPort);


	// Trenutno se salje jedna te ista poruka.
	while (1)
	{
		// CREATE MESSAGE ---------------------------------------------------------------------------------------------------
		char* message = "01234567891011121314151617181920212223";		// za sad kratka poruka da bi mogli da testiramo da li sve radi

		// DIVIDE MESSAGE ---------------------------------------------------------------------------------------------------

		// Deli pocetnu poruku na segmente i smesta ih u bufferPool.
		// Postavlja tim segmentima u bufferPoolu vrednost SegmentContent i SegmentLength. 
		// Postavlja vrednost polja usingBuffer buffera iz bufferPoola na true za one buffere u koje je smestio segmente.
		// Ne moraju svi bufferi iz bufferPoola biti zauzeti (ako je poruka kraca).
		int localNumberOfSegments = CreateSegments(message, bufferPool);
		
		// Kaze receiveAck threadu koji je broj segmenata, da bi znao posle koliko ackova da se resetuje
		EnterCriticalSection(&csNumberOfSegments);
		*(tp.numberOfSegments) = localNumberOfSegments;
		LeaveCriticalSection(&csNumberOfSegments);

		// SEND --------------------------------------------------------------------------------------------------------------
		int localAckIdex = -1;
		// Namesta ackIndex na pocetnu vrednost.
		EnterCriticalSection(&csAckIndex);
		*(tp.ackIndex) = localAckIdex;
		LeaveCriticalSection(&csAckIndex);

		// Salju se svi segmenti jedne poruke jedan po jedan.
		for (int i = 0; i < localNumberOfSegments; i++)
		{
			// Objasnjenje:
			// indexACK je -1 kad nije doslo do TIMEOUT
			// indexACK nije -1 kad je doslo do TIMEOUT na nekom segmentu i tad predstavlja index segmenta od kog krece zanavljanje

			// Poslednji ackovan index
			EnterCriticalSection(&csAckIndex);
			localAckIdex = *(tp.ackIndex);

			// indexACK = -1 -> i se ne menja
			// indexACK != -1 -> i = indexACK
			if (localAckIdex != -1)
			{
				// Zanavljamo od poslednjeg ackovanog segmenta
				i = localAckIdex;
				// Kazemo da su svi bufferi pre tog segmenta slobodni, svi bufferi posle tog segmenta ostaju zauzeti
				for (int j = 0;j < localAckIdex;j++)
				{
					// Poruka za ovaj buffre je ACKovana, i buffer moze da se oslobodi
					bufferPool[i].usingBuffer = false;
					memset(bufferPool[i].pBuffer, 0, sizeof(struct Segment));
				}

				// Vracamo ackIndex na -1
				*(tp.ackIndex) = -1;
			}
			LeaveCriticalSection(&csAckIndex);

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
				iResult = sendto(*(tp.clientSocket),
					(char*)(bufferPool[i].pBuffer),
					sizeof(struct Segment),
					0,
					(LPSOCKADDR)&serverAddress,
					sockAddrLen);

				if (iResult == SOCKET_ERROR)
				{
					printf("sendto failed with error: %d\n", WSAGetLastError());
					closesocket(*(tp.clientSocket));
					WSACleanup();
					return 1;
				}

				// Dobavljamo sistemsko vreme.
				SYSTEMTIME t;
				GetSystemTime(&t);
				// Pamtimo kad smo poslali segment zbog TIMEOUTa.
				EnterCriticalSection(&csTimeouts);
				tp.timeouts[i].SegmentSent = t.wMilliseconds;
				LeaveCriticalSection(&csTimeouts);

				// Ispis poslate poruke. (dodajemo na kraj '\0' da moze da se ispise)
				char content[SEGMENT_CONTENT_LENGTH + 1];
				memcpy(content, bufferPool[i].pBuffer->SegmentContent, bufferPool[i].pBuffer->SegmentLength);
				content[bufferPool[i].pBuffer->SegmentLength] = '\0';
				printf("Sent message: %s\n", content);

				// Ako smo poslali sve segmente, ali ack nije stigao za sve segmente plus TIMEOUT se nije desio ni na jednom segmentu.
				// Cekamo da se ili ackuju ne ackovani segmenti ili da nekom segmentu istekne TIMEOUT.
				// ackIndex je -2 ako je poslednji segment ackovan
				while (localAckIdex != -2 && i == BUFFER_NUMBER - 1)
				{
					printf("Waiting for last segments to get ACKed...\n");
					Sleep(CLIENT_SLEEP_TIME);

					// Uzmi novu vrednost ackIndexa
					EnterCriticalSection(&csAckIndex);
					localAckIdex = *(tp.ackIndex);
					LeaveCriticalSection(&csAckIndex);
				}
			}
		}


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

	run = false;
}

// Thread receive ack function (clientSocket, ackIndex, numberOfSegments, timeouts)
/*
\	ackIndex = -1		sve je ok, salji sledeci segment
/   ackIndex = -2		poslednji segment je ackovan
\	ackIndex =  n		n-tom segmentu je istekao timeout, salji ponovo od n-tog segmenta
*/
DWORD WINAPI ReceiveAck(LPVOID lpParam)
{
	ThreadParameters tp = *(ThreadParameters*)lpParam;

	// variable used to store function return value
	int iResult;
	// server address
	sockaddr_in serverAddress;
	// size of sockaddr structure
	int sockAddrLen = sizeof(struct sockaddr);
	// server port we will send data to
	int serverPort = SERVER_PORT;

	// Initialize serverAddress structure
	memset((char*)&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_addr.s_addr = inet_addr(SERVER_IP_ADDERESS);
	serverAddress.sin_port = htons((u_short)serverPort);

	int localAckIndex = 0;
	// Timeout u milisekundama.
	int TIMEOUT_LENGTH = 1000;
	int localNumberOfSegments = -1;
	EnterCriticalSection(&csNumberOfSegments);
	localNumberOfSegments = *(tp.numberOfSegments);
	LeaveCriticalSection(&csNumberOfSegments);

	while (1)
	{
		// Da li je prethodna poruka poslata?
		while (localNumberOfSegments == -1)
		{
			// Prethodna poruka je poslata. Cekamo vrednost broja segmenata za novu poruku.
			EnterCriticalSection(&csNumberOfSegments);
			localNumberOfSegments = *(tp.numberOfSegments);
			LeaveCriticalSection(&csNumberOfSegments);
			Sleep(CLIENT_SLEEP_TIME);
		}

		// SELECT ---------------------------------------------------------------------------------------------------------
		// Parametri za select.
		FD_SET set;
		timeval timeVal;

		FD_ZERO(&set);
		// Dodajemo clientSocket, jer od tog socketa primamo poruke.
		FD_SET(*tp.clientSocket, &set);

		// Postavljamo vreme cekanja recvfrom na 0, jer zelimo da nam odmah prosledi pristiglu poruku.
		timeVal.tv_sec = 0;
		timeVal.tv_usec = 0;

		iResult = select(0 /* ignored */, &set, NULL, NULL, &timeVal);

		// Da li je doslo do greske prilikom select-ovanja?
		if (iResult == SOCKET_ERROR)
		{
			// Doslo je do greske. Izlazimo iz threada.
			fprintf(stderr, "select failed with error: %ld\n", WSAGetLastError());
			return SOCKET_ERROR;
		}

		// Da li je clientSocket dobio poruku?
		if (iResult != 0)
		{
			// Dobio je poruku.
			
			// RECEIVE --------------------------------------------------------------------------------------------------------
			// Ack
			struct ACK ack;
			memset(&ack, 0, sizeof(struct ACK));

			// Primamo ack.
			iResult = recvfrom(*(tp.clientSocket),
				(char*)&ack,
				sizeof(struct ACK),
				0,
				(LPSOCKADDR)&serverAddress,
				&sockAddrLen);

			// Da li je doslo do greske kod primanja poruke?
			if (iResult == SOCKET_ERROR)
			{
				// Doslo je do greske. Primamo poruku ispocetka.
				printf("recvfrom failed with error: %d\n", WSAGetLastError());
				continue;
			}

			// Ispisujemo primljenu poruku.
			printf("Received ACK = %d\n", ack.SegmentACK);

			// Da li je segment ackovan?
			if (ack.SegmentACK == 1)
			{
				// Segment je ACKovan, pa pamtimo indeks tog segmenta.
				localAckIndex = ack.SegmentIndex;
			}
		}

		// Da li se desio TIMEOUT za bilo koji segment?
		EnterCriticalSection(&csTimeouts);
		for (int i = localAckIndex;i < localNumberOfSegments;i++)
		{
			// Dobavljamo sistemsko vreme.
			SYSTEMTIME t;
			GetSystemTime(&t);

			// Da li se desio TIMEOUT za i-ti segment?
			if (t.wMilliseconds - tp.timeouts[i].SegmentSent > TIMEOUT_LENGTH)
			{
				// Desio se timeout za i-ti segment.
				EnterCriticalSection(&csAckIndex);
				// Menjamo ackIndex na indeks od kog treba da krece zanavljanje.
				*(tp.ackIndex) = i;
				LeaveCriticalSection(&csAckIndex);
				// Izlazimo iz petlje, jer nas segmenti posle ovog neinteresuju(svi oni se smatraju ne ackovanim takodje).
				break;
			}
		}
		LeaveCriticalSection(&csTimeouts);

		// Da li smo primili ack za poslednji segment?
		if (localAckIndex == localNumberOfSegments - 1)
		{
			// Primili smo ack za poslednji segment.
			EnterCriticalSection(&csAckIndex);
			// Menjamo ackIndex na -2. To je znak send threadu da je poslednji segment primljen.
			*(tp.ackIndex) = -2;
			LeaveCriticalSection(&csAckIndex);
			// Resetujemo indeks za sledecu poruku.
			localAckIndex = 0;
			// Resetujemo broj segmenata za sledecu poruku(i lokalni i globalni).
			localNumberOfSegments = -1;
			EnterCriticalSection(&csNumberOfSegments);
			*(tp.numberOfSegments) = localNumberOfSegments;
			LeaveCriticalSection(&csNumberOfSegments);
		}
	}
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
