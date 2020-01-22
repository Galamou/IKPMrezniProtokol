#pragma once
#ifndef COMMON_HPP_INCLUDE

#include <stdlib.h>
#include <WinSock2.h>

// ## Response ########################################################################################################
char ACK_MESSAGE[4] = { 'A', 'C', 'K', '\0' };

// ## CRC #############################################################################################################

#define POLYNOMIAL 0xD8  /* 11011 followed by 0's */
#define WIDTH  (8 * sizeof(char))
#define TOPBIT (1 << (WIDTH - 1))

char crc(char const message[], int nBytes) // Returns a remainder of the CRC algorithm.
										   // Before sending a message: append the remainder at the end of the data.
										   // After recieving a message: check if the remainder is 0 after running the data through the CRC algorithm.
{
	char remainder = 0;

	/*
	 * Perform modulo-2 division, a byte at a time.
	 */
	for (int byte = 0; byte < nBytes; ++byte)
	{
		/*
		 * Bring the next byte into the remainder.
		 */
		remainder ^= (message[byte] << (WIDTH - 8));

		/*
		 * Perform modulo-2 division, a bit at a time.
		 */
		for (char bit = 8; bit > 0; --bit)
		{
			/*
			 * Try to divide the current data bit.
			 */
			if (remainder & TOPBIT)
			{
				remainder = (remainder << 1) ^ POLYNOMIAL;
			}
			else
			{
				remainder = (remainder << 1);
			}
		}
	}

	/*
	 * The final remainder is the CRC result.
	 */
	return (remainder);

}

// A return value used by the SEND and RECIEVE functions for CRC.
struct protocol_comm_data
{
	int iResult;
	char rem;
};

protocol_comm_data recvfrom_w_crc(SOCKET* socket, char* buffer, int buffer_size, int* flags, sockaddr_in* source_address, int* sock_addr_len)
{
	int iResult = recvfrom(*socket,
		buffer,
		buffer_size,
		*flags,
		(LPSOCKADDR)source_address,
		sock_addr_len);

	char rem = crc(buffer, buffer_size);

	protocol_comm_data pcd;
	pcd.iResult = iResult;
	pcd.rem = rem;

	return pcd;
}

protocol_comm_data sendto_w_crc(SOCKET* socket, char* data, int data_length, int* flags, sockaddr_in* destination_address, int* sock_addr_len)
{
	char rem = crc(data, data_length);

	char* temp_data = (char*)malloc(data_length + sizeof(char));
	memcpy(temp_data, data, data_length);
	temp_data[data_length] = rem;

	int iResult = sendto(*socket,
		temp_data,
		data_length + sizeof(char),
		*flags,
		(LPSOCKADDR)destination_address,
		*sock_addr_len);

	free(temp_data);

	protocol_comm_data pcd;
	pcd.iResult = iResult;
	pcd.rem = rem;

	return pcd;
}

#endif // !COMMON_HPP_INCLUDE