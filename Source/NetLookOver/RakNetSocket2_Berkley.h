/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

//#include "EmptyHeader.h"

#ifdef RAKNET_SOCKET_2_INLINE_FUNCTIONS

#ifndef RAKNETSOCKET2_BERKLEY_CPP
#define RAKNETSOCKET2_BERKLEY_CPP

// Every platform except windows store 8 and native client supports Berkley sockets
#if !defined(WINDOWS_STORE_RT) && !defined(__native_client__)

#include "Itoa.h"

void RNS2_Berkley::SetSocketOptions(void)
{
	int r;
	// This doubles the max throughput rate
	int sock_opt=1024*256;
	r = setsockopt__( rns2Socket, SOL_SOCKET, SO_RCVBUF, ( char * ) & sock_opt, sizeof ( sock_opt ) );
	RakAssert(r==0);

	// Immediate hard close. Don't linger the socket, or recreating the socket quickly on Vista fails.
	// Fail with voice and xbox

	sock_opt=0;
	r = setsockopt__( rns2Socket, SOL_SOCKET, SO_LINGER, ( char * ) & sock_opt, sizeof ( sock_opt ) );
	// Do not assert, ignore failure



	// This doesn't make much difference: 10% maybe
	// Not supported on console 2
	sock_opt=1024*16;
	r = setsockopt__( rns2Socket, SOL_SOCKET, SO_SNDBUF, ( char * ) & sock_opt, sizeof ( sock_opt ) );
	RakAssert(r==0);

}

void RNS2_Berkley::SetNonBlockingSocket(unsigned long nonblocking)
{
#if 1
		int res = ioctlsocket__( rns2Socket, FIONBIO, &nonblocking );
		RakAssert(res==0);



#else
	if (nonblocking)
		fcntl( rns2Socket, F_SETFL, O_NONBLOCK );
#endif
}
void RNS2_Berkley::SetBroadcastSocket(int broadcast)
{
	setsockopt__( rns2Socket, SOL_SOCKET, SO_BROADCAST, ( char * ) & broadcast, sizeof( broadcast ) );
}
void RNS2_Berkley::SetIPHdrIncl(int ipHdrIncl)
{

		setsockopt__( rns2Socket, IPPROTO_IP, IP_HDRINCL, ( char * ) & ipHdrIncl, sizeof( ipHdrIncl ) );

}
void RNS2_Berkley::SetDoNotFragment( int opt )
{
	#if defined( IP_DONTFRAGMENT )
 #if 1 && !defined(_DEBUG)
		// If this assert hit you improperly linked against WSock32.h
		RakAssert(IP_DONTFRAGMENT==14);
	#endif
		setsockopt__( rns2Socket, boundAddress.GetIPPROTO(), IP_DONTFRAGMENT, ( char * ) & opt, sizeof ( opt ) );
	#endif
}

void RNS2_Berkley::GetSystemAddressIPV4 ( RNS2Socket rns2Socket, SystemAddress *systemAddressOut )
{
	sockaddr_in sa;
	memset(&sa,0,sizeof(sockaddr_in));
	socklen_t len = sizeof(sa);
	//int r = 
		getsockname__(rns2Socket, (sockaddr*)&sa, &len);
	systemAddressOut->SetPortNetworkOrder(sa.sin_port);
	systemAddressOut->address.addr4.sin_addr.s_addr=sa.sin_addr.s_addr;

	if (systemAddressOut->address.addr4.sin_addr.s_addr == INADDR_ANY)
	{
			systemAddressOut->address.addr4.sin_addr.s_addr=inet_addr__("127.0.0.1");
	}
}

#ifdef _MSC_VER
#pragma warning( disable : 4702 ) // warning C4702: unreachable code
#endif
RNS2BindResult RNS2_Berkley::BindSharedIPV4( RNS2_BerkleyBindParameters *bindParameters, const char *file, unsigned int line ) {

	(void) file;
	(void) line;

	int ret;
	memset(&boundAddress.address.addr4,0,sizeof(sockaddr_in));
	boundAddress.address.addr4.sin_port = htons( bindParameters->port );
	rns2Socket = (int) socket__( bindParameters->addressFamily, bindParameters->type, bindParameters->protocol );
	if (rns2Socket == -1)
		return BR_FAILED_TO_BIND_SOCKET;

	SetSocketOptions();
	SetNonBlockingSocket(bindParameters->nonBlockingSocket);
	SetBroadcastSocket(bindParameters->setBroadcast);
	SetIPHdrIncl(bindParameters->setIPHdrIncl);

	// Fill in the rest of the address structure
	boundAddress.address.addr4.sin_family = AF_INET;
	
	if (bindParameters->hostAddress && bindParameters->hostAddress[0])
	{

		boundAddress.address.addr4.sin_addr.s_addr = inet_addr__( bindParameters->hostAddress );

	}
	else
	{
		//		RAKNET_DEBUG_PRINTF("Binding any on port %i\n", port);
		boundAddress.address.addr4.sin_addr.s_addr = INADDR_ANY;
	}

	// bind our name to the socket
	ret = bind__( rns2Socket, ( struct sockaddr * ) &boundAddress.address.addr4, sizeof( boundAddress.address.addr4 ) );

	if ( ret <= -1 )
	{

#if 1
		closesocket__(rns2Socket);
		return BR_FAILED_TO_BIND_SOCKET;
#elif (defined(__GNUC__) || defined(__GCCXML__) ) && !1
		closesocket__(rns2Socket);
		switch (ret)
		{
		case EBADF:
			RAKNET_DEBUG_PRINTF("bind__(): sockfd is not a valid descriptor.\n"); break;

		case ENOTSOCK:
			RAKNET_DEBUG_PRINTF("bind__(): Argument is a descriptor for a file, not a socket.\n"); break;

		case EINVAL:
			RAKNET_DEBUG_PRINTF("bind__(): The addrlen is wrong, or the socket was not in the AF_UNIX family.\n"); break;
		case EROFS:
			RAKNET_DEBUG_PRINTF("bind__(): The socket inode would reside on a read-only file system.\n"); break;
		case EFAULT:
			RAKNET_DEBUG_PRINTF("bind__(): my_addr points outside the user's accessible address space.\n"); break;
		case ENAMETOOLONG:
			RAKNET_DEBUG_PRINTF("bind__(): my_addr is too long.\n"); break;
		case ENOENT:
			RAKNET_DEBUG_PRINTF("bind__(): The file does not exist.\n"); break;
		case ENOMEM:
			RAKNET_DEBUG_PRINTF("bind__(): Insufficient kernel memory was available.\n"); break;
		case ENOTDIR:
			RAKNET_DEBUG_PRINTF("bind__(): A component of the path prefix is not a directory.\n"); break;
		case EACCES:
			// Port reserved on PS4
			RAKNET_DEBUG_PRINTF("bind__(): Search permission is denied on a component of the path prefix.\n"); break;

		case ELOOP:
			RAKNET_DEBUG_PRINTF("bind__(): Too many symbolic links were encountered in resolving my_addr.\n"); break;

		default:
			RAKNET_DEBUG_PRINTF("Unknown bind__() error %i.\n", ret); break;
		}
#endif
	
		return BR_FAILED_TO_BIND_SOCKET;
	}

	GetSystemAddressIPV4(rns2Socket, &boundAddress );

	return BR_SUCCESS;

}

void RNS2_Berkley::RecvFromBlockingIPV4(RNS2RecvStruct *recvFromStruct)
{
	sockaddr* sockAddrPtr;
	socklen_t sockLen;
	socklen_t* socketlenPtr=(socklen_t*) &sockLen;
	sockaddr_in sa;
	memset(&sa,0,sizeof(sockaddr_in));
	const int flag=0;
	


	{
		sockLen=sizeof(sa);
		sa.sin_family = AF_INET;
		sa.sin_port=0;
		sockAddrPtr=(sockaddr*) &sa;
	}

	recvFromStruct->bytesRead = recvfrom__( GetSocket(), recvFromStruct->data, sizeof(recvFromStruct->data), flag, sockAddrPtr, socketlenPtr );


	if (recvFromStruct->bytesRead<=0)
	{
		return;
	}
	recvFromStruct->timeRead=RakNet::GetTimeUS();


	{
		
		recvFromStruct->systemAddress.SetPortNetworkOrder( sa.sin_port );
		recvFromStruct->systemAddress.address.addr4.sin_addr.s_addr=sa.sin_addr.s_addr;
	}

	// printf("--- Got %i bytes from %s\n", recvFromStruct->bytesRead, recvFromStruct->systemAddress.ToString());
}

void RNS2_Berkley::RecvFromBlocking(RNS2RecvStruct *recvFromStruct)
{
	return RecvFromBlockingIPV4(recvFromStruct);
}

#endif // !defined(WINDOWS_STORE_RT) && !defined(__native_client__)

#endif // file header

#endif // #ifdef RAKNET_SOCKET_2_INLINE_FUNCTIONS
