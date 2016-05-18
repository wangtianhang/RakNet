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

#ifndef RAKNETSOCKET2_BERKLEY_NATIVE_CLIENT_CPP
#define RAKNETSOCKET2_BERKLEY_NATIVE_CLIENT_CPP

// Every platform except windows store 8 and native client supports Berkley sockets
#if !defined(WINDOWS_STORE_RT)

#include "Itoa.h"

// Shared on most platforms, but excluded from the listed


void DomainNameToIP_Berkley_IPV4( const char *domainName, char ip[65] )
{
	static struct in_addr addr;
	memset(&addr,0,sizeof(in_addr));
	
	// Use inet_addr instead? What is the difference?
	struct hostent * phe = gethostbyname( domainName );

	if ( phe == 0 || phe->h_addr_list[ 0 ] == 0 )
	{
		//cerr << "Yow! Bad host lookup." << endl;
		memset(ip,0,65*sizeof(char));
		return;
	}

	if (phe->h_addr_list[ 0 ]==0)
	{
		memset(ip,0,65*sizeof(char));
		return;
	}

	memcpy( &addr, phe->h_addr_list[ 0 ], sizeof( struct in_addr ) );
	strcpy(ip, inet_ntoa( addr ));
}



void DomainNameToIP_Berkley( const char *domainName, char ip[65] )
{
	return DomainNameToIP_Berkley_IPV4(domainName, ip);
}




#endif // !defined(WINDOWS_STORE_RT) && !defined(__native_client__)

#endif // file header

#endif // #ifdef RAKNET_SOCKET_2_INLINE_FUNCTIONS
