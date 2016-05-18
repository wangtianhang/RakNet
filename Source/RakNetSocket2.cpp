/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "RakNetSocket2.h"
#include "RakMemoryOverride.h"
#include "RakAssert.h"
#include "RakSleep.h"
#include "SocketDefines.h"
#include "GetTime.h"
#include <stdio.h>
#include <string.h> // memcpy

using namespace RakNet;

#if 1
#else
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>  // error numbers
#if !defined(ANDROID)
#include <ifaddrs.h>
#endif
#include <netinet/in.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#endif

#ifdef TEST_NATIVE_CLIENT_ON_WINDOWS
#else
#define RAKNET_SOCKET_2_INLINE_FUNCTIONS
//#include "RakNetSocket2_360_720.cpp"
//#include "RakNetSocket2_PS3_PS4.cpp"
//#include "RakNetSocket2_PS4.cpp"
#include "RakNetSocket2_Windows_Linux.h"
#include "RakNetSocket2_Windows_Linux_360.h"
//#include "RakNetSocket2_Vita.cpp"
//#include "RakNetSocket2_NativeClient.cpp"
#include "RakNetSocket2_Berkley.h"
#include "RakNetSocket2_Berkley_NativeClient.h"
//#include "RakNetSocket2_WindowsStore8.cpp"
#undef RAKNET_SOCKET_2_INLINE_FUNCTIONS

#endif

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif

void RakNetSocket2Allocator::DeallocRNS2(RakNetSocket2 *s) {RakNet::OP_DELETE(s,_FILE_AND_LINE_);}
RakNetSocket2::RakNetSocket2() {eventHandler=0;}
RakNetSocket2::~RakNetSocket2() {}
void RakNetSocket2::SetRecvEventHandler(RNS2EventHandler *_eventHandler) {eventHandler=_eventHandler;}
RNS2Type RakNetSocket2::GetSocketType(void) const {return socketType;}
void RakNetSocket2::SetSocketType(RNS2Type t) {socketType=t;}
bool RakNetSocket2::IsBerkleySocket(void) const {
	return socketType!=RNS2T_CHROME && socketType!=RNS2T_WINDOWS_STORE_8;
}
SystemAddress RakNetSocket2::GetBoundAddress(void) const {return boundAddress;}

RakNetSocket2* RakNetSocket2Allocator::AllocRNS2(void)
{
	RakNetSocket2* s2;
#if defined(WINDOWS_STORE_RT)
	s2 = RakNet::OP_NEW<RNS2_WindowsStore8>(_FILE_AND_LINE_);
	s2->SetSocketType(RNS2T_WINDOWS_STORE_8);

#elif defined(__native_client__)
	s2 = RakNet::OP_NEW<RNS2_NativeClient>(_FILE_AND_LINE_);
	s2->SetSocketType(RNS2T_CHROME);

#elif 1
	s2 = RakNet::OP_NEW<RNS2_Windows>(_FILE_AND_LINE_);
	s2->SetSocketType(RNS2T_WINDOWS);
#else
	s2 = RakNet::OP_NEW<RNS2_Linux>(_FILE_AND_LINE_);
	s2->SetSocketType(RNS2T_LINUX);
#endif
	return s2;
}
void RakNetSocket2::GetMyIP( SystemAddress addresses[MAXIMUM_NUMBER_OF_INTERNAL_IDS] )
{
#if defined(WINDOWS_STORE_RT)
	RNS2_WindowsStore8::GetMyIP( addresses );


#elif defined(__native_client__)
	RNS2_NativeClient::GetMyIP( addresses );


#elif 1
	RNS2_Windows::GetMyIP( addresses );
#else
	RNS2_Linux::GetMyIP( addresses );
#endif
}

unsigned int RakNetSocket2::GetUserConnectionSocketIndex(void) const {return userConnectionSocketIndex;}
void RakNetSocket2::SetUserConnectionSocketIndex(unsigned int i) {userConnectionSocketIndex=i;}
RNS2EventHandler * RakNetSocket2::GetEventHandler(void) const {return eventHandler;}

void RakNetSocket2::DomainNameToIP( const char *domainName, char ip[65] ) {
#if defined(WINDOWS_STORE_RT)
	return RNS2_WindowsStore8::DomainNameToIP( domainName, ip );
#elif defined(__native_client__)
	return DomainNameToIP_Berkley( domainName, ip );

#elif 1
	return DomainNameToIP_Berkley( domainName, ip );
#else
	return DomainNameToIP_Berkley( domainName, ip );
#endif
}

#if defined(WINDOWS_STORE_RT)
#elif defined(__native_client__)

#else // defined(__native_client__)
bool IRNS2_Berkley::IsPortInUse(unsigned short port, const char *hostAddress, unsigned short addressFamily, int type ) {
	RNS2_BerkleyBindParameters bbp;
	bbp.remotePortRakNetWasStartedOn_PS3_PS4_PSP2=0;
	bbp.port=port; bbp.hostAddress=(char*) hostAddress;	bbp.addressFamily=addressFamily;
	bbp.type=type; bbp.protocol=0; bbp.nonBlockingSocket=false;
	bbp.setBroadcast=false;	bbp.doNotFragment=false; bbp.protocol=0;
	bbp.setIPHdrIncl=false;
	SystemAddress boundAddress;
	RNS2_Berkley *rns2 = (RNS2_Berkley*) RakNetSocket2Allocator::AllocRNS2();
	RNS2BindResult bindResult = rns2->Bind(&bbp, _FILE_AND_LINE_);
	RakNetSocket2Allocator::DeallocRNS2(rns2);
	return bindResult==BR_FAILED_TO_BIND_SOCKET;
}

#if defined(__APPLE__)
void SocketReadCallback(CFSocketRef s, CFSocketCallBackType type, CFDataRef address, const void *data, void *info)
// This C routine is called by CFSocket when there's data waiting on our 
// UDP socket.  It just redirects the call to Objective-C code.
{ }
#endif

RNS2BindResult RNS2_Berkley::BindShared( RNS2_BerkleyBindParameters *bindParameters, const char *file, unsigned int line ) {
	RNS2BindResult br;

	br=BindSharedIPV4(bindParameters, file, line);

	if (br!=BR_SUCCESS)
		return br;

	unsigned long zero=0;
	RNS2_SendParameters bsp;
	bsp.data=(char*) &zero;
	bsp.length=4;
	bsp.systemAddress=boundAddress;
	bsp.ttl=0;
	RNS2SendResult sr = Send(&bsp, _FILE_AND_LINE_);
	if (sr<0)
		return BR_FAILED_SEND_TEST;

	memcpy(&binding, bindParameters, sizeof(RNS2_BerkleyBindParameters));

	/*
#if defined(__APPLE__)
	const CFSocketContext   context = { 0, this, NULL, NULL, NULL };
	_cfSocket = CFSocketCreateWithNative(NULL, rns2Socket, kCFSocketReadCallBack, SocketReadCallback, &context);
#endif
	*/

	return br;
}

RAK_THREAD_DECLARATION(RNS2_Berkley::RecvFromLoop)
{



	RNS2_Berkley *b = ( RNS2_Berkley * ) arguments;

	b->RecvFromLoopInt();
	return 0;
}
unsigned RNS2_Berkley::RecvFromLoopInt(void)
{
	isRecvFromLoopThreadActive.Increment();
	
	while ( endThreads == false )
	{
		RNS2RecvStruct *recvFromStruct;
		recvFromStruct=binding.eventHandler->AllocRNS2RecvStruct(_FILE_AND_LINE_);
		if (recvFromStruct != NULL)
		{
			recvFromStruct->socket=this;
			RecvFromBlocking(recvFromStruct);

			if (recvFromStruct->bytesRead>0)
			{
				RakAssert(recvFromStruct->systemAddress.GetPort());
				binding.eventHandler->OnRNS2Recv(recvFromStruct);
			}
			else
			{
				RakSleep(0);
				binding.eventHandler->DeallocRNS2RecvStruct(recvFromStruct, _FILE_AND_LINE_);
			}
		}
	}
	isRecvFromLoopThreadActive.Decrement();




	return 0;

}
RNS2_Berkley::RNS2_Berkley()
{
	rns2Socket=(RNS2Socket)INVALID_SOCKET;
}
RNS2_Berkley::~RNS2_Berkley()
{
	if (rns2Socket!=INVALID_SOCKET)
	{
		/*
#if defined(__APPLE__)
		CFSocketInvalidate(_cfSocket);
#endif
		*/

		closesocket__(rns2Socket);
	}

}
int RNS2_Berkley::CreateRecvPollingThread(int threadPriority)
{
	endThreads=false;






	int errorCode = RakNet::RakThread::Create(RecvFromLoop, this, threadPriority);

	return errorCode;
}
void RNS2_Berkley::SignalStopRecvPollingThread(void)
{
	endThreads=true;
}
void RNS2_Berkley::BlockOnStopRecvPollingThread(void)
{
	endThreads=true;

	// Get recvfrom to unblock
	RNS2_SendParameters bsp;
	unsigned long zero=0;
	bsp.data=(char*) &zero;
	bsp.length=4;
	bsp.systemAddress=boundAddress;
	bsp.ttl=0;
	Send(&bsp, _FILE_AND_LINE_);

	RakNet::TimeMS timeout = RakNet::GetTimeMS()+1000;
	while ( isRecvFromLoopThreadActive.GetValue()>0 && RakNet::GetTimeMS()<timeout )
	{
		// Get recvfrom to unblock
		Send(&bsp, _FILE_AND_LINE_);
		RakSleep(30);
	}
}
const RNS2_BerkleyBindParameters *RNS2_Berkley::GetBindings(void) const {return &binding;}
RNS2Socket RNS2_Berkley::GetSocket(void) const {return rns2Socket;}
// See RakNetSocket2_Berkley.cpp for WriteSharedIPV4, BindSharedIPV4And6 and other implementations


#if   1
RNS2_Windows::RNS2_Windows() {slo=0;}
RNS2_Windows::~RNS2_Windows() {}
RNS2BindResult RNS2_Windows::Bind( RNS2_BerkleyBindParameters *bindParameters, const char *file, unsigned int line ) {
	RNS2BindResult bindResult = BindShared(bindParameters, file, line);
	if (bindResult == BR_FAILED_TO_BIND_SOCKET)
	{
		// Sometimes windows will fail if the socket is recreated too quickly
		RakSleep(100);
		bindResult = BindShared(bindParameters, file, line);
	}
	return bindResult;
}
RNS2SendResult RNS2_Windows::Send( RNS2_SendParameters *sendParameters, const char *file, unsigned int line ) {
	if (slo)
	{
		RNS2SendResult len;
		len = slo->RakNetSendTo(sendParameters->data, sendParameters->length,sendParameters->systemAddress);
		if (len>=0)
			return len;
	} 
	return Send_Windows_Linux_360NoVDP(rns2Socket,sendParameters, file, line);
}
void RNS2_Windows::GetMyIP( SystemAddress addresses[MAXIMUM_NUMBER_OF_INTERNAL_IDS] ) {return GetMyIP_Windows_Linux(addresses);}
void RNS2_Windows::SetSocketLayerOverride(SocketLayerOverride *_slo) {slo = _slo;}
SocketLayerOverride* RNS2_Windows::GetSocketLayerOverride(void) {return slo;}
#else
RNS2BindResult RNS2_Linux::Bind( RNS2_BerkleyBindParameters *bindParameters, const char *file, unsigned int line ) {return BindShared(bindParameters, file, line);}
RNS2SendResult RNS2_Linux::Send( RNS2_SendParameters *sendParameters, const char *file, unsigned int line ) {return Send_Windows_Linux_360NoVDP(rns2Socket,sendParameters, file, line);}
void RNS2_Linux::GetMyIP( SystemAddress addresses[MAXIMUM_NUMBER_OF_INTERNAL_IDS] ) {return GetMyIP_Windows_Linux(addresses);}
#endif // Linux

#endif //  defined(__native_client__)
