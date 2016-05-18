/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef __RAKNET_SOCKET_2_H
#define __RAKNET_SOCKET_2_H

#include "RakNetTypes.h"
#include "MTUSize.h"
#include "LocklessTypes.h"
#include "RakThread.h"
#include "DS_ThreadsafeAllocatingQueue.h"
#include "Export.h"

// For CFSocket
// https://developer.apple.com/library/mac/#documentation/CoreFOundation/Reference/CFSocketRef/Reference/reference.html
// Reason: http://sourceforge.net/p/open-dis/discussion/683284/thread/0929d6a0
#if defined(__APPLE__)
#import <CoreFoundation/CoreFoundation.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

// #define TEST_NATIVE_CLIENT_ON_WINDOWS

#ifdef TEST_NATIVE_CLIENT_ON_WINDOWS
#define __native_client__
typedef int PP_Resource;
#endif

namespace RakNet
{

class RakNetSocket2;
struct RNS2_BerkleyBindParameters;
struct RNS2_SendParameters;
typedef int RNS2Socket;

enum RNS2BindResult
{
	BR_SUCCESS,
	BR_REQUIRES_RAKNET_SUPPORT_IPV6_DEFINE,
	BR_FAILED_TO_BIND_SOCKET,
	BR_FAILED_SEND_TEST,
};

typedef int RNS2SendResult;

enum RNS2Type
{
	RNS2T_WINDOWS_STORE_8,
	RNS2T_PS3,
	RNS2T_PS4,
	RNS2T_CHROME,
	RNS2T_VITA,
	RNS2T_XBOX_360,
	RNS2T_XBOX_720,
	RNS2T_WINDOWS,
	RNS2T_LINUX
};

struct RNS2_SendParameters
{
	RNS2_SendParameters() {ttl=0;}
	char *data;
	int length;
	SystemAddress systemAddress;
	int ttl;
};

struct RNS2RecvStruct
{



	char data[MAXIMUM_MTU_SIZE];

	int bytesRead;
	SystemAddress systemAddress;
	RakNet::TimeUS timeRead;
	RakNetSocket2 *socket;
};

class RakNetSocket2Allocator
{
public:
	static RakNetSocket2* AllocRNS2(void);
	static void DeallocRNS2(RakNetSocket2 *s);
};

class RAK_DLL_EXPORT RNS2EventHandler
{
public:
	RNS2EventHandler() {}
	virtual ~RNS2EventHandler() {}

	//		bufferedPackets.Push(recvFromStruct);
	//		quitAndDataEvents.SetEvent();
	virtual void OnRNS2Recv(RNS2RecvStruct *recvStruct)=0;
	virtual void DeallocRNS2RecvStruct(RNS2RecvStruct *s, const char *file, unsigned int line)=0;
	virtual RNS2RecvStruct *AllocRNS2RecvStruct(const char *file, unsigned int line)=0;

	// recvFromStruct=bufferedPackets.Allocate( _FILE_AND_LINE_ );
	// 	DataStructures::ThreadsafeAllocatingQueue<RNS2RecvStruct> bufferedPackets;
};

class RakNetSocket2
{
public:
	RakNetSocket2();
	virtual ~RakNetSocket2();

	// In order for the handler to trigger, some platforms must call PollRecvFrom, some platforms this create an internal thread.
	void SetRecvEventHandler(RNS2EventHandler *_eventHandler);
	virtual RNS2SendResult Send( RNS2_SendParameters *sendParameters, const char *file, unsigned int line )=0;
	RNS2Type GetSocketType(void) const;
	void SetSocketType(RNS2Type t);
	bool IsBerkleySocket(void) const;
	SystemAddress GetBoundAddress(void) const;
	unsigned int GetUserConnectionSocketIndex(void) const;
	void SetUserConnectionSocketIndex(unsigned int i);
	RNS2EventHandler * GetEventHandler(void) const;

	// ----------- STATICS ------------
	static void GetMyIP( SystemAddress addresses[MAXIMUM_NUMBER_OF_INTERNAL_IDS] );
	static void DomainNameToIP( const char *domainName, char ip[65] );

protected:
	RNS2EventHandler *eventHandler;
	RNS2Type socketType;
	SystemAddress boundAddress;
	unsigned int userConnectionSocketIndex;
};

#if defined(WINDOWS_STORE_RT)

#elif defined(__native_client__)

#else // defined(WINDOWS_STORE_RT)

struct RNS2_BerkleyBindParameters
{
	// Input parameters
	unsigned short port;
	char *hostAddress;
	unsigned short addressFamily; // AF_INET or AF_INET6
	int type; // SOCK_DGRAM
	int protocol; // 0
	bool nonBlockingSocket;
	int setBroadcast;
	int setIPHdrIncl;
	int doNotFragment;
	int pollingThreadPriority;
	RNS2EventHandler *eventHandler;
	unsigned short remotePortRakNetWasStartedOn_PS3_PS4_PSP2;
};

// Every platform except Windows Store 8 can use the Berkley sockets interface
class IRNS2_Berkley : public RakNetSocket2
{
public:
	// ----------- STATICS ------------
	// For addressFamily, use AF_INET
	// For type, use SOCK_DGRAM
	static bool IsPortInUse(unsigned short port, const char *hostAddress, unsigned short addressFamily, int type );

	// ----------- MEMBERS ------------
	virtual RNS2BindResult Bind( RNS2_BerkleyBindParameters *bindParameters, const char *file, unsigned int line )=0;
};
// Every platform that uses Berkley sockets, except native client, can compile some common functions
class RNS2_Berkley : public IRNS2_Berkley
{
public:
	RNS2_Berkley();
	virtual ~RNS2_Berkley();
	int CreateRecvPollingThread(int threadPriority);
	void SignalStopRecvPollingThread(void);
	void BlockOnStopRecvPollingThread(void);
	const RNS2_BerkleyBindParameters *GetBindings(void) const;
	RNS2Socket GetSocket(void) const;
	void SetDoNotFragment( int opt );

protected:
	// Used by other classes
	RNS2BindResult BindShared( RNS2_BerkleyBindParameters *bindParameters, const char *file, unsigned int line );
	RNS2BindResult BindSharedIPV4( RNS2_BerkleyBindParameters *bindParameters, const char *file, unsigned int line );
	RNS2BindResult BindSharedIPV4And6( RNS2_BerkleyBindParameters *bindParameters, const char *file, unsigned int line );
	
	static void GetSystemAddressIPV4 ( RNS2Socket rns2Socket, SystemAddress *systemAddressOut );
	static void GetSystemAddressIPV4And6 ( RNS2Socket rns2Socket, SystemAddress *systemAddressOut );

	// Internal
	void SetNonBlockingSocket(unsigned long nonblocking);
	void SetSocketOptions(void);
	void SetBroadcastSocket(int broadcast);
	void SetIPHdrIncl(int ipHdrIncl);
	void RecvFromBlocking(RNS2RecvStruct *recvFromStruct);
	void RecvFromBlockingIPV4(RNS2RecvStruct *recvFromStruct);
	void RecvFromBlockingIPV4And6(RNS2RecvStruct *recvFromStruct);

	RNS2Socket rns2Socket;
	RNS2_BerkleyBindParameters binding;

	unsigned RecvFromLoopInt(void);
	RakNet::LocklessUint32_t isRecvFromLoopThreadActive;
	volatile bool endThreads;
	// Constructor not called!

#if defined(__APPLE__)
	// http://sourceforge.net/p/open-dis/discussion/683284/thread/0929d6a0
	CFSocketRef             _cfSocket;
#endif

	static RAK_THREAD_DECLARATION(RecvFromLoop);
};

#if 1 || defined(__GNUC__)  || defined(__GCCXML__) || defined(__S3E__)
class RNS2_Windows_Linux_360
{
public:
protected:
	static RNS2SendResult Send_Windows_Linux_360NoVDP( RNS2Socket rns2Socket, RNS2_SendParameters *sendParameters, const char *file, unsigned int line );
};
#endif


#if   1

class RAK_DLL_EXPORT SocketLayerOverride
{
public:
	SocketLayerOverride() {}
	virtual ~SocketLayerOverride() {}

	/// Called when SendTo would otherwise occur.
	virtual int RakNetSendTo( const char *data, int length, const SystemAddress &systemAddress )=0;

	/// Called when RecvFrom would otherwise occur. Return number of bytes read. Write data into dataOut
	// Return -1 to use RakNet's normal recvfrom, 0 to abort RakNet's normal recvfrom, and positive to return data
	virtual int RakNetRecvFrom( char dataOut[ MAXIMUM_MTU_SIZE ], SystemAddress *senderOut, bool calledFromMainThread )=0;
};

class RNS2_Windows : public RNS2_Berkley, public RNS2_Windows_Linux_360
{
public:
	RNS2_Windows();
	virtual ~RNS2_Windows();
	RNS2BindResult Bind( RNS2_BerkleyBindParameters *bindParameters, const char *file, unsigned int line );
	RNS2SendResult Send( RNS2_SendParameters *sendParameters, const char *file, unsigned int line );
	void SetSocketLayerOverride(SocketLayerOverride *_slo);
	SocketLayerOverride* GetSocketLayerOverride(void);
	// ----------- STATICS ------------
	static void GetMyIP( SystemAddress addresses[MAXIMUM_NUMBER_OF_INTERNAL_IDS] );
protected:
	static void GetMyIPIPV4( SystemAddress addresses[MAXIMUM_NUMBER_OF_INTERNAL_IDS] );
	static void GetMyIPIPV4And6( SystemAddress addresses[MAXIMUM_NUMBER_OF_INTERNAL_IDS] );
	SocketLayerOverride *slo;
};

#else

#endif // Linux

#endif // #elif !defined(WINDOWS_STORE_RT)

} // namespace RakNet

#endif // __RAKNET_SOCKET_2_H