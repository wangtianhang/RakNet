/*
 *  Copyright (c) 2014, Oculus VR, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// \file
//
#define CAT_NEUTER_EXPORT /* Neuter dllimport for libcat */

#include "RakNetDefines.h"
#include "RakPeer.h"
#include "RakNetTypes.h"

#if 1

#else
#include <unistd.h>
#endif

// #if defined(new)
// #pragma push_macro("new")
// #undef new
// #define RMO_NEW_UNDEF_ALLOCATING_QUEUE
// #endif

#include <time.h>
#include <ctype.h> // toupper
#include <string.h>
#include "GetTime.h"
#include "MessageIdentifiers.h"
#include "DS_HuffmanEncodingTree.h"
#include "Rand.h"
//#include "PluginInterface2.h"
#include "StringCompressor.h"
#include "StringTable.h"
//#include "NetworkIDObject.h"
#include "RakNetTypes.h"
#include "DR_SHA1.h"
#include "RakSleep.h"
#include "RakAssert.h"
#include "RakNetVersion.h"
//#include "NetworkIDManager.h"
#include "gettimeofday.h"
#include "SignaledEvent.h"
#include "SuperFastHash.h"
#include "RakAlloca.h"
#include "WSAStartupSingleton.h"

#ifdef USE_THREADED_SEND
#include "SendToThread.h"
#endif

#ifdef CAT_AUDIT
#define CAT_AUDIT_PRINTF(...) printf(__VA_ARGS__)
#else
#define CAT_AUDIT_PRINTF(...)
#endif

namespace RakNet
{
RAK_THREAD_DECLARATION(UpdateNetworkLoop);
RAK_THREAD_DECLARATION(RecvFromLoop);
RAK_THREAD_DECLARATION(UDTConnect);
}
#define REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE 8

#if !defined ( __APPLE__ ) && !defined ( __APPLE_CC__ )
#include <stdlib.h> // malloc
#endif


static const int NUM_MTU_SIZES=3;

static const int mtuSizes[NUM_MTU_SIZES]={MAXIMUM_MTU_SIZE, 1200, 576};


// Note to self - if I change this it might affect RECIPIENT_OFFLINE_MESSAGE_INTERVAL in Natpunchthrough.cpp
//static const int MAX_OPEN_CONNECTION_REQUESTS=8;
//static const int TIME_BETWEEN_OPEN_CONNECTION_REQUESTS=500;

#ifdef _MSC_VER
#pragma warning( push )
#endif

using namespace RakNet;

static RakNetRandom rnr;


static const unsigned int MAX_OFFLINE_DATA_LENGTH=400; // I set this because I limit ID_CONNECTION_REQUEST to 512 bytes, and the password is appended to that packet.

// Used to distinguish between offline messages with data, and messages from the reliability layer
// Should be different than any message that could result from messages from the reliability layer
#if  !defined(__GNUC__)
#pragma warning(disable:4309) // 'initializing' : truncation of constant value
#endif
// Make sure highest bit is 0, so isValid in DatagramHeaderFormat is false
static const unsigned char OFFLINE_MESSAGE_DATA_ID[16]={0x00,0xFF,0xFF,0x00,0xFE,0xFE,0xFE,0xFE,0xFD,0xFD,0xFD,0xFD,0x12,0x34,0x56,0x78};

struct PacketFollowedByData
{
	Packet p;
	unsigned char data[1];
};

Packet *RakPeer::AllocPacket(unsigned dataSize, const char *file, unsigned int line)
{
	RakNet::Packet *p;
	packetAllocationPoolMutex.Lock();
	p = packetAllocationPool.Allocate(file,line);
	packetAllocationPoolMutex.Unlock();
	p = new ((void*)p) Packet;
	p->data=(unsigned char*) rakMalloc_Ex(dataSize,file,line);
	p->length=dataSize;
	p->bitSize=BYTES_TO_BITS(dataSize);
	p->deleteData=true;
	p->guid=UNASSIGNED_RAKNET_GUID;
	p->wasGeneratedLocally=false;
	return p;
}

Packet *RakPeer::AllocPacket(unsigned dataSize, unsigned char *data, const char *file, unsigned int line)
{
	// Packet *p = (Packet *)rakMalloc_Ex(sizeof(Packet), file, line);
	RakNet::Packet *p;
	packetAllocationPoolMutex.Lock();
	p = packetAllocationPool.Allocate(file,line);
	packetAllocationPoolMutex.Unlock();
	p = new ((void*)p) Packet;
	RakAssert(p);
	p->data=data;
	p->length=dataSize;
	p->bitSize=BYTES_TO_BITS(dataSize);
	p->deleteData=true;
	p->guid=UNASSIGNED_RAKNET_GUID;
	p->wasGeneratedLocally=false;
	return p;
}

STATIC_FACTORY_DEFINITIONS(RakPeerInterface,RakPeer) 

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Constructor
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RakPeer()
{
#if LIBCAT_SECURITY==1

#endif

	StringCompressor::AddReference();
	RakNet::StringTable::AddReference();
	WSAStartupSingleton::AddRef();

	defaultMTUSize = mtuSizes[NUM_MTU_SIZES-1];
	trackFrequencyTable = false;
	maximumIncomingConnections = 0;
	maximumNumberOfPeers = 0;
	//remoteSystemListSize=0;
	remoteSystemList = 0;
	activeSystemList = 0;
	activeSystemListSize=0;
	remoteSystemLookup=0;
	bytesSentPerSecond = bytesReceivedPerSecond = 0;
	endThreads = true;
	isMainLoopThreadActive = false;
	//incomingDatagramEventHandler=0;

	// isRecvfromThreadActive=false;
#if defined(GET_TIME_SPIKE_LIMIT) && GET_TIME_SPIKE_LIMIT>0
	occasionalPing = true;
#else
	occasionalPing = false;
#endif
	//allowInternalRouting=false;
	for (unsigned int i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
		ipList[i]=UNASSIGNED_SYSTEM_ADDRESS;
	allowConnectionResponseIPMigration = false;
	//incomingPasswordLength=outgoingPasswordLength=0;
	incomingPasswordLength=0;
	splitMessageProgressInterval=0;
	//unreliableTimeout=0;
	unreliableTimeout=1000;
	maxOutgoingBPS=0;
	firstExternalID=UNASSIGNED_SYSTEM_ADDRESS;
	myGuid=UNASSIGNED_RAKNET_GUID;
	//userUpdateThreadPtr=0;
	//userUpdateThreadData=0;

	defaultTimeoutTime=10000;

	bufferedCommands.SetPageSize(sizeof(BufferedCommandStruct)*16);
	socketQueryOutput.SetPageSize(sizeof(SocketQueryOutput)*8);

	packetAllocationPoolMutex.Lock();
	packetAllocationPool.SetPageSize(sizeof(DataStructures::MemoryPool<Packet>::MemoryWithPage)*32);
	packetAllocationPoolMutex.Unlock();

	remoteSystemIndexPool.SetPageSize(sizeof(DataStructures::MemoryPool<RemoteSystemIndex>::MemoryWithPage)*32);

	GenerateGUID();

	quitAndDataEvents.InitEvent();
	limitConnectionFrequencyFromTheSameIP=false;
	ResetSendReceipt();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Destructor
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::~RakPeer()
{
	Shutdown( 0, 0 );

	// Free the ban list.
	//ClearBanList();

	StringCompressor::RemoveReference();
	RakNet::StringTable::RemoveReference();
	WSAStartupSingleton::Deref();

	quitAndDataEvents.CloseEvent();

#if LIBCAT_SECURITY==1

#endif

}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// \brief Starts the network threads, opens the listen port.
// You must call this before calling Connect().
// Multiple calls while already active are ignored.  To call this function again with different settings, you must first call Shutdown().
// \note Call SetMaximumIncomingConnections if you want to accept incoming connections
// \param[in] maxConnections The maximum number of connections between this instance of RakPeer and another instance of RakPeer. Required so the network can preallocate and for thread safety. A pure client would set this to 1.  A pure server would set it to the number of allowed clients.- A hybrid would set it to the sum of both types of connections
// \param[in] localPort The port to listen for connections on.
// \param[in] _threadSleepTimer How many ms to Sleep each internal update cycle. With new congestion control, the best results will be obtained by passing 10.
// \param[in] socketDescriptors An array of SocketDescriptor structures to force RakNet to listen on a particular IP address or port (or both).  Each SocketDescriptor will represent one unique socket.  Do not pass redundant structures.  To listen on a specific port, you can pass &socketDescriptor, 1SocketDescriptor(myPort,0); such as for a server.  For a client, it is usually OK to just pass SocketDescriptor();
// \param[in] socketDescriptorCount The size of the \a socketDescriptors array.  Pass 1 if you are not sure what to pass.
// \return False on failure (can't create socket or thread), true on success.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
StartupResult RakPeer::Startup( unsigned int maxConnections, SocketDescriptor *socketDescriptors, unsigned socketDescriptorCount, int threadPriority )
{
	if (IsActive())
		return RAKNET_ALREADY_STARTED;

	// If getting the guid failed in the constructor, try again
	if (myGuid.g==0)
	{
		GenerateGUID();
		if (myGuid.g==0)
			return COULD_NOT_GENERATE_GUID;
	}

	if (threadPriority==-99999)
	{
		threadPriority=0;
	}


	FillIPList();

	if (myGuid==UNASSIGNED_RAKNET_GUID)
	{
		rnr.SeedMT( GenerateSeedFromGuid() );
	}

	RakAssert(socketDescriptors && socketDescriptorCount>=1);

	if (socketDescriptors==0 || socketDescriptorCount<1)
		return INVALID_SOCKET_DESCRIPTORS;

	RakAssert( maxConnections > 0 );

	if ( maxConnections <= 0 )
		return INVALID_MAX_CONNECTIONS;

	DerefAllSockets();


	int i;
	// Go through all socket descriptors and precreate sockets on the specified addresses
	for (i=0; i<socketDescriptorCount; i++)
	{

		RakNetSocket2 *r2 = RakNetSocket2Allocator::AllocRNS2();
		r2->SetUserConnectionSocketIndex(i);
		#if defined(__native_client__)

		#elif defined(WINDOWS_STORE_RT)

		#else
		if (r2->IsBerkleySocket())
		{
			RNS2_BerkleyBindParameters bbp;
			bbp.port=socketDescriptors[i].port;
			bbp.hostAddress=(char*) socketDescriptors[i].hostAddress;
			bbp.addressFamily=socketDescriptors[i].socketFamily;
			bbp.type=SOCK_DGRAM;
			bbp.protocol=socketDescriptors[i].extraSocketOptions;
			bbp.nonBlockingSocket=false;
			bbp.setBroadcast=true;
			bbp.setIPHdrIncl=false;
			bbp.doNotFragment=false;
			bbp.pollingThreadPriority=threadPriority;
			bbp.eventHandler=this;
			bbp.remotePortRakNetWasStartedOn_PS3_PS4_PSP2=socketDescriptors[i].remotePortRakNetWasStartedOn_PS3_PSP2;
			RNS2BindResult br = ((RNS2_Berkley*) r2)->Bind(&bbp, _FILE_AND_LINE_);

			if (
			#if RAKNET_SUPPORT_IPV6==0
				socketDescriptors[i].socketFamily!=AF_INET ||
			#endif
				br==BR_REQUIRES_RAKNET_SUPPORT_IPV6_DEFINE)
			{
				RakNetSocket2Allocator::DeallocRNS2(r2);
				DerefAllSockets();
				return SOCKET_FAMILY_NOT_SUPPORTED;
			}
			else if (br==BR_FAILED_TO_BIND_SOCKET)
			{
				RakNetSocket2Allocator::DeallocRNS2(r2);
				DerefAllSockets();
				return SOCKET_PORT_ALREADY_IN_USE;
			}
			else if (br==BR_FAILED_SEND_TEST)
			{
				RakNetSocket2Allocator::DeallocRNS2(r2);
				DerefAllSockets();
				return SOCKET_FAILED_TEST_SEND;
			}
			else
			{
				RakAssert(br==BR_SUCCESS);
			}
		}
		else
		{
			RakAssert("TODO" && 0);
		}
		#endif

		socketList.Push(r2, _FILE_AND_LINE_ );

	}

#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
	for (i=0; i<socketDescriptorCount; i++)
	{
		if (socketList[i]->IsBerkleySocket())
			((RNS2_Berkley*) socketList[i])->CreateRecvPollingThread(threadPriority);
	}
#endif

// #if !defined(_XBOX) && !defined(_XBOX_720_COMPILE_AS_WINDOWS) && !defined(X360)
	for (i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
	{
		if (ipList[i]==UNASSIGNED_SYSTEM_ADDRESS)
			break;
#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
		if (socketList[0]->IsBerkleySocket())
		{
			unsigned short port = ((RNS2_Berkley*)socketList[0])->GetBoundAddress().GetPort();
			ipList[i].SetPortHostOrder(port);

		}
#endif
// 		ipList[i].SetPort(((RNS2_360_720*)socketList[0])->GetBoundAddress().GetPort());
	}
// #endif


	if ( maximumNumberOfPeers == 0 )
	{
		// Don't allow more incoming connections than we have peers.
		if ( maximumIncomingConnections > maxConnections )
			maximumIncomingConnections = maxConnections;

		maximumNumberOfPeers = maxConnections;
		// 04/19/2006 - Don't overallocate because I'm no longer allowing connected pings.
		// The disconnects are not consistently processed and the process was sloppy and complicated.
		// Allocate 10% extra to handle new connections from players trying to connect when the server is full
		//remoteSystemListSize = maxConnections;// * 11 / 10 + 1;

		// remoteSystemList in Single thread
		//remoteSystemList = RakNet::OP_NEW<RemoteSystemStruct[ remoteSystemListSize ]>( _FILE_AND_LINE_ );
		remoteSystemList = RakNet::OP_NEW_ARRAY<RemoteSystemStruct>(maximumNumberOfPeers, _FILE_AND_LINE_ );

		remoteSystemLookup = RakNet::OP_NEW_ARRAY<RemoteSystemIndex*>((unsigned int) maximumNumberOfPeers * REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE, _FILE_AND_LINE_ );

		activeSystemList = RakNet::OP_NEW_ARRAY<RemoteSystemStruct*>(maximumNumberOfPeers, _FILE_AND_LINE_ );

		for ( i = 0; i < maximumNumberOfPeers; i++ )
		//for ( i = 0; i < remoteSystemListSize; i++ )
		{
			// remoteSystemList in Single thread
			remoteSystemList[ i ].isActive = false;
			remoteSystemList[ i ].systemAddress = UNASSIGNED_SYSTEM_ADDRESS;
			remoteSystemList[ i ].guid = UNASSIGNED_RAKNET_GUID;
			remoteSystemList[ i ].myExternalSystemAddress = UNASSIGNED_SYSTEM_ADDRESS;
			remoteSystemList[ i ].connectMode=RemoteSystemStruct::NO_ACTION;
			remoteSystemList[ i ].MTUSize = defaultMTUSize;
			remoteSystemList[ i ].remoteSystemIndex = (SystemIndex) i;
// #ifdef _DEBUG
// 			remoteSystemList[ i ].reliabilityLayer.ApplyNetworkSimulator(_packetloss, _minExtraPing, _extraPingVariance);
// #endif

			// All entries in activeSystemList have valid pointers all the time.
			activeSystemList[ i ] = &remoteSystemList[ i ];
		}

		for (unsigned int i=0; i < (unsigned int) maximumNumberOfPeers*REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE; i++)
		{
			remoteSystemLookup[i]=0;
		}
	}

	// For histogram statistics
	// nextReadBytesTime=0;
	// lastSentBytes=lastReceivedBytes=0;

	if ( endThreads )
	{
		updateCycleIsRunning = false;
		endThreads = false;
		firstExternalID=UNASSIGNED_SYSTEM_ADDRESS;

		ClearBufferedCommands();
		ClearBufferedPackets();
		ClearSocketQueryOutput();

		if ( isMainLoopThreadActive == false )
		{
#if RAKPEER_USER_THREADED!=1

			int errorCode;

					errorCode = RakNet::RakThread::Create(UpdateNetworkLoop, this, threadPriority);


					if ( errorCode != 0 )
					{
						Shutdown( 0, 0 );
						return FAILED_TO_CREATE_NETWORK_THREAD;
					}
//					RakAssert(isRecvFromLoopThreadActive.GetValue()==0);
#endif // RAKPEER_USER_THREADED!=1

				}

#if RAKPEER_USER_THREADED!=1
		// Wait for the threads to activate.  When they are active they will set these variables to true
		while (  isMainLoopThreadActive == false )
			RakSleep(10);
#endif // RAKPEER_USER_THREADED!=1
	}

#ifdef USE_THREADED_SEND
	RakNet::SendToThread::AddRef();
#endif

	return RAKNET_STARTED;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Sets how many incoming connections are allowed.  If this is less than the number of players currently connected, no
// more players will be allowed to connect.  If this is greater than the maximum number of peers allowed, it will be reduced
// to the maximum number of peers allowed.  Defaults to 0.
//
// Parameters:
// numberAllowed - Maximum number of incoming connections allowed.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetMaximumIncomingConnections( unsigned short numberAllowed )
{
	maximumIncomingConnections = numberAllowed;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns the maximum number of incoming connections, which is always <= maxConnections
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetMaximumIncomingConnections( void ) const
{
	return maximumIncomingConnections;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Returns how many open connections there are at this time
// \return the number of open connections
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned short RakPeer::NumberOfConnections(void) const
{
	DataStructures::List<SystemAddress> addresses;
	DataStructures::List<RakNetGUID> guids;
	GetSystemList(addresses, guids);
	return (unsigned short) addresses.Size();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Call this to connect to the specified host (ip or domain name) and server port.
// Calling Connect and not calling SetMaximumIncomingConnections acts as a dedicated client.  Calling both acts as a true peer.
// This is a non-blocking connection.  You know the connection is successful when IsConnected() returns true
// or receive gets a packet with the type identifier ID_CONNECTION_REQUEST_ACCEPTED.  If the connection is not
// successful, such as rejected connection or no response then neither of these things will happen.
// Requires that you first call Initialize
//
// Parameters:
// host: Either a dotted IP address or a domain name
// remotePort: Which port to connect to on the remote machine.
// passwordData: A data block that must match the data block on the server.  This can be just a password, or can be a stream of data
// passwordDataLength: The length in bytes of passwordData
//
// Returns:
// True on successful initiation. False on incorrect parameters, internal error, or too many existing peers
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ConnectionAttemptResult RakPeer::Connect( const char* host, unsigned short remotePort, const char *passwordData, int passwordDataLength, PublicKey *publicKey, unsigned connectionSocketIndex, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime )
{
	// If endThreads is true here you didn't call Startup() first.
	if ( host == 0 || endThreads || connectionSocketIndex>=socketList.Size() )
		return INVALID_PARAMETER;

	RakAssert(remotePort!=0);

	connectionSocketIndex=GetRakNetSocketFromUserConnectionSocketIndex(connectionSocketIndex);

	if (passwordDataLength>255)
		passwordDataLength=255;

	if (passwordData==0)
		passwordDataLength=0;

	// Not threadsafe but it's not important enough to lock.  Who is going to change the password a lot during runtime?
	// It won't overflow at least because outgoingPasswordLength is an unsigned char
//	if (passwordDataLength>0)
//		memcpy(outgoingPassword, passwordData, passwordDataLength);
//	outgoingPasswordLength=(unsigned char) passwordDataLength;

	// 04/02/09 - Can't remember why I disabled connecting to self, but it seems to work
	// Connecting to ourselves in the same instance of the program?
//	if ( ( strcmp( host, "127.0.0.1" ) == 0 || strcmp( host, "0.0.0.0" ) == 0 ) && remotePort == mySystemAddress[0].port )
//		return false;

	return SendConnectionRequest( host, remotePort, passwordData, passwordDataLength, publicKey, connectionSocketIndex, 0, sendConnectionAttemptCount, timeBetweenSendConnectionAttemptsMS, timeoutTime);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Stops the network threads and close all connections.  Multiple calls are ok.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::Shutdown( unsigned int blockDuration, unsigned char orderingChannel, PacketPriority disconnectionNotificationPriority )
{
	unsigned i,j;
	bool anyActive;
	RakNet::TimeMS startWaitingTime;
//	SystemAddress systemAddress;
	RakNet::TimeMS time;
	//unsigned short systemListSize = remoteSystemListSize; // This is done for threading reasons
	unsigned int systemListSize = maximumNumberOfPeers;

	if ( blockDuration > 0 )
	{
		for ( i = 0; i < systemListSize; i++ )
		{
			// remoteSystemList in user thread
			if (remoteSystemList[i].isActive)
				NotifyAndFlagForShutdown(remoteSystemList[i].systemAddress, false, orderingChannel, disconnectionNotificationPriority);
		}

		time = RakNet::GetTimeMS();
		startWaitingTime = time;
		while ( time - startWaitingTime < blockDuration )
		{
			anyActive=false;
			for (j=0; j < systemListSize; j++)
			{
				// remoteSystemList in user thread
				if (remoteSystemList[j].isActive)
				{
					anyActive=true;
					break;
				}
			}

			// If this system is out of packets to send, then stop waiting
			if ( anyActive==false )
				break;

			// This will probably cause the update thread to run which will probably
			// send the disconnection notification

			RakSleep(15);
			time = RakNet::GetTimeMS();
		}
	}

	activeSystemListSize=0;

	quitAndDataEvents.SetEvent();

	endThreads = true;

//	RakNet::TimeMS timeout;
#if RAKPEER_USER_THREADED!=1

#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
	for (i=0; i < socketList.Size(); i++)
	{
		if (socketList[i]->IsBerkleySocket())
		{
			((RNS2_Berkley *)socketList[i])->SignalStopRecvPollingThread();
		}
	}
#endif

	while ( isMainLoopThreadActive )
	{
		endThreads = true;
		RakSleep(15);
	}

#if !defined(__native_client__) && !defined(WINDOWS_STORE_RT)
	for (i=0; i < socketList.Size(); i++)
	{
		if (socketList[i]->IsBerkleySocket())
		{
			((RNS2_Berkley *)socketList[i])->BlockOnStopRecvPollingThread();
		}
	}
#endif


#endif // RAKPEER_USER_THREADED!=1

//	char c=0;
//	unsigned int socketIndex;
	// remoteSystemList in Single thread
	for ( i = 0; i < systemListSize; i++ )
	{
		// Reserve this reliability layer for ourselves
		remoteSystemList[ i ].isActive = false;

		// Remove any remaining packets
		RakAssert(remoteSystemList[ i ].MTUSize <= MAXIMUM_MTU_SIZE);
		remoteSystemList[ i ].reliabilityLayer.Reset(false, remoteSystemList[ i ].MTUSize, false);
		remoteSystemList[ i ].rakNetSocket = 0;
	}


	// Setting maximumNumberOfPeers to 0 allows remoteSystemList to be reallocated in Initialize.
	// Setting remoteSystemListSize prevents threads from accessing the reliability layer
	maximumNumberOfPeers = 0;
	//remoteSystemListSize = 0;

	// Free any packets the user didn't deallocate
	packetReturnMutex.Lock();
	for (i=0; i < packetReturnQueue.Size(); i++)
		DeallocatePacket(packetReturnQueue[i]);
	packetReturnQueue.Clear(_FILE_AND_LINE_);
	packetReturnMutex.Unlock();
	packetAllocationPoolMutex.Lock();
	packetAllocationPool.Clear(_FILE_AND_LINE_);
	packetAllocationPoolMutex.Unlock();

	DerefAllSockets();

	ClearBufferedCommands();
	ClearBufferedPackets();
	ClearSocketQueryOutput();
	bytesSentPerSecond = bytesReceivedPerSecond = 0;

	ClearRequestedConnectionList();


	// Clear out the reliability layer list in case we want to reallocate it in a successive call to Init.
	RemoteSystemStruct * temp = remoteSystemList;
	remoteSystemList = 0;
	RakNet::OP_DELETE_ARRAY(temp, _FILE_AND_LINE_);
	RakNet::OP_DELETE_ARRAY(activeSystemList, _FILE_AND_LINE_);
	activeSystemList=0;

	ClearRemoteSystemLookup();

#ifdef USE_THREADED_SEND
	RakNet::SendToThread::Deref();
#endif

	ResetSendReceipt();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Returns true if the network threads are running
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
inline bool RakPeer::IsActive( void ) const
{
	return endThreads == false;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Fills the array remoteSystems with the systemAddress of all the systems we are connected to
//
// Parameters:
// remoteSystems (out): An array of SystemAddress structures to be filled with the SystemAddresss of the systems we are connected to
// - pass 0 to remoteSystems to only get the number of systems we are connected to
// numberOfSystems (int, out): As input, the size of remoteSystems array.  As output, the number of elements put into the array
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::GetConnectionList( SystemAddress *remoteSystems, unsigned short *numberOfSystems ) const
{
	if (numberOfSystems==0)
		return false;

	if ( remoteSystemList == 0 || endThreads == true )
	{
		if (numberOfSystems)
			*numberOfSystems=0;
		return false;
	}

	DataStructures::List<SystemAddress> addresses;
	DataStructures::List<RakNetGUID> guids;
	GetSystemList(addresses, guids);
	if (remoteSystems)
	{
		unsigned short i;
		for (i=0; i < *numberOfSystems && i < addresses.Size(); i++)
			remoteSystems[i]=addresses[i];
		*numberOfSystems=i;
	}
	else
	{
		*numberOfSystems=(unsigned short) addresses.Size();
	}
	return true;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
uint32_t RakPeer::IncrementNextSendReceipt(void)
{
	sendReceiptSerialMutex.Lock();
	uint32_t returned = sendReceiptSerial;
	if (++sendReceiptSerial==0)
		sendReceiptSerial=1;
	sendReceiptSerialMutex.Unlock();
	return returned;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Sends a block of data to the specified system that you are connected to.
// This function only works while the client is connected (Use the Connect function).
// The first byte should be a message identifier starting at ID_USER_PACKET_ENUM
//
// Parameters:
// data: The block of data to send
// length: The size in bytes of the data to send
// bitStream: The bitstream to send
// priority: What priority level to send on.
// reliability: How reliability to send this data
// orderingChannel: When using ordered or sequenced packets, what channel to order these on.
// - Packets are only ordered relative to other packets on the same stream
// systemAddress: Who to send this packet to, or in the case of broadcasting who not to send it to. Use UNASSIGNED_SYSTEM_ADDRESS to specify none
// broadcast: True to send this packet to all connected systems.  If true, then systemAddress specifies who not to send the packet to.
// Returns:
// \return 0 on bad input. Otherwise a number that identifies this message. If \a reliability is a type that returns a receipt, on a later call to Receive() you will get ID_SND_RECEIPT_ACKED or ID_SND_RECEIPT_LOSS with bytes 1-4 inclusive containing this number
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// uint32_t RakPeer::Send( const char *data, const int length, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, uint32_t forceReceiptNumber )
// {
// #ifdef _DEBUG
// 	RakAssert( data && length > 0 );
// #endif
// 	RakAssert( !( reliability >= NUMBER_OF_RELIABILITIES || reliability < 0 ) );
// 	RakAssert( !( priority > NUMBER_OF_PRIORITIES || priority < 0 ) );
// 	RakAssert( !( orderingChannel >= NUMBER_OF_ORDERED_STREAMS ) );
// 
// 	if ( data == 0 || length < 0 )
// 		return 0;
// 
// 	if ( remoteSystemList == 0 || endThreads == true )
// 		return 0;
// 
// 	if ( broadcast == false && systemIdentifier.IsUndefined())
// 		return 0;
// 
// 	uint32_t usedSendReceipt;
// 	if (forceReceiptNumber!=0)
// 		usedSendReceipt=forceReceiptNumber;
// 	else
// 		usedSendReceipt=IncrementNextSendReceipt();
// 
// 	if (broadcast==false && IsLoopbackAddress(systemIdentifier,true))
// 	{
// 		SendLoopback(data,length);
// 
// 		if (reliability>=UNRELIABLE_WITH_ACK_RECEIPT)
// 		{
// 			char buff[5];
// 			buff[0]=ID_SND_RECEIPT_ACKED;
// 			sendReceiptSerialMutex.Lock();
// 			memcpy(buff+1, &sendReceiptSerial, 4);
// 			sendReceiptSerialMutex.Unlock();
// 			SendLoopback( buff, 5 );
// 		}
// 
// 		return usedSendReceipt;
// 	}
// 
// 	SendBuffered(data, length*8, priority, reliability, orderingChannel, systemIdentifier, broadcast, RemoteSystemStruct::NO_ACTION, usedSendReceipt);
// 
// 	return usedSendReceipt;
// }

// void RakPeer::SendLoopback( const char *data, const int length )
// {
// 	if ( data == 0 || length < 0 )
// 		return;
// 
// 	Packet *packet = AllocPacket(length, _FILE_AND_LINE_);
// 	memcpy(packet->data, data, length);
// 	packet->systemAddress = GetLoopbackAddress();
// 	packet->guid=myGuid;
// 	PushBackPacket(packet, false);
// }

uint32_t RakPeer::Send( const RakNet::BitStream * bitStream, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, uint32_t forceReceiptNumber )
{

	RakAssert( !( reliability >= NUMBER_OF_RELIABILITIES || reliability < 0 ) );
	RakAssert( !( priority > NUMBER_OF_PRIORITIES || priority < 0 ) );
	RakAssert( !( orderingChannel >= NUMBER_OF_ORDERED_STREAMS ) );

	if ( bitStream->GetNumberOfBytesUsed() == 0 )
		return 0;

	if ( remoteSystemList == 0 || endThreads == true )
		return 0;

	if ( broadcast == false && systemIdentifier.IsUndefined() )
		return 0;

	uint32_t usedSendReceipt;
	if (forceReceiptNumber!=0)
		usedSendReceipt=forceReceiptNumber;
	else
		usedSendReceipt=IncrementNextSendReceipt();

// 	if (broadcast==false && IsLoopbackAddress(systemIdentifier,true))
// 	{
// 		SendLoopback((const char*) bitStream->GetData(),bitStream->GetNumberOfBytesUsed());
// 		if (reliability>=UNRELIABLE_WITH_ACK_RECEIPT)
// 		{
// 			char buff[5];
// 			buff[0]=ID_SND_RECEIPT_ACKED;
// 			sendReceiptSerialMutex.Lock();
// 			memcpy(buff+1, &sendReceiptSerial,4);
// 			sendReceiptSerialMutex.Unlock();
// 			SendLoopback( buff, 5 );
// 		}
// 		return usedSendReceipt;
// 	}

	// Sends need to be buffered and processed in the update thread because the systemAddress associated with the reliability layer can change,
	// from that thread, resulting in a send to the wrong player!  While I could mutex the systemAddress, that is much slower than doing this
	SendBuffered((const char*)bitStream->GetData(), bitStream->GetNumberOfBitsUsed(), priority, reliability, orderingChannel, systemIdentifier, broadcast, RemoteSystemStruct::NO_ACTION, usedSendReceipt);


	return usedSendReceipt;
}


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Gets a packet from the incoming packet queue. Use DeallocatePacket to deallocate the packet after you are done with it.
// Check the Packet struct at the top of CoreNetworkStructures.h for the format of the struct
//
// Returns:
// 0 if no packets are waiting to be handled, otherwise an allocated packet
// If the client is not active this will also return 0, as all waiting packets are flushed when the client is Disconnected
// This also updates all memory blocks associated with synchronized memory and distributed objects
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#ifdef _MSC_VER
#pragma warning( disable : 4701 ) // warning C4701: local variable <variable name> may be used without having been initialized
#endif
Packet* RakPeer::Receive( void )
{
	if ( !( IsActive() ) )
		return 0;

	RakNet::Packet *packet;
//	Packet **threadPacket;
//	PluginReceiveResult pluginResult;

	int offset;
	unsigned int i;

	do
	{
		packetReturnMutex.Lock();
		if (packetReturnQueue.IsEmpty())
			packet=0;
		else
			packet = packetReturnQueue.Pop();
		packetReturnMutex.Unlock();
		if (packet==0)
			return 0;

//		unsigned char msgId;
		if ( ( packet->length >= sizeof(unsigned char) + sizeof( RakNet::Time ) ) &&
			( (unsigned char) packet->data[ 0 ] == ID_TIMESTAMP ) )
		{
			offset = sizeof(unsigned char);
			ShiftIncomingTimestamp( packet->data + offset, packet->systemAddress );
//			msgId=packet->data[sizeof(unsigned char) + sizeof( RakNet::Time )];
		}
//		else
	//		msgId=packet->data[0];
	
	} while(packet==0);

	return packet;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Call this to deallocate a packet returned by Receive
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::DeallocatePacket( Packet *packet )
{
	if ( packet == 0 )
		return;

	if (packet->deleteData)
	{
		rakFree_Ex(packet->data, _FILE_AND_LINE_ );
		packet->~Packet();
		packetAllocationPoolMutex.Lock();
		packetAllocationPool.Release(packet,_FILE_AND_LINE_);
		packetAllocationPoolMutex.Unlock();
	}
	else
	{
		rakFree_Ex(packet, _FILE_AND_LINE_ );
	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Return the total number of connections we are allowed
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetMaximumNumberOfPeers( void ) const
{
	return maximumNumberOfPeers;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Close the connection to another host (if we initiated the connection it will disconnect, if they did it will kick them out).
//
// Parameters:
// target: Which connection to close
// sendDisconnectionNotification: True to send ID_DISCONNECTION_NOTIFICATION to the recipient. False to close it silently.
// channel: If blockDuration > 0, the disconnect packet will be sent on this channel
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::CloseConnection( const AddressOrGUID target, bool sendDisconnectionNotification, unsigned char orderingChannel, PacketPriority disconnectionNotificationPriority )
{
	CloseConnectionInternal(target, sendDisconnectionNotification, false, orderingChannel, disconnectionNotificationPriority);

	// 12/14/09 Return ID_CONNECTION_LOST when calling CloseConnection with sendDisconnectionNotification==false, elsewise it is never returned
	if (sendDisconnectionNotification==false && GetConnectionState(target)==IS_CONNECTED)
	{
		Packet *packet=AllocPacket(sizeof( char ), _FILE_AND_LINE_);
		packet->data[ 0 ] = ID_CONNECTION_LOST; // DeadConnection
		packet->guid = target.rakNetGuid==UNASSIGNED_RAKNET_GUID ? GetGuidFromSystemAddress(target.systemAddress) : target.rakNetGuid;
		packet->systemAddress = target.systemAddress==UNASSIGNED_SYSTEM_ADDRESS ? GetSystemAddressFromGuid(target.rakNetGuid) : target.systemAddress;
		packet->systemAddress.systemIndex = (SystemIndex) GetIndexFromSystemAddress(packet->systemAddress);
		packet->guid.systemIndex=packet->systemAddress.systemIndex;
		packet->wasGeneratedLocally=true; // else processed twice
		AddPacketToProducer(packet);
	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Cancel a pending connection attempt
// If we are already connected, the connection stays open
// \param[in] target Which system to cancel
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::CancelConnectionAttempt( const SystemAddress target )
{
	unsigned int i;

	// Cancel pending connection attempt, if there is one
	i=0;
	requestedConnectionQueueMutex.Lock();
	while (i < requestedConnectionQueue.Size())
	{
		if (requestedConnectionQueue[i]->systemAddress==target)
		{
#if LIBCAT_SECURITY==1
			CAT_AUDIT_PRINTF("AUDIT: Deleting requestedConnectionQueue %i client_handshake %x\n", i, requestedConnectionQueue[ i ]->client_handshake);
			RakNet::OP_DELETE(requestedConnectionQueue[i]->client_handshake, _FILE_AND_LINE_ );
#endif
			RakNet::OP_DELETE(requestedConnectionQueue[i], _FILE_AND_LINE_ );
			requestedConnectionQueue.RemoveAtIndex(i);
			break;
		}
		else
			i++;
	}
	requestedConnectionQueueMutex.Unlock();

}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef _MSC_VER
#pragma warning( disable : 4702 ) // warning C4702: unreachable code
#endif
ConnectionState RakPeer::GetConnectionState(const AddressOrGUID systemIdentifier)
{
	if (systemIdentifier.systemAddress!=UNASSIGNED_SYSTEM_ADDRESS)
	{
		unsigned int i=0;
		requestedConnectionQueueMutex.Lock();
		for (; i < requestedConnectionQueue.Size(); i++)
		{
			if (requestedConnectionQueue[i]->systemAddress==systemIdentifier.systemAddress)
			{
				requestedConnectionQueueMutex.Unlock();
				return IS_PENDING;
			}
		}
		requestedConnectionQueueMutex.Unlock();
	}

	int index;
	if (systemIdentifier.systemAddress!=UNASSIGNED_SYSTEM_ADDRESS)
	{
		index = GetIndexFromSystemAddress(systemIdentifier.systemAddress, false);
	}
	else
	{
		index = GetIndexFromGuid(systemIdentifier.rakNetGuid);
	}

	if (index==-1)
		return IS_NOT_CONNECTED;

	if (remoteSystemList[index].isActive==false)
		return IS_DISCONNECTED;

	switch (remoteSystemList[index].connectMode)
	{
	case RemoteSystemStruct::DISCONNECT_ASAP:
		return IS_DISCONNECTING;
	case RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY:
		return IS_SILENTLY_DISCONNECTING;
	case RemoteSystemStruct::DISCONNECT_ON_NO_ACK:
		return IS_DISCONNECTING;
	case RemoteSystemStruct::REQUESTED_CONNECTION:
		return IS_CONNECTING;
	case RemoteSystemStruct::HANDLING_CONNECTION_REQUEST:
		return IS_CONNECTING;
	case RemoteSystemStruct::UNVERIFIED_SENDER:
		return IS_CONNECTING;
	case RemoteSystemStruct::CONNECTED:
		return IS_CONNECTED;
    default:
		return IS_NOT_CONNECTED;
	}

	return IS_NOT_CONNECTED;
}


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Given a systemAddress, returns an index from 0 to the maximum number of players allowed - 1.
//
// Parameters
// systemAddress - The systemAddress to search for
//
// Returns
// An integer from 0 to the maximum number of peers -1, or -1 if that player is not found
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetIndexFromSystemAddress( const SystemAddress systemAddress ) const
{
	return GetIndexFromSystemAddress(systemAddress, false);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// This function is only useful for looping through all players.
//
// Parameters
// index - an integer between 0 and the maximum number of players allowed - 1.
//
// Returns
// A valid systemAddress or UNASSIGNED_SYSTEM_ADDRESS if no such player at that index
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SystemAddress RakPeer::GetSystemAddressFromIndex( unsigned int index )
{
	// remoteSystemList in user thread
	//if ( index >= 0 && index < remoteSystemListSize )
	if ( index < maximumNumberOfPeers )
		if (remoteSystemList[index].isActive && remoteSystemList[ index ].connectMode==RakPeer::RemoteSystemStruct::CONNECTED) // Don't give the user players that aren't fully connected, since sends will fail
			return remoteSystemList[ index ].systemAddress;

	return UNASSIGNED_SYSTEM_ADDRESS;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Same as GetSystemAddressFromIndex but returns RakNetGUID
// \param[in] index Index should range between 0 and the maximum number of players allowed - 1.
// \return The RakNetGUID
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakNetGUID RakPeer::GetGUIDFromIndex( unsigned int index )
{
	// remoteSystemList in user thread
	//if ( index >= 0 && index < remoteSystemListSize )
	if ( index < maximumNumberOfPeers )
		if (remoteSystemList[index].isActive && remoteSystemList[ index ].connectMode==RakPeer::RemoteSystemStruct::CONNECTED) // Don't give the user players that aren't fully connected, since sends will fail
			return remoteSystemList[ index ].guid;

	return UNASSIGNED_RAKNET_GUID;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Same as calling GetSystemAddressFromIndex and GetGUIDFromIndex for all systems, but more efficient
// Indices match each other, so \a addresses[0] and \a guids[0] refer to the same system
// \param[out] addresses All system addresses. Size of the list is the number of connections. Size of the list will match the size of the \a guids list.
// \param[out] guids All guids. Size of the list is the number of connections. Size of the list will match the size of the \a addresses list.
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::GetSystemList(DataStructures::List<SystemAddress> &addresses, DataStructures::List<RakNetGUID> &guids) const
{
	addresses.Clear(false, _FILE_AND_LINE_);
	guids.Clear(false, _FILE_AND_LINE_);

	if ( remoteSystemList == 0 || endThreads == true )
		return;

	unsigned int i;
	for (i=0; i < activeSystemListSize; i++)
	{
		if ((activeSystemList[i])->isActive &&
			(activeSystemList[i])->connectMode==RakPeer::RemoteSystemStruct::CONNECTED)
		{
			addresses.Push((activeSystemList[i])->systemAddress, _FILE_AND_LINE_ );
			guids.Push((activeSystemList[i])->guid, _FILE_AND_LINE_ );
		}
	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

RakNet::Time RakPeer::GetClockDifferentialInt(RemoteSystemStruct *remoteSystem) const
{
	int counter, lowestPingSoFar;
	RakNet::Time clockDifferential;

	lowestPingSoFar = 65535;

	clockDifferential = 0;

	for ( counter = 0; counter < PING_TIMES_ARRAY_SIZE; counter++ )
	{
		if ( remoteSystem->pingAndClockDifferential[ counter ].pingTime == 65535 )
			break;

		if ( remoteSystem->pingAndClockDifferential[ counter ].pingTime < lowestPingSoFar )
		{
			clockDifferential = remoteSystem->pingAndClockDifferential[ counter ].clockDifferential;
			lowestPingSoFar = remoteSystem->pingAndClockDifferential[ counter ].pingTime;
		}
	}

	return clockDifferential;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Description:
// Return the unique SystemAddress that represents you on the the network
// Note that unlike in previous versions, this is a struct and is not sequential
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
SystemAddress RakPeer::GetInternalID( const SystemAddress systemAddress, const int index ) const
{
	if (systemAddress==UNASSIGNED_SYSTEM_ADDRESS)
	{
		return ipList[index];
	}
	else
	{

//		SystemAddress returnValue;
		RemoteSystemStruct * remoteSystem = GetRemoteSystemFromSystemAddress( systemAddress, false, true );
		if (remoteSystem==0)
			return UNASSIGNED_SYSTEM_ADDRESS;

		return remoteSystem->theirInternalSystemAddress[index];

	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
/// \brief Sets your internal IP address, for platforms that do not support reading it, or to override a value
/// \param[in] systemAddress. The address to set. Use SystemAddress::FromString() if you want to use a dotted string
/// \param[in] index When you have multiple internal IDs, which index to set?
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetInternalID(SystemAddress systemAddress, int index)
{
	RakAssert(index >=0 && index < MAXIMUM_NUMBER_OF_INTERNAL_IDS);
	ipList[index]=systemAddress;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

const RakNetGUID& RakPeer::GetGuidFromSystemAddress( const SystemAddress input ) const
{
	if (input==UNASSIGNED_SYSTEM_ADDRESS)
		return myGuid;

	if (input.systemIndex!=(SystemIndex)-1 && input.systemIndex<maximumNumberOfPeers && remoteSystemList[ input.systemIndex ].systemAddress == input)
		return remoteSystemList[ input.systemIndex ].guid;

	unsigned int i;
	for ( i = 0; i < maximumNumberOfPeers; i++ )
	{
		if (remoteSystemList[ i ].systemAddress == input )
		{
			// Set the systemIndex so future lookups will be fast
			remoteSystemList[i].guid.systemIndex = (SystemIndex) i;

			return remoteSystemList[ i ].guid;
		}
	}

	return UNASSIGNED_RAKNET_GUID;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

unsigned int RakPeer::GetSystemIndexFromGuid( const RakNetGUID input ) const
{
	if (input==UNASSIGNED_RAKNET_GUID)
		return (unsigned int) -1;

	if (input==myGuid)
		return (unsigned int) -1;

	if (input.systemIndex!=(SystemIndex)-1 && input.systemIndex<maximumNumberOfPeers && remoteSystemList[ input.systemIndex ].guid == input)
		return input.systemIndex;

	unsigned int i;
	for ( i = 0; i < maximumNumberOfPeers; i++ )
	{
		if (remoteSystemList[ i ].guid == input )
		{
			// Set the systemIndex so future lookups will be fast
			remoteSystemList[i].guid.systemIndex = (SystemIndex) i;

			return i;
		}
	}

	return (unsigned int) -1;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

SystemAddress RakPeer::GetSystemAddressFromGuid( const RakNetGUID input ) const
{
	if (input==UNASSIGNED_RAKNET_GUID)
		return UNASSIGNED_SYSTEM_ADDRESS;

	if (input==myGuid)
		return GetInternalID(UNASSIGNED_SYSTEM_ADDRESS);

	if (input.systemIndex!=(SystemIndex)-1 && input.systemIndex<maximumNumberOfPeers && remoteSystemList[ input.systemIndex ].guid == input)
		return remoteSystemList[ input.systemIndex ].systemAddress;

	unsigned int i;
	for ( i = 0; i < maximumNumberOfPeers; i++ )
	{
		if (remoteSystemList[ i ].guid == input )
		{
			// Set the systemIndex so future lookups will be fast
			remoteSystemList[i].guid.systemIndex = (SystemIndex) i;

			return remoteSystemList[ i ].systemAddress;
		}
	}

	return UNASSIGNED_SYSTEM_ADDRESS;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Set the time, in MS, to use before considering ourselves disconnected after not being able to deliver a reliable packet
// \param[in] time Time, in MS
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetTimeoutTime( RakNet::TimeMS timeMS, const SystemAddress target )
{
	if (target==UNASSIGNED_SYSTEM_ADDRESS)
	{
		defaultTimeoutTime=timeMS;

		unsigned i;
		for ( i = 0; i < maximumNumberOfPeers; i++ )
		{
			if (remoteSystemList[ i ].isActive)
			{
				if ( remoteSystemList[ i ].isActive )
					remoteSystemList[ i ].reliabilityLayer.SetTimeoutTime(timeMS);
			}
		}
	}
	else
	{
		RemoteSystemStruct * remoteSystem = GetRemoteSystemFromSystemAddress( target, false, true );

		if ( remoteSystem != 0 )
			remoteSystem->reliabilityLayer.SetTimeoutTime(timeMS);
	}
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

RakNet::TimeMS RakPeer::GetTimeoutTime( const SystemAddress target )
{
	if (target==UNASSIGNED_SYSTEM_ADDRESS)
	{
		return defaultTimeoutTime;
	}
	else
	{
		RemoteSystemStruct * remoteSystem = GetRemoteSystemFromSystemAddress( target, false, true );

		if ( remoteSystem != 0 )
			remoteSystem->reliabilityLayer.GetTimeoutTime();
	}
	return defaultTimeoutTime;
}


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Put a packet back at the end of the receive queue in case you don't want to deal with it immediately
//
// packet The packet you want to push back.
// pushAtHead True to push the packet so that the next receive call returns it.  False to push it at the end of the queue (obviously pushing it at the end makes the packets out of order)
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::PushBackPacket( Packet *packet, bool pushAtHead)
{
	if (packet==0)
		return;

	unsigned i;
//	for (i=0; i < pluginListTS.Size(); i++)
//		pluginListTS[i]->OnPushBackPacket((const char*) packet->data, packet->bitSize, packet->systemAddress);
//	for (i=0; i < pluginListNTS.Size(); i++)
//		pluginListNTS[i]->OnPushBackPacket((const char*) packet->data, packet->bitSize, packet->systemAddress);

	packetReturnMutex.Lock();
	if (pushAtHead)
		packetReturnQueue.PushAtHead(packet,0,_FILE_AND_LINE_);
	else
		packetReturnQueue.Push(packet,_FILE_AND_LINE_);
	packetReturnMutex.Unlock();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Packet* RakPeer::AllocatePacket(unsigned dataSize)
{
	return AllocPacket(dataSize, _FILE_AND_LINE_);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::WriteOutOfBandHeader(RakNet::BitStream *bitStream)
{
	bitStream->Write((MessageID)ID_OUT_OF_BAND_INTERNAL);
 	bitStream->Write(myGuid);
	bitStream->WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakNetStatistics * RakPeer::GetStatistics( const SystemAddress systemAddress, RakNetStatistics *rns )
{
	static RakNetStatistics staticStatistics;
	RakNetStatistics *systemStats;
	if (rns==0)
		systemStats=&staticStatistics;
	else
		systemStats=rns;

	if (systemAddress==UNASSIGNED_SYSTEM_ADDRESS)
	{
		bool firstWrite=false;
		// Return a crude sum
		for ( unsigned short i = 0; i < maximumNumberOfPeers; i++ )
		{
			if (remoteSystemList[ i ].isActive)
			{
				RakNetStatistics rnsTemp;
				remoteSystemList[ i ].reliabilityLayer.GetStatistics(&rnsTemp);

				if (firstWrite==false)
				{
					memcpy(systemStats, &rnsTemp, sizeof(RakNetStatistics));
					firstWrite=true;
				}
				else
					(*systemStats)+=rnsTemp;
			}
		}
		return systemStats;
	}
	else
	{
		RemoteSystemStruct * rss;
		rss = GetRemoteSystemFromSystemAddress( systemAddress, false, false );
		if ( rss && endThreads==false )
		{
			rss->reliabilityLayer.GetStatistics(systemStats);
			return systemStats;
		}
	}

	return 0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetReceiveBufferSize(void)
{
	unsigned int size;
	packetReturnMutex.Lock();
	size=packetReturnQueue.Size();
	packetReturnMutex.Unlock();
	return size;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetIndexFromSystemAddress( const SystemAddress systemAddress, bool calledFromNetworkThread ) const
{
	unsigned i;

	if ( systemAddress == UNASSIGNED_SYSTEM_ADDRESS )
		return -1;

	if (systemAddress.systemIndex!=(SystemIndex)-1 && systemAddress.systemIndex < maximumNumberOfPeers && remoteSystemList[systemAddress.systemIndex].systemAddress==systemAddress && remoteSystemList[ systemAddress.systemIndex ].isActive)
		return systemAddress.systemIndex;

	if (calledFromNetworkThread)
	{
		return GetRemoteSystemIndex(systemAddress);
	}
	else
	{
		// remoteSystemList in user and network thread
		for ( i = 0; i < maximumNumberOfPeers; i++ )
			if ( remoteSystemList[ i ].isActive && remoteSystemList[ i ].systemAddress == systemAddress )
				return i;

		// If no active results found, try previously active results.
		for ( i = 0; i < maximumNumberOfPeers; i++ )
			if ( remoteSystemList[ i ].systemAddress == systemAddress )
				return i;
	}

	return -1;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
int RakPeer::GetIndexFromGuid( const RakNetGUID guid )
{
	unsigned i;

	if ( guid == UNASSIGNED_RAKNET_GUID )
		return -1;

	if (guid.systemIndex!=(SystemIndex)-1 && guid.systemIndex < maximumNumberOfPeers && remoteSystemList[guid.systemIndex].guid==guid && remoteSystemList[ guid.systemIndex ].isActive)
		return guid.systemIndex;

	// remoteSystemList in user and network thread
	for ( i = 0; i < maximumNumberOfPeers; i++ )
		if ( remoteSystemList[ i ].isActive && remoteSystemList[ i ].guid == guid )
			return i;

	// If no active results found, try previously active results.
	for ( i = 0; i < maximumNumberOfPeers; i++ )
		if ( remoteSystemList[ i ].guid == guid )
			return i;

	return -1;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
ConnectionAttemptResult RakPeer::SendConnectionRequest( const char* host, unsigned short remotePort, const char *passwordData, int passwordDataLength, PublicKey *publicKey, unsigned connectionSocketIndex, unsigned int extraData, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime )
{
	RakAssert(passwordDataLength <= 256);
	RakAssert(remotePort!=0);
	SystemAddress systemAddress;
	if (!systemAddress.FromStringExplicitPort(host,remotePort,socketList[connectionSocketIndex]->GetBoundAddress().GetIPVersion()))
		return CANNOT_RESOLVE_DOMAIN_NAME;

	// Already connected?
	if (GetRemoteSystemFromSystemAddress(systemAddress, false, true))
		return ALREADY_CONNECTED_TO_ENDPOINT;

	//RequestedConnectionStruct *rcs = (RequestedConnectionStruct *) rakMalloc_Ex(sizeof(RequestedConnectionStruct), _FILE_AND_LINE_);
	RequestedConnectionStruct *rcs = RakNet::OP_NEW<RequestedConnectionStruct>(_FILE_AND_LINE_);

	rcs->systemAddress=systemAddress;
	rcs->nextRequestTime=RakNet::GetTimeMS();
	rcs->requestsMade=0;
	rcs->data=0;
	rcs->socket=0;
	rcs->extraData=extraData;
	rcs->socketIndex=connectionSocketIndex;
	rcs->actionToTake=RequestedConnectionStruct::CONNECT;
	rcs->sendConnectionAttemptCount=sendConnectionAttemptCount;
	rcs->timeBetweenSendConnectionAttemptsMS=timeBetweenSendConnectionAttemptsMS;
	memcpy(rcs->outgoingPassword, passwordData, passwordDataLength);
	rcs->outgoingPasswordLength=(unsigned char) passwordDataLength;
	rcs->timeoutTime=timeoutTime;

	// Return false if already pending, else push on queue
	unsigned int i=0;
	requestedConnectionQueueMutex.Lock();
	for (; i < requestedConnectionQueue.Size(); i++)
	{
		if (requestedConnectionQueue[i]->systemAddress==systemAddress)
		{
			requestedConnectionQueueMutex.Unlock();
			// Not necessary
			//RakNet::OP_DELETE(rcs->client_handshake,_FILE_AND_LINE_);
			RakNet::OP_DELETE(rcs,_FILE_AND_LINE_);
			return CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
		}
	}
	requestedConnectionQueue.Push(rcs, _FILE_AND_LINE_ );
	requestedConnectionQueueMutex.Unlock();

	return CONNECTION_ATTEMPT_STARTED;
}
// ConnectionAttemptResult RakPeer::SendConnectionRequest( const char* host, unsigned short remotePort, const char *passwordData, int passwordDataLength, PublicKey *publicKey, unsigned connectionSocketIndex, unsigned int extraData, unsigned sendConnectionAttemptCount, unsigned timeBetweenSendConnectionAttemptsMS, RakNet::TimeMS timeoutTime, RakNetSocket2* socket )
// {
// 	RakAssert(passwordDataLength <= 256);
// 	SystemAddress systemAddress;
// 	systemAddress.FromStringExplicitPort(host,remotePort);
// 
// 	// Already connected?
// 	if (GetRemoteSystemFromSystemAddress(systemAddress, false, true))
// 		return ALREADY_CONNECTED_TO_ENDPOINT;
// 
// 	//RequestedConnectionStruct *rcs = (RequestedConnectionStruct *) rakMalloc_Ex(sizeof(RequestedConnectionStruct), _FILE_AND_LINE_);
// 	RequestedConnectionStruct *rcs = RakNet::OP_NEW<RequestedConnectionStruct>(_FILE_AND_LINE_);
// 
// 	rcs->systemAddress=systemAddress;
// 	rcs->nextRequestTime=RakNet::GetTimeMS();
// 	rcs->requestsMade=0;
// 	rcs->data=0;
// 	rcs->socket=0;
// 	rcs->extraData=extraData;
// 	rcs->socketIndex=connectionSocketIndex;
// 	rcs->actionToTake=RequestedConnectionStruct::CONNECT;
// 	rcs->sendConnectionAttemptCount=sendConnectionAttemptCount;
// 	rcs->timeBetweenSendConnectionAttemptsMS=timeBetweenSendConnectionAttemptsMS;
// 	memcpy(rcs->outgoingPassword, passwordData, passwordDataLength);
// 	rcs->outgoingPasswordLength=(unsigned char) passwordDataLength;
// 	rcs->timeoutTime=timeoutTime;
// 	rcs->socket=socket;
// 
// #if LIBCAT_SECURITY==1
// 	if (!GenerateConnectionRequestChallenge(rcs,publicKey))
// 		return SECURITY_INITIALIZATION_FAILED;
// #else
// 	(void) publicKey;
// #endif
// 
// 	// Return false if already pending, else push on queue
// 	unsigned int i=0;
// 	requestedConnectionQueueMutex.Lock();
// 	for (; i < requestedConnectionQueue.Size(); i++)
// 	{
// 		if (requestedConnectionQueue[i]->systemAddress==systemAddress)
// 		{
// 			requestedConnectionQueueMutex.Unlock();
// 			// Not necessary
// 			//RakNet::OP_DELETE(rcs->client_handshake,_FILE_AND_LINE_);
// 			RakNet::OP_DELETE(rcs,_FILE_AND_LINE_);
// 			return CONNECTION_ATTEMPT_ALREADY_IN_PROGRESS;
// 		}
// 	}
// 	requestedConnectionQueue.Push(rcs, _FILE_AND_LINE_ );
// 	requestedConnectionQueueMutex.Unlock();
// 
// 	return CONNECTION_ATTEMPT_STARTED;
// }
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ValidateRemoteSystemLookup(void) const
{
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystem( const AddressOrGUID systemIdentifier, bool calledFromNetworkThread, bool onlyActive ) const
{
	if (systemIdentifier.rakNetGuid!=UNASSIGNED_RAKNET_GUID)
		return GetRemoteSystemFromGUID(systemIdentifier.rakNetGuid, onlyActive);
	else
		return GetRemoteSystemFromSystemAddress(systemIdentifier.systemAddress, calledFromNetworkThread, onlyActive);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystemFromSystemAddress( const SystemAddress systemAddress, bool calledFromNetworkThread, bool onlyActive ) const
{
	unsigned i;

	if ( systemAddress == UNASSIGNED_SYSTEM_ADDRESS )
		return 0;

	if (calledFromNetworkThread)
	{
		unsigned int index = GetRemoteSystemIndex(systemAddress);
		if (index!=(unsigned int) -1)
		{
			if (onlyActive==false || remoteSystemList[ index ].isActive==true )
			{
				RakAssert(remoteSystemList[index].systemAddress==systemAddress);
				return remoteSystemList + index;
			}
		}
	}
	else
	{
		int deadConnectionIndex=-1;

		// Active connections take priority.  But if there are no active connections, return the first systemAddress match found
		for ( i = 0; i < maximumNumberOfPeers; i++ )
		{
			if (remoteSystemList[ i ].systemAddress == systemAddress)
			{
				if ( remoteSystemList[ i ].isActive )
					return remoteSystemList + i;
				else if (deadConnectionIndex==-1)
					deadConnectionIndex=i;
			}
		}

		if (deadConnectionIndex!=-1 && onlyActive==false)
			return remoteSystemList + deadConnectionIndex;
	}

	return 0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct *RakPeer::GetRemoteSystemFromGUID( const RakNetGUID guid, bool onlyActive ) const
{
	if (guid==UNASSIGNED_RAKNET_GUID)
		return 0;

	unsigned i;
	for ( i = 0; i < maximumNumberOfPeers; i++ )
	{
		if (remoteSystemList[ i ].guid == guid && (onlyActive==false || remoteSystemList[ i ].isActive))
		{
			return remoteSystemList + i;
		}
	}
	return 0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ParseConnectionRequestPacket( RakPeer::RemoteSystemStruct *remoteSystem, const SystemAddress &systemAddress, const char *data, int byteSize )
{
	RakNet::BitStream bs((unsigned char*) data,byteSize,false);
	bs.IgnoreBytes(sizeof(MessageID));
	RakNetGUID guid;
	bs.Read(guid);
	RakNet::Time incomingTimestamp;
	bs.Read(incomingTimestamp);
	unsigned char doSecurity;
	bs.Read(doSecurity);

#if LIBCAT_SECURITY==1

#endif // LIBCAT_SECURITY

	unsigned char *password = bs.GetData()+BITS_TO_BYTES(bs.GetReadOffset());
	int passwordLength = byteSize - BITS_TO_BYTES(bs.GetReadOffset());
	if ( incomingPasswordLength != passwordLength ||
		memcmp( password, incomingPassword, incomingPasswordLength ) != 0 )
	{
		CAT_AUDIT_PRINTF("AUDIT: Invalid password\n");
		// This one we only send once since we don't care if it arrives.
		RakNet::BitStream bitStream;
		bitStream.Write((MessageID)ID_INVALID_PASSWORD);
		bitStream.Write(GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
		SendImmediate((char*) bitStream.GetData(), bitStream.GetNumberOfBytesUsed(), IMMEDIATE_PRIORITY, RELIABLE, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0);
		remoteSystem->connectMode=RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY;
		return;
	}

	// OK
	remoteSystem->connectMode=RemoteSystemStruct::HANDLING_CONNECTION_REQUEST;

	OnConnectionRequest( remoteSystem, incomingTimestamp );
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::OnConnectionRequest( RakPeer::RemoteSystemStruct *remoteSystem, RakNet::Time incomingTimestamp )
{
	RakNet::BitStream bitStream;
	bitStream.Write((MessageID)ID_CONNECTION_REQUEST_ACCEPTED);
	bitStream.Write(remoteSystem->systemAddress);
	SystemIndex systemIndex = (SystemIndex) GetIndexFromSystemAddress( remoteSystem->systemAddress, true );
	RakAssert(systemIndex!=65535);
	bitStream.Write(systemIndex);
	for (unsigned int i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
		bitStream.Write(ipList[i]);
	bitStream.Write(incomingTimestamp);
	bitStream.Write(RakNet::GetTime());

	SendImmediate((char*)bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, RELIABLE_ORDERED, 0, remoteSystem->systemAddress, false, false, RakNet::GetTimeUS(), 0);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::NotifyAndFlagForShutdown( const SystemAddress systemAddress, bool performImmediate, unsigned char orderingChannel, PacketPriority disconnectionNotificationPriority )
{
	RakNet::BitStream temp( sizeof(unsigned char) );
	temp.Write( (MessageID)ID_DISCONNECTION_NOTIFICATION );
	if (performImmediate)
	{
		SendImmediate((char*)temp.GetData(), temp.GetNumberOfBitsUsed(), disconnectionNotificationPriority, RELIABLE_ORDERED, orderingChannel, systemAddress, false, false, RakNet::GetTimeUS(), 0);
		RemoteSystemStruct *rss=GetRemoteSystemFromSystemAddress(systemAddress, true, true);
		rss->connectMode=RemoteSystemStruct::DISCONNECT_ASAP;
	}
	else
	{
		SendBuffered((const char*)temp.GetData(), temp.GetNumberOfBitsUsed(), disconnectionNotificationPriority, RELIABLE_ORDERED, orderingChannel, systemAddress, false, RemoteSystemStruct::DISCONNECT_ASAP, 0);
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetNumberOfRemoteInitiatedConnections( void ) const
{
	if ( remoteSystemList == 0 || endThreads == true )
		return 0;

	unsigned int numberOfIncomingConnections;
	numberOfIncomingConnections = 0;
	unsigned int i;
	for (i=0; i < activeSystemListSize; i++)
	{
		if ((activeSystemList[i])->isActive &&
			(activeSystemList[i])->connectMode==RakPeer::RemoteSystemStruct::CONNECTED &&
			(activeSystemList[i])->weInitiatedTheConnection==false
			)
		{
			numberOfIncomingConnections++;
		}
	}
	return numberOfIncomingConnections;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct * RakPeer::AssignSystemAddressToRemoteSystemList( const SystemAddress systemAddress, RemoteSystemStruct::ConnectMode connectionMode, RakNetSocket2* incomingRakNetSocket, bool *thisIPConnectedRecently, SystemAddress bindingAddress, int incomingMTU, RakNetGUID guid, bool useSecurity )
{
	RemoteSystemStruct * remoteSystem;
	unsigned i,j,assignedIndex;
	RakNet::TimeMS time = RakNet::GetTimeMS();


	if (limitConnectionFrequencyFromTheSameIP)
	{
// 		if (IsLoopbackAddress(systemAddress,false)==false)
// 		{
			for ( i = 0; i < maximumNumberOfPeers; i++ )
			{
				if ( remoteSystemList[ i ].isActive==true &&
					remoteSystemList[ i ].systemAddress.EqualsExcludingPort(systemAddress) &&
					time >= remoteSystemList[ i ].connectionTime &&
					time - remoteSystemList[ i ].connectionTime < 100
					)
				{
					// 4/13/09 Attackers can flood ID_OPEN_CONNECTION_REQUEST and use up all available connection slots
					// Ignore connection attempts if this IP address connected within the last 100 milliseconds
					*thisIPConnectedRecently=true;
					ValidateRemoteSystemLookup();
					return 0;
				}
			}
/*		}*/
	}

	// Don't use a different port than what we received on
	bindingAddress.CopyPort(incomingRakNetSocket->GetBoundAddress());

	*thisIPConnectedRecently=false;
	for ( assignedIndex = 0; assignedIndex < maximumNumberOfPeers; assignedIndex++ )
	{
		if ( remoteSystemList[ assignedIndex ].isActive==false )
		{
			// printf("--- Address %s has become active\n", systemAddress.ToString());

			remoteSystem=remoteSystemList+assignedIndex;
			ReferenceRemoteSystem(systemAddress, assignedIndex);
			remoteSystem->MTUSize=defaultMTUSize;
			remoteSystem->guid=guid;
			remoteSystem->isActive = true; // This one line causes future incoming packets to go through the reliability layer
			// Reserve this reliability layer for ourselves.
			if (incomingMTU > remoteSystem->MTUSize)
				remoteSystem->MTUSize=incomingMTU;
			RakAssert(remoteSystem->MTUSize <= MAXIMUM_MTU_SIZE);
			remoteSystem->reliabilityLayer.Reset(true, remoteSystem->MTUSize, useSecurity);
			remoteSystem->reliabilityLayer.SetSplitMessageProgressInterval(splitMessageProgressInterval);
			remoteSystem->reliabilityLayer.SetUnreliableTimeout(unreliableTimeout);
			remoteSystem->reliabilityLayer.SetTimeoutTime(defaultTimeoutTime);
			AddToActiveSystemList(assignedIndex);
			if (incomingRakNetSocket->GetBoundAddress()==bindingAddress)
			{
				remoteSystem->rakNetSocket=incomingRakNetSocket;
			}
			else
			{
				char str[256];
				bindingAddress.ToString(true,str);
				// See if this is an internal IP address.
				// If so, force binding on it so we reply on the same IP address as they sent to.
				unsigned int ipListIndex, foundIndex=(unsigned int)-1;

				for (ipListIndex=0; ipListIndex < MAXIMUM_NUMBER_OF_INTERNAL_IDS; ipListIndex++)
				{
					if (ipList[ipListIndex]==UNASSIGNED_SYSTEM_ADDRESS)
						break;

					if (bindingAddress.EqualsExcludingPort(ipList[ipListIndex]))
					{
						foundIndex=ipListIndex;
						break;
					}
				}

				// 06/26/09 Unconfirmed report that Vista firewall blocks the reply if we force a binding
				// For now use the incoming socket only
				// Originally this code was to force a machine with multiple IP addresses to reply back on the IP
				// that the datagram came in on
				if (1 || foundIndex==(unsigned int)-1)
				{
					// Must not be an internal LAN address. Just use whatever socket it came in on
					remoteSystem->rakNetSocket=incomingRakNetSocket;
				}
				else
				{

				}
			}

			for ( j = 0; j < (unsigned) PING_TIMES_ARRAY_SIZE; j++ )
			{
				remoteSystem->pingAndClockDifferential[ j ].pingTime = 65535;
				remoteSystem->pingAndClockDifferential[ j ].clockDifferential = 0;
			}

			remoteSystem->connectMode=connectionMode;
			remoteSystem->pingAndClockDifferentialWriteIndex = 0;
			remoteSystem->lowestPing = 65535;
			remoteSystem->nextPingTime = 0; // Ping immediately
			remoteSystem->weInitiatedTheConnection = false;
			remoteSystem->connectionTime = time;
			remoteSystem->myExternalSystemAddress = UNASSIGNED_SYSTEM_ADDRESS;
			remoteSystem->lastReliableSend=time;

			return remoteSystem;
		}
	}

	return 0;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Adjust the first four bytes (treated as unsigned int) of the pointer
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ShiftIncomingTimestamp( unsigned char *data, const SystemAddress &systemAddress ) const
{
	RakNet::BitStream timeBS( data, sizeof(RakNet::Time), false);
	RakNet::Time encodedTimestamp;
	timeBS.Read(encodedTimestamp);

	encodedTimestamp = encodedTimestamp - GetBestClockDifferential( systemAddress );
	timeBS.SetWriteOffset(0);
	timeBS.Write(encodedTimestamp);
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Thanks to Chris Taylor (cat02e@fsu.edu) for the improved timestamping algorithm
RakNet::Time RakPeer::GetBestClockDifferential( const SystemAddress systemAddress ) const
{
	RemoteSystemStruct *remoteSystem = GetRemoteSystemFromSystemAddress( systemAddress, true, true );

	if ( remoteSystem == 0 )
		return 0;

	return GetClockDifferentialInt(remoteSystem);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::RemoteSystemLookupHashIndex(const SystemAddress &sa) const
{
	return SystemAddress::ToInteger(sa) % ((unsigned int) maximumNumberOfPeers * REMOTE_SYSTEM_LOOKUP_HASH_MULTIPLE);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ReferenceRemoteSystem(const SystemAddress &sa, unsigned int remoteSystemListIndex)
{
	SystemAddress oldAddress = remoteSystemList[remoteSystemListIndex].systemAddress;
	if (oldAddress!=UNASSIGNED_SYSTEM_ADDRESS)
	{
		// The system might be active if rerouting
//		RakAssert(remoteSystemList[remoteSystemListIndex].isActive==false);

		// Remove the reference if the reference is pointing to this inactive system
		if (GetRemoteSystem(oldAddress)==&remoteSystemList[remoteSystemListIndex])
			DereferenceRemoteSystem(oldAddress);
	}
	DereferenceRemoteSystem(sa);

	remoteSystemList[remoteSystemListIndex].systemAddress=sa;

	unsigned int hashIndex = RemoteSystemLookupHashIndex(sa);
	RemoteSystemIndex *rsi;
	rsi = remoteSystemIndexPool.Allocate(_FILE_AND_LINE_);
	if (remoteSystemLookup[hashIndex]==0)
	{
		rsi->next=0;
		rsi->index=remoteSystemListIndex;
		remoteSystemLookup[hashIndex]=rsi;
	}
	else
	{
		RemoteSystemIndex *cur = remoteSystemLookup[hashIndex];
		while (cur->next!=0)
		{
			cur=cur->next;
		}

		rsi = remoteSystemIndexPool.Allocate(_FILE_AND_LINE_);
		rsi->next=0;
		rsi->index=remoteSystemListIndex;
		cur->next=rsi;
	}


	RakAssert(GetRemoteSystemIndex(sa)==remoteSystemListIndex);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::DereferenceRemoteSystem(const SystemAddress &sa)
{
	unsigned int hashIndex = RemoteSystemLookupHashIndex(sa);
	RemoteSystemIndex *cur = remoteSystemLookup[hashIndex];
	RemoteSystemIndex *last = 0;
	while (cur!=0)
	{
		if (remoteSystemList[cur->index].systemAddress==sa)
		{
			if (last==0)
			{
				remoteSystemLookup[hashIndex]=cur->next;
			}
			else
			{
				last->next=cur->next;
			}
			remoteSystemIndexPool.Release(cur,_FILE_AND_LINE_);
			break;
		}
		last=cur;
		cur=cur->next;
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetRemoteSystemIndex(const SystemAddress &sa) const
{
	unsigned int hashIndex = RemoteSystemLookupHashIndex(sa);
	RemoteSystemIndex *cur = remoteSystemLookup[hashIndex];
	while (cur!=0)
	{
		if (remoteSystemList[cur->index].systemAddress==sa)
			return cur->index;
		cur=cur->next;
	}
	return (unsigned int) -1;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RakPeer::RemoteSystemStruct* RakPeer::GetRemoteSystem(const SystemAddress &sa) const
{
	unsigned int remoteSystemIndex = GetRemoteSystemIndex(sa);
	if (remoteSystemIndex==(unsigned int)-1)
		return 0;
	return remoteSystemList + remoteSystemIndex;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearRemoteSystemLookup(void)
{
	remoteSystemIndexPool.Clear(_FILE_AND_LINE_);
	RakNet::OP_DELETE_ARRAY(remoteSystemLookup,_FILE_AND_LINE_);
	remoteSystemLookup=0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::AddToActiveSystemList(unsigned int remoteSystemListIndex)
{
	activeSystemList[activeSystemListSize++]=remoteSystemList+remoteSystemListIndex;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::RemoveFromActiveSystemList(const SystemAddress &sa)
{
	unsigned int i;
	for (i=0; i < activeSystemListSize; i++)
	{
		RemoteSystemStruct *rss=activeSystemList[i];
		if (rss->systemAddress==sa)
		{
			activeSystemList[i]=activeSystemList[activeSystemListSize-1];
			activeSystemListSize--;
			return;
		}
	}
	RakAssert("activeSystemList invalid, entry not found in RemoveFromActiveSystemList. Ensure that AddToActiveSystemList and RemoveFromActiveSystemList are called by the same thread." && 0);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// bool RakPeer::IsLoopbackAddress(const AddressOrGUID &systemIdentifier, bool matchPort) const
// {
// 	if (systemIdentifier.rakNetGuid!=UNASSIGNED_RAKNET_GUID)
// 		return systemIdentifier.rakNetGuid==myGuid;
// 
// 	for (int i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS && ipList[i]!=UNASSIGNED_SYSTEM_ADDRESS; i++)
// 	{
// 		if (matchPort)
// 		{
// 			if (ipList[i]==systemIdentifier.systemAddress)
// 				return true;
// 		}
// 		else
// 		{
// 			if (ipList[i].EqualsExcludingPort(systemIdentifier.systemAddress))
// 				return true;
// 		}
// 	}
// 
// 	return (matchPort==true && systemIdentifier.systemAddress==firstExternalID) ||
// 		(matchPort==false && systemIdentifier.systemAddress.EqualsExcludingPort(firstExternalID));
// }
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// SystemAddress RakPeer::GetLoopbackAddress(void) const
// {
// 	return ipList[0];
// }
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::AllowIncomingConnections(void) const
{
	return GetNumberOfRemoteInitiatedConnections() < GetMaximumIncomingConnections();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::DeallocRNS2RecvStruct(RNS2RecvStruct *s, const char *file, unsigned int line)
{
	bufferedPacketsFreePoolMutex.Lock();
	bufferedPacketsFreePool.Push(s, file, line);
	bufferedPacketsFreePoolMutex.Unlock();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RNS2RecvStruct *RakPeer::AllocRNS2RecvStruct(const char *file, unsigned int line)
{
	bufferedPacketsFreePoolMutex.Lock();
	if (bufferedPacketsFreePool.Size()>0)
	{
		RNS2RecvStruct *s = bufferedPacketsFreePool.Pop();
		bufferedPacketsFreePoolMutex.Unlock();
		return s;
	}
	else
	{
		bufferedPacketsFreePoolMutex.Unlock();
		return RakNet::OP_NEW<RNS2RecvStruct>(file,line);
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearBufferedPackets(void)
{
	bufferedPacketsFreePoolMutex.Lock();
	while (bufferedPacketsFreePool.Size()>0)
		RakNet::OP_DELETE(bufferedPacketsFreePool.Pop(), _FILE_AND_LINE_);
	bufferedPacketsFreePoolMutex.Unlock();

	bufferedPacketsQueueMutex.Lock();
	while (bufferedPacketsQueue.Size()>0)
		RakNet::OP_DELETE(bufferedPacketsQueue.Pop(), _FILE_AND_LINE_);
	bufferedPacketsQueueMutex.Unlock();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SetupBufferedPackets(void)
{
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::PushBufferedPacket(RNS2RecvStruct * p)
{
	bufferedPacketsQueueMutex.Lock();
	bufferedPacketsQueue.Push(p, _FILE_AND_LINE_);
	bufferedPacketsQueueMutex.Unlock();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RNS2RecvStruct *RakPeer::PopBufferedPacket(void)
{
	bufferedPacketsQueueMutex.Lock();
	if (bufferedPacketsQueue.Size()>0)
	{
		RNS2RecvStruct *s = bufferedPacketsQueue.Pop();
		bufferedPacketsQueueMutex.Unlock();
		return s;
	}
	bufferedPacketsQueueMutex.Unlock();
	return 0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::PingInternal( const SystemAddress target, bool performImmediate, PacketReliability reliability )
{
	if ( IsActive() == false )
		return ;

	RakNet::BitStream bitStream(sizeof(unsigned char)+sizeof(RakNet::Time));
	bitStream.Write((MessageID)ID_CONNECTED_PING);
	bitStream.Write(RakNet::GetTime());
	if (performImmediate)
		SendImmediate( (char*)bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, reliability, 0, target, false, false, RakNet::GetTimeUS(), 0 );
	else
		Send( &bitStream, IMMEDIATE_PRIORITY, reliability, 0, target, false );
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::CloseConnectionInternal( const AddressOrGUID& systemIdentifier, bool sendDisconnectionNotification, bool performImmediate, unsigned char orderingChannel, PacketPriority disconnectionNotificationPriority )
{

	if (systemIdentifier.IsUndefined())
		return;

	if ( remoteSystemList == 0 || endThreads == true )
		return;

	SystemAddress target;
	if (systemIdentifier.systemAddress!=UNASSIGNED_SYSTEM_ADDRESS)
	{
		target=systemIdentifier.systemAddress;
	}
	else
	{
		target=GetSystemAddressFromGuid(systemIdentifier.rakNetGuid);
	}

	if (target!=UNASSIGNED_SYSTEM_ADDRESS && performImmediate)
		target.FixForIPVersion(socketList[0]->GetBoundAddress());

	if (sendDisconnectionNotification)
	{
		NotifyAndFlagForShutdown(target, performImmediate, orderingChannel, disconnectionNotificationPriority);
	}
	else
	{
		if (performImmediate)
		{
			unsigned int index = GetRemoteSystemIndex(target);
			if (index!=(unsigned int) -1)
			{
				if ( remoteSystemList[index].isActive )
				{
					RemoveFromActiveSystemList(target);

					// Found the index to stop
					// printf("--- Address %s has become inactive\n", remoteSystemList[index].systemAddress.ToString());
					remoteSystemList[index].isActive = false;

					remoteSystemList[index].guid=UNASSIGNED_RAKNET_GUID;

					// Reserve this reliability layer for ourselves
					//remoteSystemList[ remoteSystemLookup[index].index ].systemAddress = UNASSIGNED_SYSTEM_ADDRESS;

					// Clear any remaining messages
					RakAssert(remoteSystemList[index].MTUSize <= MAXIMUM_MTU_SIZE);
					remoteSystemList[index].reliabilityLayer.Reset(false, remoteSystemList[index].MTUSize, false);

					// Not using this socket
					remoteSystemList[index].rakNetSocket = 0;
				}
			}
		}
		else
		{
			BufferedCommandStruct *bcs;
			bcs=bufferedCommands.Allocate( _FILE_AND_LINE_ );
			bcs->command=BufferedCommandStruct::BCS_CLOSE_CONNECTION;
			bcs->systemIdentifier=target;
			bcs->data=0;
			bcs->orderingChannel=orderingChannel;
			bcs->priority=disconnectionNotificationPriority;
			bufferedCommands.Push(bcs);
		}
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SendBuffered( const char *data, BitSize_t numberOfBitsToSend, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, RemoteSystemStruct::ConnectMode connectionMode, uint32_t receipt )
{
	BufferedCommandStruct *bcs;

	bcs=bufferedCommands.Allocate( _FILE_AND_LINE_ );
	bcs->data = (char*) rakMalloc_Ex( (size_t) BITS_TO_BYTES(numberOfBitsToSend), _FILE_AND_LINE_ ); // Making a copy doesn't lose efficiency because I tell the reliability layer to use this allocation for its own copy
	if (bcs->data==0)
	{
		notifyOutOfMemory(_FILE_AND_LINE_);
		bufferedCommands.Deallocate(bcs, _FILE_AND_LINE_);
		return;
	}
	
	RakAssert( !( reliability >= NUMBER_OF_RELIABILITIES || reliability < 0 ) );
	RakAssert( !( priority > NUMBER_OF_PRIORITIES || priority < 0 ) );
	RakAssert( !( orderingChannel >= NUMBER_OF_ORDERED_STREAMS ) );

	memcpy(bcs->data, data, (size_t) BITS_TO_BYTES(numberOfBitsToSend));
	bcs->numberOfBitsToSend=numberOfBitsToSend;
	bcs->priority=priority;
	bcs->reliability=reliability;
	bcs->orderingChannel=orderingChannel;
	bcs->systemIdentifier=systemIdentifier;
	bcs->broadcast=broadcast;
	bcs->connectionMode=connectionMode;
	bcs->receipt=receipt;
	bcs->command=BufferedCommandStruct::BCS_SEND;
	bufferedCommands.Push(bcs);

	if (priority==IMMEDIATE_PRIORITY)
	{
		// Forces pending sends to go out now, rather than waiting to the next update interval
		quitAndDataEvents.SetEvent();
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::SendBufferedList( const char **data, const int *lengths, const int numParameters, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, RemoteSystemStruct::ConnectMode connectionMode, uint32_t receipt )
{
	BufferedCommandStruct *bcs;
	unsigned int totalLength=0;
	unsigned int lengthOffset;
	int i;
	for (i=0; i < numParameters; i++)
	{
		if (lengths[i]>0)
			totalLength+=lengths[i];
	}
	if (totalLength==0)
		return;

	char *dataAggregate;
	dataAggregate = (char*) rakMalloc_Ex( (size_t) totalLength, _FILE_AND_LINE_ ); // Making a copy doesn't lose efficiency because I tell the reliability layer to use this allocation for its own copy
	if (dataAggregate==0)
	{
		notifyOutOfMemory(_FILE_AND_LINE_);
		return;
	}
	for (i=0, lengthOffset=0; i < numParameters; i++)
	{
		if (lengths[i]>0)
		{
			memcpy(dataAggregate+lengthOffset, data[i], lengths[i]);
			lengthOffset+=lengths[i];
		}
	}

// 	if (broadcast==false && IsLoopbackAddress(systemIdentifier,true))
// 	{
// 		SendLoopback(dataAggregate,totalLength);
// 		rakFree_Ex(dataAggregate,_FILE_AND_LINE_);
// 		return;
// 	}

	RakAssert( !( reliability >= NUMBER_OF_RELIABILITIES || reliability < 0 ) );
	RakAssert( !( priority > NUMBER_OF_PRIORITIES || priority < 0 ) );
	RakAssert( !( orderingChannel >= NUMBER_OF_ORDERED_STREAMS ) );

	bcs=bufferedCommands.Allocate( _FILE_AND_LINE_ );
	bcs->data = dataAggregate;
	bcs->numberOfBitsToSend=BYTES_TO_BITS(totalLength);
	bcs->priority=priority;
	bcs->reliability=reliability;
	bcs->orderingChannel=orderingChannel;
	bcs->systemIdentifier=systemIdentifier;
	bcs->broadcast=broadcast;
	bcs->connectionMode=connectionMode;
	bcs->receipt=receipt;
	bcs->command=BufferedCommandStruct::BCS_SEND;
	bufferedCommands.Push(bcs);

	if (priority==IMMEDIATE_PRIORITY)
	{
		// Forces pending sends to go out now, rather than waiting to the next update interval
		quitAndDataEvents.SetEvent();
	}
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::SendImmediate( char *data, BitSize_t numberOfBitsToSend, PacketPriority priority, PacketReliability reliability, char orderingChannel, const AddressOrGUID systemIdentifier, bool broadcast, bool useCallerDataAllocation, RakNet::TimeUS currentTime, uint32_t receipt )
{
	unsigned *sendList;
	unsigned sendListSize;
	bool callerDataAllocationUsed;
	unsigned int remoteSystemIndex, sendListIndex; // Iterates into the list of remote systems
//	unsigned numberOfBytesUsed = (unsigned) BITS_TO_BYTES(numberOfBitsToSend);
	callerDataAllocationUsed=false;

	sendListSize=0;

	if (systemIdentifier.systemAddress!=UNASSIGNED_SYSTEM_ADDRESS)
		remoteSystemIndex=GetIndexFromSystemAddress( systemIdentifier.systemAddress, true );
	else if (systemIdentifier.rakNetGuid!=UNASSIGNED_RAKNET_GUID)
		remoteSystemIndex=GetSystemIndexFromGuid(systemIdentifier.rakNetGuid);
	else
		remoteSystemIndex=(unsigned int) -1;

	// 03/06/06 - If broadcast is false, use the optimized version of GetIndexFromSystemAddress
	if (broadcast==false)
	{
		if (remoteSystemIndex==(unsigned int) -1)
		{
			return false;
		}

		#if USE_ALLOCA==1
			sendList=(unsigned *)alloca(sizeof(unsigned));
		#else
			sendList = (unsigned *) rakMalloc_Ex(sizeof(unsigned), _FILE_AND_LINE_);
		#endif

		if (remoteSystemList[remoteSystemIndex].isActive &&
			remoteSystemList[remoteSystemIndex].connectMode!=RemoteSystemStruct::DISCONNECT_ASAP &&
			remoteSystemList[remoteSystemIndex].connectMode!=RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY &&
			remoteSystemList[remoteSystemIndex].connectMode!=RemoteSystemStruct::DISCONNECT_ON_NO_ACK)
		{
			sendList[0]=remoteSystemIndex;
			sendListSize=1;
		}
	}
	else
	{
		#if USE_ALLOCA==1
			sendList=(unsigned *)alloca(sizeof(unsigned)*maximumNumberOfPeers);
		#else
			sendList = (unsigned *) rakMalloc_Ex(sizeof(unsigned)*maximumNumberOfPeers, _FILE_AND_LINE_);
		#endif

		// remoteSystemList in network thread
		unsigned int idx;
		for ( idx = 0; idx < maximumNumberOfPeers; idx++ )
		{
			if (remoteSystemIndex!=(unsigned int) -1 && idx==remoteSystemIndex)
				continue;

			if ( remoteSystemList[ idx ].isActive && remoteSystemList[ idx ].systemAddress != UNASSIGNED_SYSTEM_ADDRESS )
				sendList[sendListSize++]=idx;
		}
	}

	if (sendListSize==0)
	{
		#if !defined(USE_ALLOCA)
			rakFree_Ex(sendList, _FILE_AND_LINE_ );
		#endif

		return false;
	}

	for (sendListIndex=0; sendListIndex < sendListSize; sendListIndex++)
	{
		// Send may split the packet and thus deallocate data.  Don't assume data is valid if we use the callerAllocationData
		bool useData = useCallerDataAllocation && callerDataAllocationUsed==false && sendListIndex+1==sendListSize;
		remoteSystemList[sendList[sendListIndex]].reliabilityLayer.Send( data, numberOfBitsToSend, priority, reliability, orderingChannel, useData==false, remoteSystemList[sendList[sendListIndex]].MTUSize, currentTime, receipt );
		if (useData)
			callerDataAllocationUsed=true;

		if (reliability==RELIABLE ||
			reliability==RELIABLE_ORDERED ||
			reliability==RELIABLE_SEQUENCED ||
			reliability==RELIABLE_WITH_ACK_RECEIPT ||
			reliability==RELIABLE_ORDERED_WITH_ACK_RECEIPT
//			||
//			reliability==RELIABLE_SEQUENCED_WITH_ACK_RECEIPT
			)
			remoteSystemList[sendList[sendListIndex]].lastReliableSend=(RakNet::TimeMS)(currentTime/(RakNet::TimeUS)1000);
	}

#if !defined(USE_ALLOCA)
	rakFree_Ex(sendList, _FILE_AND_LINE_ );
#endif

	// Return value only meaningful if true was passed for useCallerDataAllocation.  Means the reliability layer used that data copy, so the caller should not deallocate it
	return callerDataAllocationUsed;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ResetSendReceipt(void)
{
	sendReceiptSerialMutex.Lock();
	sendReceiptSerial=1;
	sendReceiptSerialMutex.Unlock();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::OnConnectedPong(RakNet::Time sendPingTime, RakNet::Time sendPongTime, RemoteSystemStruct *remoteSystem)
{
	RakNet::Time ping;
//	RakNet::TimeMS lastPing;
	RakNet::Time time = RakNet::GetTime(); // Update the time value to be accurate
	if (time > sendPingTime)
		ping = time - sendPingTime;
	else
		ping=0;

//	lastPing = remoteSystem->pingAndClockDifferential[ remoteSystem->pingAndClockDifferentialWriteIndex ].pingTime;

	remoteSystem->pingAndClockDifferential[ remoteSystem->pingAndClockDifferentialWriteIndex ].pingTime = ( unsigned short ) ping;
	// Thanks to Chris Taylor (cat02e@fsu.edu) for the improved timestamping algorithm
	// Divide each integer by 2, rather than the sum by 2, to prevent overflow
	remoteSystem->pingAndClockDifferential[ remoteSystem->pingAndClockDifferentialWriteIndex ].clockDifferential = sendPongTime - ( time/2 + sendPingTime/2 );

	if ( remoteSystem->lowestPing == (unsigned short)-1 || remoteSystem->lowestPing > (int) ping )
		remoteSystem->lowestPing = (unsigned short) ping;

	if ( ++( remoteSystem->pingAndClockDifferentialWriteIndex ) == (RakNet::Time) PING_TIMES_ARRAY_SIZE )
		remoteSystem->pingAndClockDifferentialWriteIndex = 0;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearBufferedCommands(void)
{
	BufferedCommandStruct *bcs;

	while ((bcs=bufferedCommands.Pop())!=0)
	{
		if (bcs->data)
			rakFree_Ex(bcs->data, _FILE_AND_LINE_ );

		bufferedCommands.Deallocate(bcs, _FILE_AND_LINE_);
	}
	bufferedCommands.Clear(_FILE_AND_LINE_);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearSocketQueryOutput(void)
{
	socketQueryOutput.Clear(_FILE_AND_LINE_);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::ClearRequestedConnectionList(void)
{
	DataStructures::Queue<RequestedConnectionStruct*> freeQueue;
	requestedConnectionQueueMutex.Lock();
	while (requestedConnectionQueue.Size())
		freeQueue.Push(requestedConnectionQueue.Pop(), _FILE_AND_LINE_ );
	requestedConnectionQueueMutex.Unlock();
	unsigned i;
	for (i=0; i < freeQueue.Size(); i++)
	{
#if LIBCAT_SECURITY==1

#endif
		RakNet::OP_DELETE(freeQueue[i], _FILE_AND_LINE_ );
	}
}
inline void RakPeer::AddPacketToProducer(RakNet::Packet *p)
{
	packetReturnMutex.Lock();
	packetReturnQueue.Push(p,_FILE_AND_LINE_);
	packetReturnMutex.Unlock();
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// union Buff6AndBuff8
// {
// 	unsigned char buff6[6];
// 	uint64_t buff8;
// };
uint64_t RakPeerInterface::Get64BitUniqueRandomNumber(void)
{
	// Mac address is a poor solution because you can't have multiple connections from the same system

#if   1
	uint64_t g=RakNet::GetTimeUS();

	RakNet::TimeUS lastTime, thisTime;
	int j;
	// Sleep a small random time, then use the last 4 bits as a source of randomness
	for (j=0; j < 8; j++)
	{
		lastTime = RakNet::GetTimeUS();
		RakSleep(1);
		RakSleep(0);
		thisTime = RakNet::GetTimeUS();
		RakNet::TimeUS diff = thisTime-lastTime;
		unsigned int diff4Bits = (unsigned int) (diff & 15);
		diff4Bits <<= 32-4;
		diff4Bits >>= j*4;
		((char*)&g)[j] ^= diff4Bits;
	}
	return g;

#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_usec + tv.tv_sec * 1000000;
#endif
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::GenerateGUID(void)
{
	myGuid.g=Get64BitUniqueRandomNumber();

}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
namespace RakNet {
bool ProcessOfflineNetworkPacket( SystemAddress systemAddress, const char *data, const int length, RakPeer *rakPeer, RakNetSocket2* rakNetSocket, bool *isOfflineMessage, RakNet::TimeUS timeRead )
{
	(void) timeRead;
	RakPeer::RemoteSystemStruct *remoteSystem;
	RakNet::Packet *packet;
	unsigned i;


	char str1[64];
	systemAddress.ToString(false, str1);

	// The reason for all this is that the reliability layer has no way to tell between offline messages that arrived late for a player that is now connected,
	// and a regular encoding. So I insert OFFLINE_MESSAGE_DATA_ID into the stream, the encoding of which is essentially impossible to hit by chance
	if (length <=2)
	{
		*isOfflineMessage=true;
	}
	else if (
		((unsigned char)data[0] == ID_UNCONNECTED_PING ||
		(unsigned char)data[0] == ID_UNCONNECTED_PING_OPEN_CONNECTIONS) &&
		length >= sizeof(unsigned char) + sizeof(RakNet::Time) + sizeof(OFFLINE_MESSAGE_DATA_ID))
	{
		*isOfflineMessage=memcmp(data+sizeof(unsigned char) + sizeof(RakNet::Time), OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID))==0;
	}
	else if ((unsigned char)data[0] == ID_UNCONNECTED_PONG && (size_t) length >= sizeof(unsigned char) + sizeof(RakNet::TimeMS) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID))
	{
		*isOfflineMessage=memcmp(data+sizeof(unsigned char) + sizeof(RakNet::Time) + RakNetGUID::size(), OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID))==0;
	}
	else if (
		(unsigned char)data[0] == ID_OUT_OF_BAND_INTERNAL	&&
		(size_t) length >= sizeof(MessageID) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID))
	{
		*isOfflineMessage=memcmp(data+sizeof(MessageID) + RakNetGUID::size(), OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID))==0;
	}
	else if (
		(
		(unsigned char)data[0] == ID_OPEN_CONNECTION_REPLY_1 ||
		(unsigned char)data[0] == ID_OPEN_CONNECTION_REPLY_2 ||
		(unsigned char)data[0] == ID_OPEN_CONNECTION_REQUEST_1 ||
		(unsigned char)data[0] == ID_OPEN_CONNECTION_REQUEST_2 ||
		(unsigned char)data[0] == ID_CONNECTION_ATTEMPT_FAILED ||
		(unsigned char)data[0] == ID_NO_FREE_INCOMING_CONNECTIONS ||
		(unsigned char)data[0] == ID_CONNECTION_BANNED ||
		(unsigned char)data[0] == ID_ALREADY_CONNECTED ||
		(unsigned char)data[0] == ID_IP_RECENTLY_CONNECTED) &&
		(size_t) length >= sizeof(MessageID) + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID))
	{
		*isOfflineMessage=memcmp(data+sizeof(MessageID), OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID))==0;
	}
	else if (((unsigned char)data[0] == ID_INCOMPATIBLE_PROTOCOL_VERSION&&
		(size_t) length == sizeof(MessageID)*2 + RakNetGUID::size() + sizeof(OFFLINE_MESSAGE_DATA_ID)))
	{
		*isOfflineMessage=memcmp(data+sizeof(MessageID)*2, OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID))==0;
	}
	else
	{
		*isOfflineMessage=false;
	}

	if (*isOfflineMessage)
	{
//		for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//			rakPeer->pluginListNTS[i]->OnDirectSocketReceive(data, length*8, systemAddress);

		// These are all messages from unconnected systems.  Messages here can be any size, but are never processed from connected systems.
		if ( ( (unsigned char) data[ 0 ] == ID_UNCONNECTED_PING_OPEN_CONNECTIONS
			|| (unsigned char)(data)[0] == ID_UNCONNECTED_PING)	&& length >= sizeof(unsigned char)+sizeof(RakNet::Time)+sizeof(OFFLINE_MESSAGE_DATA_ID) )
		{
			if ( (unsigned char)(data)[0] == ID_UNCONNECTED_PING ||
				rakPeer->AllowIncomingConnections() ) // Open connections with players
			{
				RakNet::BitStream inBitStream( (unsigned char *) data, length, false );
				inBitStream.IgnoreBits(8);
				RakNet::Time sendPingTime;
				inBitStream.Read(sendPingTime);
				inBitStream.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
				RakNetGUID remoteGuid=UNASSIGNED_RAKNET_GUID;
				inBitStream.Read(remoteGuid);

				RakNet::BitStream outBitStream;
				outBitStream.Write((MessageID)ID_UNCONNECTED_PONG); // Should be named ID_UNCONNECTED_PONG eventually
				outBitStream.Write(sendPingTime);
				outBitStream.Write(rakPeer->myGuid);
				outBitStream.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));

				rakPeer->rakPeerMutexes[ RakPeer::offlinePingResponse_Mutex ].Lock();
				// They are connected, so append offline ping data
				outBitStream.Write( (char*)rakPeer->offlinePingResponse.GetData(), rakPeer->offlinePingResponse.GetNumberOfBytesUsed() );
				rakPeer->rakPeerMutexes[ RakPeer::offlinePingResponse_Mutex ].Unlock();

				unsigned i;
//				for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//					rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char*)outBitStream.GetData(), outBitStream.GetNumberOfBytesUsed(), systemAddress);

				RNS2_SendParameters bsp;
				bsp.data = (char*) outBitStream.GetData();
				bsp.length = outBitStream.GetNumberOfBytesUsed();
				bsp.systemAddress = systemAddress;
				rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

				// SocketLayer::SendTo( rakNetSocket, (const char*)outBitStream.GetData(), (unsigned int) outBitStream.GetNumberOfBytesUsed(), systemAddress, _FILE_AND_LINE_ );

				packet=rakPeer->AllocPacket(sizeof(MessageID), _FILE_AND_LINE_);
				packet->data[0]=data[0];
				packet->systemAddress = systemAddress;
				packet->guid=remoteGuid;
				packet->systemAddress.systemIndex = ( SystemIndex ) rakPeer->GetIndexFromSystemAddress( systemAddress, true );
				packet->guid.systemIndex=packet->systemAddress.systemIndex;
				rakPeer->AddPacketToProducer(packet);
			}
		}
		// UNCONNECTED MESSAGE Pong with no data.
		else if ((unsigned char) data[ 0 ] == ID_UNCONNECTED_PONG && (size_t) length >= sizeof(unsigned char)+sizeof(RakNet::Time)+RakNetGUID::size()+sizeof(OFFLINE_MESSAGE_DATA_ID) && (size_t) length < sizeof(unsigned char)+sizeof(RakNet::Time)+RakNetGUID::size()+sizeof(OFFLINE_MESSAGE_DATA_ID)+MAX_OFFLINE_DATA_LENGTH)
		{
			packet=rakPeer->AllocPacket((unsigned int) (length-sizeof(OFFLINE_MESSAGE_DATA_ID)-RakNetGUID::size()-sizeof(RakNet::Time)+sizeof(RakNet::TimeMS)), _FILE_AND_LINE_);
			RakNet::BitStream bsIn((unsigned char*) data, length, false);
			bsIn.IgnoreBytes(sizeof(unsigned char));
			RakNet::Time ping;
			bsIn.Read(ping);
			bsIn.Read(packet->guid);
			
			RakNet::BitStream bsOut((unsigned char*) packet->data, packet->length, false);
			bsOut.ResetWritePointer();
			bsOut.Write((unsigned char)ID_UNCONNECTED_PONG);
			RakNet::TimeMS pingMS=(RakNet::TimeMS)ping;
			bsOut.Write(pingMS);
			bsOut.WriteAlignedBytes(
				(const unsigned char*)data+sizeof(unsigned char)+sizeof(RakNet::Time)+RakNetGUID::size()+sizeof(OFFLINE_MESSAGE_DATA_ID),
				length-sizeof(unsigned char)-sizeof(RakNet::Time)-RakNetGUID::size()-sizeof(OFFLINE_MESSAGE_DATA_ID)
				);

			packet->systemAddress = systemAddress;
			packet->systemAddress.systemIndex = ( SystemIndex ) rakPeer->GetIndexFromSystemAddress( systemAddress, true );
			packet->guid.systemIndex=packet->systemAddress.systemIndex;
			rakPeer->AddPacketToProducer(packet);
		}
		else if ((unsigned char) data[ 0 ] == ID_OUT_OF_BAND_INTERNAL &&
			(size_t) length > sizeof(OFFLINE_MESSAGE_DATA_ID)+sizeof(MessageID)+RakNetGUID::size() &&
			(size_t) length < MAX_OFFLINE_DATA_LENGTH+sizeof(OFFLINE_MESSAGE_DATA_ID)+sizeof(MessageID)+RakNetGUID::size())
		{
			unsigned int dataLength = (unsigned int) (length-sizeof(OFFLINE_MESSAGE_DATA_ID)-RakNetGUID::size()-sizeof(MessageID));
			RakAssert(dataLength<1024);
			packet=rakPeer->AllocPacket(dataLength+1, _FILE_AND_LINE_);
			RakAssert(packet->length<1024);

			RakNet::BitStream bs2((unsigned char*) data, length, false);
			bs2.IgnoreBytes(sizeof(MessageID));
			bs2.Read(packet->guid);

			if (data[sizeof(OFFLINE_MESSAGE_DATA_ID)+sizeof(MessageID) + RakNetGUID::size()]==ID_ADVERTISE_SYSTEM)
			{
				packet->length--;
				packet->bitSize=BYTES_TO_BITS(packet->length);
				packet->data[0]=ID_ADVERTISE_SYSTEM;
				memcpy(packet->data+1, data+sizeof(OFFLINE_MESSAGE_DATA_ID)+sizeof(MessageID)*2 + RakNetGUID::size(), dataLength-1);
			}
			else
			{
				packet->data[0]=ID_OUT_OF_BAND_INTERNAL;
				memcpy(packet->data+1, data+sizeof(OFFLINE_MESSAGE_DATA_ID)+sizeof(MessageID) + RakNetGUID::size(), dataLength);
			}

			packet->systemAddress = systemAddress;
			packet->systemAddress.systemIndex = ( SystemIndex ) rakPeer->GetIndexFromSystemAddress( systemAddress, true );
			packet->guid.systemIndex=packet->systemAddress.systemIndex;
			rakPeer->AddPacketToProducer(packet);
		}
		else if ((unsigned char)(data)[0] == (MessageID)ID_OPEN_CONNECTION_REPLY_1)
		{
//			for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//				rakPeer->pluginListNTS[i]->OnDirectSocketReceive(data, length*8, systemAddress);

			RakNet::BitStream bsIn((unsigned char*) data,length,false);
			bsIn.IgnoreBytes(sizeof(MessageID));
			bsIn.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
			RakNetGUID serverGuid;
			bsIn.Read(serverGuid);
			unsigned char serverHasSecurity;
			uint32_t cookie;
			(void) cookie;
			bsIn.Read(serverHasSecurity);
			// Even if the server has security, it may not be required of us if we are in the security exception list
			if (serverHasSecurity)
			{
				bsIn.Read(cookie);
			}

			RakNet::BitStream bsOut;
			bsOut.Write((MessageID)ID_OPEN_CONNECTION_REQUEST_2);
			bsOut.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
			if (serverHasSecurity)
				bsOut.Write(cookie);

			unsigned i;
			rakPeer->requestedConnectionQueueMutex.Lock();
			for (i=0; i <  rakPeer->requestedConnectionQueue.Size(); i++)
			{
				RakPeer::RequestedConnectionStruct *rcs;
				rcs=rakPeer->requestedConnectionQueue[i];
				if (rcs->systemAddress==systemAddress)
				{
					if (serverHasSecurity)
					{
#if LIBCAT_SECURITY==1

#else // LIBCAT_SECURITY
						// Message does not contain a challenge
						bsOut.Write((unsigned char)0);
#endif // LIBCAT_SECURITY
					}
					else
					{
						// Server does not need security
#if LIBCAT_SECURITY==1

#endif // LIBCAT_SECURITY

					}

					uint16_t mtu;
					bsIn.Read(mtu);

					// Binding address
					bsOut.Write(rcs->systemAddress);
					rakPeer->requestedConnectionQueueMutex.Unlock();
					// MTU
					bsOut.Write(mtu);
					// Our guid
					bsOut.Write(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));

//					for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//						rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char*) bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), rcs->systemAddress);

					// SocketLayer::SendTo( rakPeer->socketList[rcs->socketIndex], (const char*) bsOut.GetData(), bsOut.GetNumberOfBytesUsed(), rcs->systemAddress, _FILE_AND_LINE_ );

					RNS2_SendParameters bsp;
					bsp.data = (char*) bsOut.GetData();
					bsp.length = bsOut.GetNumberOfBytesUsed();
					bsp.systemAddress = systemAddress;
					rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

					return true;
				}
			}
			rakPeer->requestedConnectionQueueMutex.Unlock();
		}
		else if ((unsigned char)(data)[0] == (MessageID)ID_OPEN_CONNECTION_REPLY_2)
		{
//			for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//				rakPeer->pluginListNTS[i]->OnDirectSocketReceive(data, length*8, systemAddress);

			RakNet::BitStream bs((unsigned char*) data,length,false);
			bs.IgnoreBytes(sizeof(MessageID));
			bs.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
			RakNetGUID guid;
			bs.Read(guid);
			SystemAddress bindingAddress;
			bool b = bs.Read(bindingAddress);
			RakAssert(b);
			uint16_t mtu;
			b=bs.Read(mtu);
			RakAssert(b);
			bool doSecurity=false;
			b=bs.Read(doSecurity);
			RakAssert(b);

#if LIBCAT_SECURITY==1

#endif // LIBCAT_SECURITY

			RakPeer::RequestedConnectionStruct *rcs;
			bool unlock=true;
			unsigned i;
			rakPeer->requestedConnectionQueueMutex.Lock();
			for (i=0; i <  rakPeer->requestedConnectionQueue.Size(); i++)
			{
				rcs=rakPeer->requestedConnectionQueue[i];


				if (rcs->systemAddress==systemAddress)
				{
#if LIBCAT_SECURITY==1

#endif // LIBCAT_SECURITY

					rakPeer->requestedConnectionQueueMutex.Unlock();
					unlock=false;

					RakAssert(rcs->actionToTake==RakPeer::RequestedConnectionStruct::CONNECT);
					// You might get this when already connected because of cross-connections
					bool thisIPConnectedRecently=false;
					remoteSystem=rakPeer->GetRemoteSystemFromSystemAddress( systemAddress, true, true );
					if (remoteSystem==0)
					{
						if (rcs->socket == 0)
						{
							remoteSystem=rakPeer->AssignSystemAddressToRemoteSystemList(systemAddress, RakPeer::RemoteSystemStruct::UNVERIFIED_SENDER, rakNetSocket, &thisIPConnectedRecently, bindingAddress, mtu, guid, doSecurity);
						}
						else
						{
							remoteSystem=rakPeer->AssignSystemAddressToRemoteSystemList(systemAddress, RakPeer::RemoteSystemStruct::UNVERIFIED_SENDER, rcs->socket, &thisIPConnectedRecently, bindingAddress, mtu, guid, doSecurity);
						}
					}

					// 4/13/09 Attackers can flood ID_OPEN_CONNECTION_REQUEST and use up all available connection slots
					// Ignore connection attempts if this IP address connected within the last 100 milliseconds
					if (thisIPConnectedRecently==false)
					{
						// Don't check GetRemoteSystemFromGUID, server will verify
						if (remoteSystem)
						{
							// Move pointer from RequestedConnectionStruct to RemoteSystemStruct
#if LIBCAT_SECURITY==1

#endif // LIBCAT_SECURITY

							remoteSystem->weInitiatedTheConnection=true;
							remoteSystem->connectMode=RakPeer::RemoteSystemStruct::REQUESTED_CONNECTION;
							if (rcs->timeoutTime!=0)
								remoteSystem->reliabilityLayer.SetTimeoutTime(rcs->timeoutTime);

							RakNet::BitStream temp;
							temp.Write( (MessageID)ID_CONNECTION_REQUEST);
							temp.Write(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
							temp.Write(RakNet::GetTime());

#if LIBCAT_SECURITY==1

#else
							temp.Write((unsigned char)0);
#endif // LIBCAT_SECURITY

							if ( rcs->outgoingPasswordLength > 0 )
								temp.Write( ( char* ) rcs->outgoingPassword,  rcs->outgoingPasswordLength );

							rakPeer->SendImmediate((char*)temp.GetData(), temp.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, RELIABLE, 0, systemAddress, false, false, timeRead, 0 );
						}
						else
						{
							// Failed, no connections available anymore
							packet=rakPeer->AllocPacket(sizeof( char ), _FILE_AND_LINE_);
							packet->data[ 0 ] = ID_CONNECTION_ATTEMPT_FAILED; // Attempted a connection and couldn't
							packet->bitSize = ( sizeof( char ) * 8);
							packet->systemAddress = rcs->systemAddress;
							packet->guid=guid;
							rakPeer->AddPacketToProducer(packet);
						}
					}

					rakPeer->requestedConnectionQueueMutex.Lock();
					for (unsigned int k=0; k < rakPeer->requestedConnectionQueue.Size(); k++)
					{
						if (rakPeer->requestedConnectionQueue[k]->systemAddress==systemAddress)
						{
							rakPeer->requestedConnectionQueue.RemoveAtIndex(k);
							break;
						}
					}
					rakPeer->requestedConnectionQueueMutex.Unlock();

#if LIBCAT_SECURITY==1

#endif // LIBCAT_SECURITY
					RakNet::OP_DELETE(rcs,_FILE_AND_LINE_);

					break;
				}
			}

			if (unlock)
				rakPeer->requestedConnectionQueueMutex.Unlock();

			return true;

		}
		else if ((unsigned char)(data)[0] == (MessageID)ID_CONNECTION_ATTEMPT_FAILED ||
			(unsigned char)(data)[0] == (MessageID)ID_NO_FREE_INCOMING_CONNECTIONS ||
			(unsigned char)(data)[0] == (MessageID)ID_CONNECTION_BANNED ||
			(unsigned char)(data)[0] == (MessageID)ID_ALREADY_CONNECTED ||
			(unsigned char)(data)[0] == (MessageID)ID_INVALID_PASSWORD ||
			(unsigned char)(data)[0] == (MessageID)ID_IP_RECENTLY_CONNECTED ||
			(unsigned char)(data)[0] == (MessageID)ID_INCOMPATIBLE_PROTOCOL_VERSION)
		{

			RakNet::BitStream bs((unsigned char*) data,length,false);
			bs.IgnoreBytes(sizeof(MessageID));
			bs.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
			if ((unsigned char)(data)[0] == (MessageID)ID_INCOMPATIBLE_PROTOCOL_VERSION)
				bs.IgnoreBytes(sizeof(unsigned char));

			RakNetGUID guid;
			bs.Read(guid);

			RakPeer::RequestedConnectionStruct *rcs;
			bool connectionAttemptCancelled=false;
			unsigned i;
			rakPeer->requestedConnectionQueueMutex.Lock();
			for (i=0; i <  rakPeer->requestedConnectionQueue.Size(); i++)
			{
				rcs=rakPeer->requestedConnectionQueue[i];
				if (rcs->actionToTake==RakPeer::RequestedConnectionStruct::CONNECT && rcs->systemAddress==systemAddress)
				{
					connectionAttemptCancelled=true;
					rakPeer->requestedConnectionQueue.RemoveAtIndex(i);

#if LIBCAT_SECURITY==1

#endif // LIBCAT_SECURITY
					RakNet::OP_DELETE(rcs,_FILE_AND_LINE_);
					break;
				}
			}

			rakPeer->requestedConnectionQueueMutex.Unlock();

			if (connectionAttemptCancelled)
			{
				// Tell user of connection attempt failed
				packet=rakPeer->AllocPacket(sizeof( char ), _FILE_AND_LINE_);
				packet->data[ 0 ] = data[0]; // Attempted a connection and couldn't
				packet->bitSize = ( sizeof( char ) * 8);
				packet->systemAddress = systemAddress;
				packet->guid=guid;
				rakPeer->AddPacketToProducer(packet);
			}
		}
		else if ((unsigned char)(data)[0] == ID_OPEN_CONNECTION_REQUEST_1 && length > (int) (1+sizeof(OFFLINE_MESSAGE_DATA_ID)))
		{
			unsigned int i;
			//RAKNET_DEBUG_PRINTF("%i:IOCR, ", __LINE__);
			char remoteProtocol=data[1+sizeof(OFFLINE_MESSAGE_DATA_ID)];
			if (remoteProtocol!=RAKNET_PROTOCOL_VERSION)
			{
				RakNet::BitStream bs;
				bs.Write((MessageID)ID_INCOMPATIBLE_PROTOCOL_VERSION);
				bs.Write((unsigned char)RAKNET_PROTOCOL_VERSION);
				bs.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
				bs.Write(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));

//				for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//					rakPeer->pluginListNTS[i]->OnDirectSocketSend((char*)bs.GetData(), bs.GetNumberOfBitsUsed(), systemAddress);

				// SocketLayer::SendTo( rakNetSocket, (char*)bs.GetData(), bs.GetNumberOfBytesUsed(), systemAddress, _FILE_AND_LINE_ );

				RNS2_SendParameters bsp;
				bsp.data = (char*) bs.GetData();
				bsp.length = bs.GetNumberOfBytesUsed();
				bsp.systemAddress = systemAddress;

				rakNetSocket->Send(&bsp, _FILE_AND_LINE_);
				return true;
			}

//			for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//				rakPeer->pluginListNTS[i]->OnDirectSocketReceive(data, length*8, systemAddress);

			RakNet::BitStream bsOut;
			bsOut.Write((MessageID)ID_OPEN_CONNECTION_REPLY_1);
			bsOut.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
			bsOut.Write(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
#if LIBCAT_SECURITY==1

#endif // LIBCAT_SECURITY
				bsOut.Write((unsigned char) 0);  // HasCookie oN

			// MTU. Lower MTU if it is exceeds our own limit
			if (length+UDP_HEADER_SIZE > MAXIMUM_MTU_SIZE)
				bsOut.WriteCasted<uint16_t>(MAXIMUM_MTU_SIZE);
			else
				bsOut.WriteCasted<uint16_t>(length+UDP_HEADER_SIZE);

//			for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//				rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char*) bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), systemAddress);
			// SocketLayer::SendTo( rakNetSocket, (const char*) bsOut.GetData(), bsOut.GetNumberOfBytesUsed(), systemAddress, _FILE_AND_LINE_ );

			RNS2_SendParameters bsp;
			bsp.data = (char*) bsOut.GetData();
			bsp.length = bsOut.GetNumberOfBytesUsed();
			bsp.systemAddress = systemAddress;
			rakNetSocket->Send(&bsp, _FILE_AND_LINE_);
		}
		else if ((unsigned char)(data)[0] == ID_OPEN_CONNECTION_REQUEST_2)
		{
			SystemAddress bindingAddress;
			RakNetGUID guid;
			RakNet::BitStream bsOut;
			RakNet::BitStream bs((unsigned char*) data, length, false);
			bs.IgnoreBytes(sizeof(MessageID));
			bs.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));

			bool requiresSecurityOfThisClient=false;
#if LIBCAT_SECURITY==1

#endif // LIBCAT_SECURITY

			bs.Read(bindingAddress);
			uint16_t mtu;
			bs.Read(mtu);
			bs.Read(guid);

			RakPeer::RemoteSystemStruct *rssFromSA = rakPeer->GetRemoteSystemFromSystemAddress( systemAddress, true, true );
			bool IPAddrInUse = rssFromSA != 0 && rssFromSA->isActive;
			RakPeer::RemoteSystemStruct *rssFromGuid = rakPeer->GetRemoteSystemFromGUID(guid, true);
			bool GUIDInUse = rssFromGuid != 0 && rssFromGuid->isActive;

			// IPAddrInUse, GuidInUse, outcome
			// TRUE,	  , TRUE	 , ID_OPEN_CONNECTION_REPLY if they are the same, else ID_ALREADY_CONNECTED
			// FALSE,     , TRUE     , ID_ALREADY_CONNECTED (someone else took this guid)
			// TRUE,	  , FALSE	 , ID_ALREADY_CONNECTED (silently disconnected, restarted rakNet)
			// FALSE	  , FALSE	 , Allow connection

			int outcome;
			if (IPAddrInUse & GUIDInUse)
			{
 				if (rssFromSA==rssFromGuid && rssFromSA->connectMode==RakPeer::RemoteSystemStruct::UNVERIFIED_SENDER)
				{
					// ID_OPEN_CONNECTION_REPLY if they are the same
					outcome=1;

					// Note to self: If REQUESTED_CONNECTION, this means two systems attempted to connect to each other at the same time, and one finished first.
					// Returns ID)_CONNECTION_REQUEST_ACCEPTED to one system, and ID_ALREADY_CONNECTED followed by ID_NEW_INCOMING_CONNECTION to another
				}
				else
				{
					// ID_ALREADY_CONNECTED (restarted raknet, connected again from same ip, plus someone else took this guid)
					outcome=2;
				}
			}
			else if (IPAddrInUse==false && GUIDInUse==true)
			{
				// ID_ALREADY_CONNECTED (someone else took this guid)
				outcome=3;
			}
			else if (IPAddrInUse==true && GUIDInUse==false)
			{
				// ID_ALREADY_CONNECTED (silently disconnected, restarted rakNet)
				outcome=4;
			}
			else
			{
				// Allow connection
				outcome=0;
			}

			RakNet::BitStream bsAnswer;
			bsAnswer.Write((MessageID)ID_OPEN_CONNECTION_REPLY_2);
			bsAnswer.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
			bsAnswer.Write(rakPeer->GetGuidFromSystemAddress(UNASSIGNED_SYSTEM_ADDRESS));
			bsAnswer.Write(systemAddress);
			bsAnswer.Write(mtu);
			bsAnswer.Write(requiresSecurityOfThisClient);

			if (outcome==1)
			{
				// Duplicate connection request packet from packetloss
				// Send back the same answer

				unsigned int i;
//				for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//					rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char*) bsAnswer.GetData(), bsAnswer.GetNumberOfBitsUsed(), systemAddress);
				// SocketLayer::SendTo( rakNetSocket, (const char*) bsAnswer.GetData(), bsAnswer.GetNumberOfBytesUsed(), systemAddress, _FILE_AND_LINE_ );

				RNS2_SendParameters bsp;
				bsp.data = (char*) bsAnswer.GetData();
				bsp.length = bsAnswer.GetNumberOfBytesUsed();
				bsp.systemAddress = systemAddress;
				rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

				return true;
			}
			else if (outcome!=0)
			{
				bsOut.Write((MessageID)ID_ALREADY_CONNECTED);
				bsOut.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
				bsOut.Write(rakPeer->myGuid);
//				for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//					rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char*) bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), systemAddress);
				// SocketLayer::SendTo( rakNetSocket, (const char*) bsOut.GetData(), bsOut.GetNumberOfBytesUsed(), systemAddress, _FILE_AND_LINE_ );
				RNS2_SendParameters bsp;
				bsp.data = (char*) bsOut.GetData();
				bsp.length = bsOut.GetNumberOfBytesUsed();
				bsp.systemAddress = systemAddress;
				rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

				return true;
			}

			if (rakPeer->AllowIncomingConnections()==false)
			{
				bsOut.Write((MessageID)ID_NO_FREE_INCOMING_CONNECTIONS);
				bsOut.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
				bsOut.Write(rakPeer->myGuid);
//				for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//					rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char*) bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), systemAddress);
				//SocketLayer::SendTo( rakNetSocket, (const char*) bsOut.GetData(), bsOut.GetNumberOfBytesUsed(), systemAddress, _FILE_AND_LINE_ );
				RNS2_SendParameters bsp;
				bsp.data = (char*) bsOut.GetData();
				bsp.length = bsOut.GetNumberOfBytesUsed();
				bsp.systemAddress = systemAddress;
				rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

				return true;
			}

			bool thisIPConnectedRecently=false;
			rssFromSA = rakPeer->AssignSystemAddressToRemoteSystemList(systemAddress, RakPeer::RemoteSystemStruct::UNVERIFIED_SENDER, rakNetSocket, &thisIPConnectedRecently, bindingAddress, mtu, guid, requiresSecurityOfThisClient);

			if (thisIPConnectedRecently==true)
			{
				bsOut.Write((MessageID)ID_IP_RECENTLY_CONNECTED);
				bsOut.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
				bsOut.Write(rakPeer->myGuid);
//				for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//					rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char*) bsOut.GetData(), bsOut.GetNumberOfBitsUsed(), systemAddress);
				//SocketLayer::SendTo( rakNetSocket, (const char*) bsOut.GetData(), bsOut.GetNumberOfBytesUsed(), systemAddress, _FILE_AND_LINE_ );

				RNS2_SendParameters bsp;
				bsp.data = (char*) bsOut.GetData();
				bsp.length = bsOut.GetNumberOfBytesUsed();
				bsp.systemAddress = systemAddress;
				rakNetSocket->Send(&bsp, _FILE_AND_LINE_);

				return true;
			}

			unsigned int i;
//			for (i=0; i < rakPeer->pluginListNTS.Size(); i++)
//				rakPeer->pluginListNTS[i]->OnDirectSocketSend((const char*) bsAnswer.GetData(), bsAnswer.GetNumberOfBitsUsed(), systemAddress);
			// SocketLayer::SendTo( rakNetSocket, (const char*) bsAnswer.GetData(), bsAnswer.GetNumberOfBytesUsed(), systemAddress, _FILE_AND_LINE_ );
			RNS2_SendParameters bsp;
			bsp.data = (char*) bsAnswer.GetData();
			bsp.length = bsAnswer.GetNumberOfBytesUsed();
			bsp.systemAddress = systemAddress;
			rakNetSocket->Send(&bsp, _FILE_AND_LINE_);
		}
		return true;
	}

	return false;
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void ProcessNetworkPacket( SystemAddress systemAddress, const char *data, const int length, RakPeer *rakPeer, RakNet::TimeUS timeRead, BitStream &updateBitStream )
{
	ProcessNetworkPacket(systemAddress,data,length,rakPeer,rakPeer->socketList[0],timeRead, updateBitStream);
}
void ProcessNetworkPacket( SystemAddress systemAddress, const char *data, const int length, RakPeer *rakPeer, RakNetSocket2* rakNetSocket, RakNet::TimeUS timeRead, BitStream &updateBitStream )
{
	RakAssert(systemAddress.GetPort());
	bool isOfflineMessage;
	if (ProcessOfflineNetworkPacket(systemAddress, data, length, rakPeer, rakNetSocket, &isOfflineMessage, timeRead))
	{
		return;
	}

//	RakNet::Packet *packet;
	RakPeer::RemoteSystemStruct *remoteSystem;

	// See if this datagram came from a connected system
	remoteSystem = rakPeer->GetRemoteSystemFromSystemAddress( systemAddress, true, true );
	if ( remoteSystem )
	{
		// Handle regular incoming data
		// HandleSocketReceiveFromConnectedPlayer is only safe to be called from the same thread as Update, which is this thread
		if ( isOfflineMessage==false)
		{
			remoteSystem->reliabilityLayer.HandleSocketReceiveFromConnectedPlayer(
				data, length, systemAddress, remoteSystem->MTUSize,
				rakNetSocket, &rnr, timeRead, updateBitStream);
		}
	}
	else
	{
		// int a=5;
		// printf("--- Packet from unknown system %s\n", systemAddress.ToString());
	}
}

}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GenerateSeedFromGuid(void)
{
	return (unsigned int) ((myGuid.g >> 32) ^ myGuid.g);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
void RakPeer::DerefAllSockets(void)
{
	unsigned int i;
	for (i=0; i < socketList.Size(); i++)
	{
		delete socketList[i];
	}
	socketList.Clear(false, _FILE_AND_LINE_);
}
// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
unsigned int RakPeer::GetRakNetSocketFromUserConnectionSocketIndex(unsigned int userIndex) const
{
	unsigned int i;
	for (i=0; i < socketList.Size(); i++)
	{
		if (socketList[i]->GetUserConnectionSocketIndex()==userIndex)
			return i;
	}
	RakAssert("GetRakNetSocketFromUserConnectionSocketIndex failed" && 0);
	return (unsigned int) -1;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
bool RakPeer::RunUpdateCycle(BitStream &updateBitStream )
{
	RakPeer::RemoteSystemStruct * remoteSystem;
	unsigned int activeSystemListIndex;
	Packet *packet;

	BitSize_t bitSize;
	unsigned int byteSize;
	unsigned char *data;
	SystemAddress systemAddress;
	BufferedCommandStruct *bcs;
	bool callerDataAllocationUsed;
	RakNetStatistics *rnss;
	RakNet::TimeUS timeNS=0;
	RakNet::Time timeMS=0;

	// This is here so RecvFromBlocking actually gets data from the same thread
	if (((RNS2_Windows*)socketList[0])->GetSocketLayerOverride())
	{
		int len;
		SystemAddress sender;
		char dataOut[ MAXIMUM_MTU_SIZE ];
		do {
			len = ((RNS2_Windows*)socketList[0])->GetSocketLayerOverride()->RakNetRecvFrom(dataOut,&sender,true);
			if (len>0)
				ProcessNetworkPacket( sender, dataOut, len, this, socketList[0], RakNet::GetTimeUS(), updateBitStream );
		} while (len>0);
	}


//	unsigned int socketListIndex;
	RNS2RecvStruct *recvFromStruct;
	while ((recvFromStruct=PopBufferedPacket())!=0)
	{
			ProcessNetworkPacket(recvFromStruct->systemAddress, recvFromStruct->data, recvFromStruct->bytesRead, this, recvFromStruct->socket, recvFromStruct->timeRead, updateBitStream);
			DeallocRNS2RecvStruct(recvFromStruct, _FILE_AND_LINE_);
	}

	while ((bcs=bufferedCommands.PopInaccurate())!=0)
	{
		if (bcs->command==BufferedCommandStruct::BCS_SEND)
		{
			// GetTime is a very slow call so do it once and as late as possible
			if (timeNS==0)
			{
				timeNS = RakNet::GetTimeUS();
				timeMS = (RakNet::TimeMS)(timeNS/(RakNet::TimeUS)1000);
			}

			callerDataAllocationUsed=SendImmediate((char*)bcs->data, bcs->numberOfBitsToSend, bcs->priority, bcs->reliability, bcs->orderingChannel, bcs->systemIdentifier, bcs->broadcast, true, timeNS, bcs->receipt);
			if ( callerDataAllocationUsed==false )
				rakFree_Ex(bcs->data, _FILE_AND_LINE_ );

			// Set the new connection state AFTER we call sendImmediate in case we are setting it to a disconnection state, which does not allow further sends
			if (bcs->connectionMode!=RemoteSystemStruct::NO_ACTION )
			{
				remoteSystem=GetRemoteSystem( bcs->systemIdentifier, true, true );
				if (remoteSystem)
					remoteSystem->connectMode=bcs->connectionMode;
			}
		}
		else if (bcs->command==BufferedCommandStruct::BCS_CLOSE_CONNECTION)
		{
			CloseConnectionInternal(bcs->systemIdentifier, false, true, bcs->orderingChannel, bcs->priority);
		}
// 		else if (bcs->command==BufferedCommandStruct::BCS_CHANGE_SYSTEM_ADDRESS)
// 		{
// 			// Reroute
// 			RakPeer::RemoteSystemStruct *rssFromGuid = GetRemoteSystem(bcs->systemIdentifier.rakNetGuid,true,true);
// 			if (rssFromGuid!=0)
// 			{
// 				unsigned int existingSystemIndex = GetRemoteSystemIndex(rssFromGuid->systemAddress);
// 				ReferenceRemoteSystem(bcs->systemIdentifier.systemAddress, existingSystemIndex);
// 			}
// 		}
// 		else if (bcs->command==BufferedCommandStruct::BCS_GET_SOCKET)
// 		{
// 			SocketQueryOutput *sqo;
// 			if (bcs->systemIdentifier.IsUndefined())
// 			{
// 				sqo = socketQueryOutput.Allocate( _FILE_AND_LINE_ );
// 				sqo->sockets=socketList;
// 				socketQueryOutput.Push(sqo);
// 			}
// 			else
// 			{
// 				remoteSystem=GetRemoteSystem( bcs->systemIdentifier, true, true );
// 				sqo = socketQueryOutput.Allocate( _FILE_AND_LINE_ );
// 
// 				sqo->sockets.Clear(false, _FILE_AND_LINE_);
// 				if (remoteSystem)
// 				{
// 					sqo->sockets.Push(remoteSystem->rakNetSocket, _FILE_AND_LINE_ );
// 				}
// 				else
// 				{
// 					// Leave empty smart pointer
// 				}
// 				socketQueryOutput.Push(sqo);
// 			}
// 
// 		}

		bufferedCommands.Deallocate(bcs, _FILE_AND_LINE_);
	}

	if (requestedConnectionQueue.IsEmpty()==false)
	{
		if (timeNS==0)
		{
			timeNS = RakNet::GetTimeUS();
			timeMS = (RakNet::TimeMS)(timeNS/(RakNet::TimeUS)1000);
		}

		bool condition1, condition2;
		unsigned requestedConnectionQueueIndex=0;
		requestedConnectionQueueMutex.Lock();
		while (requestedConnectionQueueIndex < requestedConnectionQueue.Size())
		{
			RequestedConnectionStruct *rcs;
			rcs = requestedConnectionQueue[requestedConnectionQueueIndex];
			requestedConnectionQueueMutex.Unlock();
			if (rcs->nextRequestTime < timeMS)
			{
				condition1=rcs->requestsMade==rcs->sendConnectionAttemptCount+1;
				condition2=(bool)((rcs->systemAddress==UNASSIGNED_SYSTEM_ADDRESS)==1);
				// If too many requests made or a hole then remove this if possible, otherwise invalidate it
				if (condition1 || condition2)
				{
					if (rcs->data)
					{
						rakFree_Ex(rcs->data, _FILE_AND_LINE_ );
						rcs->data=0;
					}

					if (condition1 && !condition2 && rcs->actionToTake==RequestedConnectionStruct::CONNECT)
					{
						// Tell user of connection attempt failed
						packet=AllocPacket(sizeof( char ), _FILE_AND_LINE_);
						packet->data[ 0 ] = ID_CONNECTION_ATTEMPT_FAILED; // Attempted a connection and couldn't
						packet->bitSize = ( sizeof(	 char ) * 8);
						packet->systemAddress = rcs->systemAddress;
						AddPacketToProducer(packet);
					}

					RakNet::OP_DELETE(rcs,_FILE_AND_LINE_);

					requestedConnectionQueueMutex.Lock();
					for (unsigned int k=0; k < requestedConnectionQueue.Size(); k++)
					{
						if (requestedConnectionQueue[k]==rcs)
						{
							requestedConnectionQueue.RemoveAtIndex(k);
							break;
						}
					}
					requestedConnectionQueueMutex.Unlock();
				}
				else
				{

					int MTUSizeIndex = rcs->requestsMade / (rcs->sendConnectionAttemptCount/NUM_MTU_SIZES);
					if (MTUSizeIndex>=NUM_MTU_SIZES)
						MTUSizeIndex=NUM_MTU_SIZES-1;
					rcs->requestsMade++;
					rcs->nextRequestTime=timeMS+rcs->timeBetweenSendConnectionAttemptsMS;

					RakNet::BitStream bitStream;
					//WriteOutOfBandHeader(&bitStream, ID_USER_PACKET_ENUM);
					bitStream.Write((MessageID)ID_OPEN_CONNECTION_REQUEST_1);
					bitStream.WriteAlignedBytes((const unsigned char*) OFFLINE_MESSAGE_DATA_ID, sizeof(OFFLINE_MESSAGE_DATA_ID));
					bitStream.Write((MessageID)RAKNET_PROTOCOL_VERSION);
					bitStream.PadWithZeroToByteLength(mtuSizes[MTUSizeIndex]-UDP_HEADER_SIZE);

					char str[256];
					rcs->systemAddress.ToString(true,str);

					//RAKNET_DEBUG_PRINTF("%i:IOCR, ", __LINE__);

					unsigned i;
//					for (i=0; i < pluginListNTS.Size(); i++)
//						pluginListNTS[i]->OnDirectSocketSend((const char*) bitStream.GetData(), bitStream.GetNumberOfBitsUsed(), rcs->systemAddress);

					RakNetSocket2 *socketToUse;
					if (rcs->socket == 0)
						socketToUse = socketList[rcs->socketIndex];
					else
						socketToUse = rcs->socket;

					rcs->systemAddress.FixForIPVersion(socketToUse->GetBoundAddress());

					if (socketToUse->IsBerkleySocket())
						((RNS2_Berkley*)socketToUse)->SetDoNotFragment(1);

//					SocketLayer::SetDoNotFragment(socketToUse, 1);
					RakNet::Time sendToStart=RakNet::GetTime();

					RNS2_SendParameters bsp;
					bsp.data = (char*) bitStream.GetData();
					bsp.length = bitStream.GetNumberOfBytesUsed();
					bsp.systemAddress = rcs->systemAddress;
					if (socketToUse->Send(&bsp, _FILE_AND_LINE_) == 10040)
					// if (SocketLayer::SendTo( socketToUse, (const char*) bitStream.GetData(), bitStream.GetNumberOfBytesUsed(), rcs->systemAddress, _FILE_AND_LINE_ )==-10040)
					{
						// Don't use this MTU size again
						rcs->requestsMade = (unsigned char) ((MTUSizeIndex + 1) * (rcs->sendConnectionAttemptCount/NUM_MTU_SIZES));
						rcs->nextRequestTime=timeMS;
					}
					else
					{
						RakNet::Time sendToEnd=RakNet::GetTime();
						if (sendToEnd-sendToStart>100)
						{
							// Drop to lowest MTU
							int lowestMtuIndex = rcs->sendConnectionAttemptCount/NUM_MTU_SIZES * (NUM_MTU_SIZES - 1);
							if (lowestMtuIndex > rcs->requestsMade)
							{
								rcs->requestsMade = (unsigned char) lowestMtuIndex;
								rcs->nextRequestTime=timeMS;
							}
							else
								rcs->requestsMade=(unsigned char)(rcs->sendConnectionAttemptCount+1);
						}
					}
					// SocketLayer::SetDoNotFragment(socketToUse, 0);
					if (socketToUse->IsBerkleySocket())
						((RNS2_Berkley*)socketToUse)->SetDoNotFragment(0);

					requestedConnectionQueueIndex++;
				}
			}
			else
				requestedConnectionQueueIndex++;

			requestedConnectionQueueMutex.Lock();
		}
		requestedConnectionQueueMutex.Unlock();
	}

	// remoteSystemList in network thread
	for ( activeSystemListIndex = 0; activeSystemListIndex < activeSystemListSize; ++activeSystemListIndex )
	//for ( remoteSystemIndex = 0; remoteSystemIndex < remoteSystemListSize; ++remoteSystemIndex )
	{
			// Found an active remote system
			remoteSystem = activeSystemList[ activeSystemListIndex ];
			systemAddress = remoteSystem->systemAddress;
			RakAssert(systemAddress!=UNASSIGNED_SYSTEM_ADDRESS);
			// Update is only safe to call from the same thread that calls HandleSocketReceiveFromConnectedPlayer,
			// which is this thread

			if (timeNS==0)
			{
				timeNS = RakNet::GetTimeUS();
				timeMS = (RakNet::TimeMS)(timeNS/(RakNet::TimeUS)1000);
				//RAKNET_DEBUG_PRINTF("timeNS = %I64i timeMS=%i\n", timeNS, timeMS);
			}


			if (timeMS > remoteSystem->lastReliableSend && timeMS-remoteSystem->lastReliableSend > remoteSystem->reliabilityLayer.GetTimeoutTime()/2 && remoteSystem->connectMode==RemoteSystemStruct::CONNECTED)
			{
				// If no reliable packets are waiting for an ack, do a one byte reliable send so that disconnections are noticed
				RakNetStatistics rakNetStatistics;
				rnss=remoteSystem->reliabilityLayer.GetStatistics(&rakNetStatistics);
				if (rnss->messagesInResendBuffer==0)
				{
					PingInternal( systemAddress, true, RELIABLE );

					//remoteSystem->lastReliableSend=timeMS+remoteSystem->reliabilityLayer.GetTimeoutTime();
					remoteSystem->lastReliableSend=timeMS;
				}
			}

			remoteSystem->reliabilityLayer.Update( remoteSystem->rakNetSocket, systemAddress, remoteSystem->MTUSize, timeNS, maxOutgoingBPS, &rnr, updateBitStream ); // systemAddress only used for the internet simulator test

			// Check for failure conditions
			if ( remoteSystem->reliabilityLayer.IsDeadConnection() ||
				((remoteSystem->connectMode==RemoteSystemStruct::DISCONNECT_ASAP || remoteSystem->connectMode==RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY) && remoteSystem->reliabilityLayer.IsOutgoingDataWaiting()==false) ||
				(remoteSystem->connectMode==RemoteSystemStruct::DISCONNECT_ON_NO_ACK && (remoteSystem->reliabilityLayer.AreAcksWaiting()==false || remoteSystem->reliabilityLayer.AckTimeout(timeMS)==true)) ||
				((
				(remoteSystem->connectMode==RemoteSystemStruct::REQUESTED_CONNECTION ||
				remoteSystem->connectMode==RemoteSystemStruct::HANDLING_CONNECTION_REQUEST ||
				remoteSystem->connectMode==RemoteSystemStruct::UNVERIFIED_SENDER)
				&& timeMS > remoteSystem->connectionTime && timeMS - remoteSystem->connectionTime > 10000))
				)
			{
			//	RAKNET_DEBUG_PRINTF("timeMS=%i remoteSystem->connectionTime=%i\n", timeMS, remoteSystem->connectionTime );

				// Failed.  Inform the user?
				// TODO - RakNet 4.0 - Return a different message identifier for DISCONNECT_ASAP_SILENTLY and DISCONNECT_ASAP than for DISCONNECT_ON_NO_ACK
				// The first two mean we called CloseConnection(), the last means the other system sent us ID_DISCONNECTION_NOTIFICATION
				if (remoteSystem->connectMode==RemoteSystemStruct::CONNECTED || remoteSystem->connectMode==RemoteSystemStruct::REQUESTED_CONNECTION
					|| remoteSystem->connectMode==RemoteSystemStruct::DISCONNECT_ASAP || remoteSystem->connectMode==RemoteSystemStruct::DISCONNECT_ON_NO_ACK)
				{

//					RakNet::BitStream undeliveredMessages;
//					remoteSystem->reliabilityLayer.GetUndeliveredMessages(&undeliveredMessages,remoteSystem->MTUSize);

//					packet=AllocPacket(sizeof( char ) + undeliveredMessages.GetNumberOfBytesUsed());
					packet=AllocPacket(sizeof( char ), _FILE_AND_LINE_);
					if (remoteSystem->connectMode==RemoteSystemStruct::REQUESTED_CONNECTION)
						packet->data[ 0 ] = ID_CONNECTION_ATTEMPT_FAILED; // Attempted a connection and couldn't
					else if (remoteSystem->connectMode==RemoteSystemStruct::CONNECTED)
						packet->data[ 0 ] = ID_CONNECTION_LOST; // DeadConnection
					else
						packet->data[ 0 ] = ID_DISCONNECTION_NOTIFICATION; // DeadConnection

//					memcpy(packet->data+1, undeliveredMessages.GetData(), undeliveredMessages.GetNumberOfBytesUsed());

					packet->guid = remoteSystem->guid;
					packet->systemAddress = systemAddress;
					packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
					packet->guid.systemIndex=packet->systemAddress.systemIndex;

					AddPacketToProducer(packet);
				}
				// else connection shutting down, don't bother telling the user

				CloseConnectionInternal( systemAddress, false, true, 0, LOW_PRIORITY );
				continue;
			}

			// Ping this guy if it is time to do so
			if ( remoteSystem->connectMode==RemoteSystemStruct::CONNECTED && timeMS > remoteSystem->nextPingTime && ( occasionalPing || remoteSystem->lowestPing == (unsigned short)-1 ) )
			{
				remoteSystem->nextPingTime = timeMS + 5000;
				PingInternal( systemAddress, true, UNRELIABLE );

				// Update again immediately after this tick so the ping goes out right away
				quitAndDataEvents.SetEvent();
			}

			// Find whoever has the lowest player ID
			//if (systemAddress < authoritativeClientSystemAddress)
			// authoritativeClientSystemAddress=systemAddress;

			// Does the reliability layer have any packets waiting for us?
			// To be thread safe, this has to be called in the same thread as HandleSocketReceiveFromConnectedPlayer
			bitSize = remoteSystem->reliabilityLayer.Receive( &data );

			while ( bitSize > 0 )
			{
				// These types are for internal use and should never arrive from a network packet
				if (data[0]==ID_CONNECTION_ATTEMPT_FAILED)
				{
					RakAssert(0);
					bitSize=0;
					continue;
				}

				// Fast and easy - just use the data that was returned
				byteSize = (unsigned int) BITS_TO_BYTES( bitSize );

				// For unknown senders we only accept a few specific packets
				if (remoteSystem->connectMode==RemoteSystemStruct::UNVERIFIED_SENDER)
				{
					if ( (unsigned char)(data)[0] == ID_CONNECTION_REQUEST )
					{
 						ParseConnectionRequestPacket(remoteSystem, systemAddress, (const char*)data, byteSize);
						rakFree_Ex(data, _FILE_AND_LINE_ );
					}
					else
					{
						CloseConnectionInternal( systemAddress, false, true, 0, LOW_PRIORITY );

						char str1[64];
						systemAddress.ToString(false, str1);
						//AddToBanList(str1, remoteSystem->reliabilityLayer.GetTimeoutTime());


						rakFree_Ex(data, _FILE_AND_LINE_ );
					}
				}
				else
				{
					// However, if we are connected we still take a connection request in case both systems are trying to connect to each other
					// at the same time
					if ( (unsigned char)(data)[0] == ID_CONNECTION_REQUEST )
					{
						// 04/27/06 This is wrong.  With cross connections, we can both have initiated the connection are in state REQUESTED_CONNECTION
						// 04/28/06 Downgrading connections from connected will close the connection due to security at ((remoteSystem->connectMode!=RemoteSystemStruct::CONNECTED && time > remoteSystem->connectionTime && time - remoteSystem->connectionTime > 10000))
						if (remoteSystem->connectMode==RemoteSystemStruct::REQUESTED_CONNECTION)
						{
							ParseConnectionRequestPacket(remoteSystem, systemAddress, (const char*)data, byteSize);
						}
						else
						{

							RakNet::BitStream bs((unsigned char*) data,byteSize,false);
							bs.IgnoreBytes(sizeof(MessageID));
							bs.IgnoreBytes(sizeof(OFFLINE_MESSAGE_DATA_ID));
							bs.IgnoreBytes(RakNetGUID::size());
							RakNet::Time incomingTimestamp;
							bs.Read(incomingTimestamp);

							// Got a connection request message from someone we are already connected to. Just reply normally.
							// This can happen due to race conditions with the fully connected mesh
							OnConnectionRequest( remoteSystem, incomingTimestamp );
						}
						rakFree_Ex(data, _FILE_AND_LINE_ );
					}
					else if ( (unsigned char) data[ 0 ] == ID_NEW_INCOMING_CONNECTION && byteSize > sizeof(unsigned char)+sizeof(unsigned int)+sizeof(unsigned short)+sizeof(RakNet::Time)*2 )
					{
						if (remoteSystem->connectMode==RemoteSystemStruct::HANDLING_CONNECTION_REQUEST)
						{
							remoteSystem->connectMode=RemoteSystemStruct::CONNECTED;
							PingInternal( systemAddress, true, UNRELIABLE );

							// Update again immediately after this tick so the ping goes out right away
							quitAndDataEvents.SetEvent();

							RakNet::BitStream inBitStream((unsigned char *) data, byteSize, false);
							SystemAddress bsSystemAddress;

							inBitStream.IgnoreBits(8);
							inBitStream.Read(bsSystemAddress);
							for (unsigned int i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
								inBitStream.Read(remoteSystem->theirInternalSystemAddress[i]);

							RakNet::Time sendPingTime, sendPongTime;
							inBitStream.Read(sendPingTime);
							inBitStream.Read(sendPongTime);
							OnConnectedPong(sendPingTime,sendPongTime,remoteSystem);

							// Overwrite the data in the packet
							//					NewIncomingConnectionStruct newIncomingConnectionStruct;
							//					RakNet::BitStream nICS_BS( data, NewIncomingConnectionStruct_Size, false );
							//					newIncomingConnectionStruct.Deserialize( nICS_BS );

							remoteSystem->myExternalSystemAddress = bsSystemAddress;

							// Bug: If A connects to B through R, A's firstExternalID is set to R. If A tries to send to R, sends to loopback because R==firstExternalID
							// Correct fix is to specify in Connect() if target is through a proxy.
							// However, in practice you have to connect to something else first anyway to know about the proxy. So setting once only is good enough
							if (firstExternalID==UNASSIGNED_SYSTEM_ADDRESS)
							{
								firstExternalID=bsSystemAddress;
								firstExternalID.debugPort=ntohs(firstExternalID.address.addr4.sin_port);
							}

							// Send this info down to the game
							packet=AllocPacket(byteSize, data, _FILE_AND_LINE_);
							packet->bitSize = bitSize;
							packet->systemAddress = systemAddress;
							packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
							packet->guid = remoteSystem->guid;
							packet->guid.systemIndex=packet->systemAddress.systemIndex;
							AddPacketToProducer(packet);
						}
						else
						{
							// Send to game even if already connected. This could happen when connecting to 127.0.0.1
							// Ignore, already connected
						//	rakFree_Ex(data, _FILE_AND_LINE_ );
						}
					}
					else if ( (unsigned char) data[ 0 ] == ID_CONNECTED_PONG && byteSize == sizeof(unsigned char)+sizeof(RakNet::Time)*2 )
					{
						RakNet::Time sendPingTime, sendPongTime;

						// Copy into the ping times array the current time - the value returned
						// First extract the sent ping
						RakNet::BitStream inBitStream( (unsigned char *) data, byteSize, false );
						//PingStruct ps;
						//ps.Deserialize(psBS);
						inBitStream.IgnoreBits(8);
						inBitStream.Read(sendPingTime);
						inBitStream.Read(sendPongTime);

						OnConnectedPong(sendPingTime,sendPongTime,remoteSystem);

						rakFree_Ex(data, _FILE_AND_LINE_ );
					}
					else if ( (unsigned char)data[0] == ID_CONNECTED_PING && byteSize == sizeof(unsigned char)+sizeof(RakNet::Time) )
					{
						RakNet::BitStream inBitStream( (unsigned char *) data, byteSize, false );
 						inBitStream.IgnoreBits(8);
						RakNet::Time sendPingTime;
						inBitStream.Read(sendPingTime);

						RakNet::BitStream outBitStream;
						outBitStream.Write((MessageID)ID_CONNECTED_PONG);
						outBitStream.Write(sendPingTime);
						outBitStream.Write(RakNet::GetTime());
						SendImmediate( (char*)outBitStream.GetData(), outBitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, UNRELIABLE, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0 );

						// Update again immediately after this tick so the ping goes out right away
						quitAndDataEvents.SetEvent();

						rakFree_Ex(data, _FILE_AND_LINE_ );
					}
					else if ( (unsigned char) data[ 0 ] == ID_DISCONNECTION_NOTIFICATION )
					{
						// We shouldn't close the connection immediately because we need to ack the ID_DISCONNECTION_NOTIFICATION
						remoteSystem->connectMode=RemoteSystemStruct::DISCONNECT_ON_NO_ACK;
						rakFree_Ex(data, _FILE_AND_LINE_ );

					//	AddPacketToProducer(packet);
					}
					else if ( (unsigned char)(data)[0] == ID_DETECT_LOST_CONNECTIONS && byteSize == sizeof(unsigned char) )
					{
						// Do nothing
						rakFree_Ex(data, _FILE_AND_LINE_ );
					}
					else if ( (unsigned char)(data)[0] == ID_INVALID_PASSWORD )
					{
						if (remoteSystem->connectMode==RemoteSystemStruct::REQUESTED_CONNECTION)
						{
							packet=AllocPacket(byteSize, data, _FILE_AND_LINE_);
							packet->bitSize = bitSize;
							packet->systemAddress = systemAddress;
							packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
							packet->guid = remoteSystem->guid;
							packet->guid.systemIndex=packet->systemAddress.systemIndex;
							AddPacketToProducer(packet);

							remoteSystem->connectMode=RemoteSystemStruct::DISCONNECT_ASAP_SILENTLY;
						}
						else
						{
							rakFree_Ex(data, _FILE_AND_LINE_ );
						}
					}
					else if ( (unsigned char)(data)[0] == ID_CONNECTION_REQUEST_ACCEPTED )
					{
						if (byteSize > sizeof(MessageID)+sizeof(unsigned int)+sizeof(unsigned short)+sizeof(SystemIndex)+sizeof(RakNet::Time)*2)
						{
							// Make sure this connection accept is from someone we wanted to connect to
							bool allowConnection, alreadyConnected;

							if (remoteSystem->connectMode==RemoteSystemStruct::HANDLING_CONNECTION_REQUEST ||
								remoteSystem->connectMode==RemoteSystemStruct::REQUESTED_CONNECTION ||
								allowConnectionResponseIPMigration)
								allowConnection=true;
							else
								allowConnection=false;

							if (remoteSystem->connectMode==RemoteSystemStruct::HANDLING_CONNECTION_REQUEST)
								alreadyConnected=true;
							else
								alreadyConnected=false;

							if ( allowConnection )
							{
								SystemAddress externalID;
								SystemIndex systemIndex;
//								SystemAddress internalID;

								RakNet::BitStream inBitStream((unsigned char *) data, byteSize, false);
								inBitStream.IgnoreBits(8);
								//	inBitStream.Read(remotePort);
								inBitStream.Read(externalID);
								inBitStream.Read(systemIndex);
								for (unsigned int i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
									inBitStream.Read(remoteSystem->theirInternalSystemAddress[i]);

								RakNet::Time sendPingTime, sendPongTime;
								inBitStream.Read(sendPingTime);
								inBitStream.Read(sendPongTime);
								OnConnectedPong(sendPingTime, sendPongTime, remoteSystem);

								// Find a free remote system struct to use
								//						RakNet::BitStream casBitS(data, byteSize, false);
								//						ConnectionAcceptStruct cas;
								//						cas.Deserialize(casBitS);
								//	systemAddress.GetPort() = remotePort;

								// The remote system told us our external IP, so save it
								remoteSystem->myExternalSystemAddress = externalID;
								remoteSystem->connectMode=RemoteSystemStruct::CONNECTED;

								// Bug: If A connects to B through R, A's firstExternalID is set to R. If A tries to send to R, sends to loopback because R==firstExternalID
								// Correct fix is to specify in Connect() if target is through a proxy.
								// However, in practice you have to connect to something else first anyway to know about the proxy. So setting once only is good enough
								if (firstExternalID==UNASSIGNED_SYSTEM_ADDRESS)
								{
									firstExternalID=externalID;
									firstExternalID.debugPort=ntohs(firstExternalID.address.addr4.sin_port);
								}

								// Send the connection request complete to the game
								packet=AllocPacket(byteSize, data, _FILE_AND_LINE_);
								packet->bitSize = byteSize * 8;
								packet->systemAddress = systemAddress;
								packet->systemAddress.systemIndex = ( SystemIndex ) GetIndexFromSystemAddress( systemAddress, true );
								packet->guid = remoteSystem->guid;
								packet->guid.systemIndex=packet->systemAddress.systemIndex;
								AddPacketToProducer(packet);

								RakNet::BitStream outBitStream;
								outBitStream.Write((MessageID)ID_NEW_INCOMING_CONNECTION);
								outBitStream.Write(systemAddress);
								for (unsigned int i=0; i < MAXIMUM_NUMBER_OF_INTERNAL_IDS; i++)
									outBitStream.Write(ipList[i]);
								outBitStream.Write(sendPongTime);
								outBitStream.Write(RakNet::GetTime());

								SendImmediate( (char*)outBitStream.GetData(), outBitStream.GetNumberOfBitsUsed(), IMMEDIATE_PRIORITY, RELIABLE_ORDERED, 0, systemAddress, false, false, RakNet::GetTimeUS(), 0 );

								if (alreadyConnected==false)
								{
									PingInternal( systemAddress, true, UNRELIABLE );
								}
							}
							else
							{
								// Ignore, already connected
								rakFree_Ex(data, _FILE_AND_LINE_ );
							}
						}
						else
						{
							// Version mismatch error?
							RakAssert(0);
							rakFree_Ex(data, _FILE_AND_LINE_ );
						}
					}
					else
					{
						// What do I do if I get a message from a system, before I am fully connected?
						// I can either ignore it or give it to the user
						// It seems like giving it to the user is a better option
						if ((data[0]>=(MessageID)ID_TIMESTAMP || data[0]==ID_SND_RECEIPT_ACKED || data[0]==ID_SND_RECEIPT_LOSS) &&
							remoteSystem->isActive
							)
						{
							packet=AllocPacket(byteSize, data, _FILE_AND_LINE_);
							packet->bitSize = bitSize;
							packet->systemAddress = systemAddress;
							packet->systemAddress.systemIndex = remoteSystem->remoteSystemIndex;
							packet->guid = remoteSystem->guid;
							packet->guid.systemIndex=packet->systemAddress.systemIndex;
							AddPacketToProducer(packet);
						}
						else
						{
							rakFree_Ex(data, _FILE_AND_LINE_ );
						}
					}
				}

				// Does the reliability layer have any more packets waiting for us?
				// To be thread safe, this has to be called in the same thread as HandleSocketReceiveFromConnectedPlayer
				bitSize = remoteSystem->reliabilityLayer.Receive( &data );
			}
		
	}

	return true;
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

void RakPeer::OnRNS2Recv(RNS2RecvStruct *recvStruct)
{
// 	if (incomingDatagramEventHandler)
// 	{
// 		if (incomingDatagramEventHandler(recvStruct)!=true)
// 			return;
// 	}

	PushBufferedPacket(recvStruct);
	quitAndDataEvents.SetEvent();
}

// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
RAK_THREAD_DECLARATION(RakNet::UpdateNetworkLoop)
{
	RakPeer * rakPeer = ( RakPeer * ) arguments;

	BitStream updateBitStream( MAXIMUM_MTU_SIZE );
// 
	rakPeer->isMainLoopThreadActive = true;

	while ( rakPeer->endThreads == false )
	{
// 		if (rakPeer->userUpdateThreadPtr)
// 			rakPeer->userUpdateThreadPtr(rakPeer, rakPeer->userUpdateThreadData);

		rakPeer->RunUpdateCycle(updateBitStream);

		// Pending sends go out this often, unless quitAndDataEvents is set
		rakPeer->quitAndDataEvents.WaitOnEvent(10);
	}

	rakPeer->isMainLoopThreadActive = false;

	return 0;

}

void RakPeer::FillIPList(void)
{
	if (ipList[0]!=UNASSIGNED_SYSTEM_ADDRESS)
		return;

	// Fill out ipList structure
	RakNetSocket2::GetMyIP( ipList );

	// Sort the addresses from lowest to highest
	int startingIdx = 0;
	while (startingIdx < MAXIMUM_NUMBER_OF_INTERNAL_IDS-1 && ipList[startingIdx] != UNASSIGNED_SYSTEM_ADDRESS)
	{
		int lowestIdx = startingIdx;
		for (int curIdx = startingIdx + 1; curIdx < MAXIMUM_NUMBER_OF_INTERNAL_IDS-1 && ipList[curIdx] != UNASSIGNED_SYSTEM_ADDRESS; curIdx++ )
		{
			if (ipList[curIdx] < ipList[startingIdx])
			{
				lowestIdx = curIdx;
			}
		}
		if (startingIdx != lowestIdx)
		{
			SystemAddress temp = ipList[startingIdx];
			ipList[startingIdx] = ipList[lowestIdx];
			ipList[lowestIdx] = temp;
		}
		++startingIdx;
	}
}

#ifdef _MSC_VER
#pragma warning( pop )
#endif
