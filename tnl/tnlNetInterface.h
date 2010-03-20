//-----------------------------------------------------------------------------------
//
//   Torque Network Library
//   Copyright (C) 2004 GarageGames.com, Inc.
//   For more information see http://www.opentnl.org
//
//   This program is free software; you can redistribute it and/or modify
//   it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; either version 2 of the License, or
//   (at your option) any later version.
//
//   For use in products that are not compatible with the terms of the GNU 
//   General Public License, alternative licensing options are available 
//   from GarageGames.com.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of the GNU General Public License
//   along with this program; if not, write to the Free Software
//   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
//------------------------------------------------------------------------------------

#ifndef _TNL_NETINTERFACE_H_
#define _TNL_NETINTERFACE_H_

#ifndef _TNL_VECTOR_H_
#include "tnlVector.h"
#endif

#ifndef _TNL_NETBASE_H_
#include "tnlNetBase.h"
#endif

#include "tnlClientPuzzle.h"

#ifndef _TNL_NETOBJECT_H_
#include "tnlNetObject.h"
#endif

#ifndef _TNL_NETCONNECTION_H_
#include "tnlNetConnection.h"
#endif

namespace TNL {

class AsymmetricKey;
class Certificate;
struct ConnectionParameters;

/// NetInterface class.  Wraps a torque socket and manages higher-level TNL connections
///
class NetInterface : public Object
{
   friend class NetConnection;
public:

protected:
   Vector<NetConnection *> mConnectionList;      ///< List of all the connections that are in a connected state on this NetInterface.
   Vector<NetConnection *> mConnectionHashTable; ///< A resizable hash table for all connected connections.  This is a flat hash table (no buckets).

   Vector<NetConnection *> mPendingConnections; ///< List of connections that are in the startup state, where the remote host has not fully
                                                ///  validated the connection.

   RefPtr<AsymmetricKey> mPrivateKey;  ///< The private key used by this NetInterface for secure key exchange.
   RefPtr<Certificate> mCertificate;   ///< A certificate, signed by some Certificate Authority, to authenticate this host.
   ClientPuzzleManager mPuzzleManager; ///< The object that tracks the current client puzzle difficulty, current puzzle and solutions for this NetInterface.

   /// @name NetInterfaceSocket Socket
   ///
   /// State regarding the socket this NetInterface controls.
   ///
   /// @{

   ///
   Socket    mSocket;   ///< Network socket this NetInterface communicates over.

   /// @}

   U32 mCurrentTime;            ///< Current time tracked by this NetInterface.
   bool mRequiresKeyExchange;   ///< True if all connections outgoing and incoming require key exchange.
   U32  mLastTimeoutCheckTime;  ///< Last time all the active connections were checked for timeouts.
   U8  mRandomHashData[12];    ///< Data that gets hashed with connect challenge requests to prevent connection spoofing.
   bool mAllowConnections;      ///< Set if this NetInterface allows connections from remote instances.

   /// Structure used to track packets that are delayed in sending for simulating a high-latency connection.
   ///
   /// The DelaySendPacket is allocated as sizeof(DelaySendPacket) + packetSize;
   struct DelaySendPacket
   {
      DelaySendPacket *nextPacket; ///< The next packet in the list of delayed packets.
      Address remoteAddress;    ///< The address to send this packet to.
      U32 sendTime;                ///< Time when we should send the packet.
      U32 packetSize;              ///< Size, in bytes, of the packet data.
      U8 packetData[1];            ///< Packet data.
   };
   DelaySendPacket *mSendPacketList; ///< List of delayed packets pending to send.

   enum NetInterfaceConstants {
      ChallengeRetryCount = 4,     ///< Number of times to send connect challenge requests before giving up.
      ChallengeRetryTime = 2500,   ///< Timeout interval in milliseconds before retrying connect challenge.

      ConnectRetryCount = 4,       ///< Number of times to send connect requests before giving up.
      ConnectRetryTime = 2500,     ///< Timeout interval in milliseconds before retrying connect request.

      PunchRetryCount = 6,         ///< Number of times to send groups of firewall punch packets before giving up.
      PunchRetryTime = 2500,       ///< Timeout interval in milliseconds before retrying punch sends.

      TimeoutCheckInterval = 1500, ///< Interval in milliseconds between checking for connection timeouts.
      PuzzleSolutionTimeout = 30000, ///< If the server gives us a puzzle that takes more than 30 seconds, time out.
   };

   /// Computes an identity token for the connecting client based on the address of the client and the
   /// client's unique nonce value.
   U32 computeClientIdentityToken(const Address &theAddress, const Nonce &theNonce);

   /// Finds a connection instance that this NetInterface has initiated.
   NetConnection *findPendingConnection(const Address &address);

   /// Adds a connection the list of pending connections.
   void addPendingConnection(NetConnection *conn);

   /// Removes a connection from the list of pending connections.
   void removePendingConnection(NetConnection *conn);

   /// Finds a connection by address from the pending list and removes it.
   void findAndRemovePendingConnection(const Address &address);

   /// Adds a connection to the internal connection list.
   void addConnection(NetConnection *connection);

   /// Remove a connection from the list.
   void removeConnection(NetConnection *connection);

   /// Begins the connection handshaking process for a connection.  Called from NetConnection::connect()
   void startConnection(NetConnection *conn);

   /// Sends a connect challenge request on behalf of the connection to the remote host.
   void sendConnectChallengeRequest(NetConnection *conn);

   /// Handles a connect challenge request by replying to the requestor of a connection with a
   /// unique token for that connection, as well as (possibly) a client puzzle (for DoS prevention),
   /// or this NetInterface's public key.
   void handleConnectChallengeRequest(const Address &addr, BitStream *stream);

   /// Sends a connect challenge request to the specified address.  This can happen as a result
   /// of receiving a connect challenge request, or during an "arranged" connection for the non-initiator
   /// of the connection.
   void sendConnectChallengeResponse(const Address &addr, Nonce &clientNonce, bool wantsKeyExchange, bool wantsCertificate);

   /// Processes a ConnectChallengeResponse, by issueing a connect request if it was for
   /// a connection this NetInterface has pending.
   void handleConnectChallengeResponse(const Address &address, BitStream *stream);

   /// Continues computation of the solution of a client puzzle, and issues a connect request
   /// when the solution is found.
   void continuePuzzleSolution(NetConnection *conn);

   /// Sends a connect request on behalf of a pending connection.
   void sendConnectRequest(NetConnection *conn);

   /// Handles a connection request from a remote host.
   ///
   /// This will verify the validity of the connection token, as well as any solution
   /// to a client puzzle this NetInterface sent to the remote host.  If those tests
   /// pass, it will construct a local connection instance to handle the rest of the
   /// connection negotiation.
   void handleConnectRequest(const Address &address, BitStream *stream);

   /// Sends a connect accept packet to acknowledge the successful acceptance of a connect request.
   void sendConnectAccept(NetConnection *conn);

   /// Handles a connect accept packet, putting the connection associated with the
   /// remote host (if there is one) into an active state.
   void handleConnectAccept(const Address &address, BitStream *stream);

   /// Sends a connect rejection to a valid connect request in response to possible error
   /// conditions (server full, wrong password, etc).
   void sendConnectReject(ConnectionParameters *theParams, const Address &theAddress, const char *reason);

   /// Handles a connect rejection packet by notifying the connection object
   /// that the connection was rejected.
   void handleConnectReject(const Address &address, BitStream *stream);

   /// Begins the connection handshaking process for an arranged connection.
   void startArrangedConnection(NetConnection *conn);

   /// Sends Punch packets to each address in the possible connection address list.
   void sendPunchPackets(NetConnection *conn);

   /// Handles an incoming Punch packet from a remote host.
   void handlePunch(const Address &theAddress, BitStream *stream);

   /// Sends an arranged connect request.
   void sendArrangedConnectRequest(NetConnection *conn);

   /// Handles an incoming connect request from an arranged connection.
   void handleArrangedConnectRequest(const Address &theAddress, BitStream *stream);
   
   /// Dispatches a disconnect packet for a specified connection.
   void handleDisconnect(const Address &address, BitStream *stream);

   /// Handles an error reported while reading a packet from this remote connection.
   void handleConnectionError(NetConnection *theConnection, const char *errorString);

   /// Disconnects the given connection and removes it from the NetInterface
   void disconnect(NetConnection *conn, NetConnection::TerminationReason reason, const char *reasonString);
   /// @}
public:
   /// @param   bindAddress    Local network address to bind this interface to.
   NetInterface(const Address &bindAddress);
   ~NetInterface();

   /// Returns the address of the first network interface in the list that the socket on this NetInterface is bound to.
   Address getFirstBoundInterfaceAddress();

   /// Sets the private key this NetInterface will use for authentication and key exchange
   void setPrivateKey(AsymmetricKey *theKey);

   /// Requires that all connections use encryption and key exchange
   void setRequiresKeyExchange(bool requires) { mRequiresKeyExchange = requires; }

   /// Sets the public certificate that validates the private key and stores
   /// information about this host.  If no certificate is set, this interface can
   /// still initiate and accept encrypted connections, but they will be vulnerable to
   /// man in the middle attacks, unless the remote host can validate the public key
   /// in another way.
   void setCertificate(Certificate *theCertificate);

   /// Returns whether or not this NetInterface allows connections from remote hosts.
   bool doesAllowConnections() { return mAllowConnections; }

   /// Sets whether or not this NetInterface allows connections from remote hosts.
   void setAllowsConnections(bool conn) { mAllowConnections = conn; }

   /// Returns the Socket associated with this NetInterface
   Socket &getSocket() { return mSocket; }

   /// Sends a packet to the remote address over this interface's socket.
   NetError sendto(const Address &address, BitStream *stream);

   /// Sends a packet to the remote address after millisecondDelay time has elapsed.
   ///
   /// This is used to simulate network latency on a LAN or single computer.
   void sendtoDelayed(const Address &address, BitStream *stream, U32 millisecondDelay);

   /// Dispatch function for processing all network packets through this NetInterface.
   void checkIncomingPackets();

   /// Processes a single packet, and dispatches either to handleInfoPacket or to
   /// the NetConnection associated with the remote address.
   virtual void processPacket(const Address &address, BitStream *packetStream);

   /// Handles all packets that don't fall into the category of connection handshake or game data.
   virtual void handleInfoPacket(const Address &address, U8 packetType, BitStream *stream);

   /// Checks all connections on this interface for packet sends, and for timeouts and all valid
   /// and pending connections.
   void processConnections();

   /// Returns the list of connections on this NetInterface.
   Vector<NetConnection *> &getConnectionList() { return mConnectionList; }

   /// looks up a connected connection on this NetInterface
   NetConnection *findConnection(const Address &remoteAddress);

   /// returns the current process time for this NetInterface
   U32 getCurrentTime() { return mCurrentTime; }
};

};

#endif
