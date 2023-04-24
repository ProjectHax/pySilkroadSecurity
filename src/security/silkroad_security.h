#pragma once

#ifndef SILKROAD_SECURITY_H_
#define SILKROAD_SECURITY_H_

//-----------------------------------------------------------------------------

#include "pch.h"

//-----------------------------------------------------------------------------

#define MAKELONGLONG_( a, b ) ((uint64_t)(((((uint64_t)(a)) & 0xffffffff)) | ((uint64_t)((((uint64_t)(b)) & 0xffffffff))) << 32))
#define MAKELONG_(a, b)      ((int32_t)(((uint16_t)(((uint16_t)(a)) & 0xffff)) | ((uint32_t)((uint16_t)(((uint16_t)(b)) & 0xffff))) << 16))
#define MAKEWORD_(a, b)      ((uint16_t)(((uint8_t)(((uint8_t)(a)) & 0xff)) | ((uint16_t)((uint8_t)(((uint8_t)(b)) & 0xff))) << 8))
#define LOWORD_(l)           ((uint16_t)(((uint32_t)(l)) & 0xffff))
#define HIWORD_(l)           ((uint16_t)((((uint32_t)(l)) >> 16) & 0xffff))
#define LOBYTE_(w)           ((uint8_t)(((uint16_t)(w)) & 0xff))
#define HIBYTE_(w)           ((uint8_t)((((uint16_t)(w)) >> 8) & 0xff))

//-----------------------------------------------------------------------------

struct PacketContainer
{
	uint16_t opcode;
	StreamUtility data;
	bool encrypted;
	bool massive;

	PacketContainer();
	PacketContainer( uint16_t packet_opcode, const StreamUtility & packet_data, bool packet_encrypted, bool packet_massive );
	PacketContainer( const PacketContainer & rhs );
	PacketContainer & operator =( const PacketContainer & rhs );
	~PacketContainer();
};

//-----------------------------------------------------------------------------

struct SilkroadSecurityData;
class SilkroadSecurity
{
public:
	SilkroadSecurityData * m_data;

public:
	SilkroadSecurity();
	~SilkroadSecurity();

	// Only call this function if this security object is being used in a server
	// context and not a clientless. Be sure to run HasPacketToSend and 
	// GetPacketToSend logic afterwards on connect to send the initial packet.
	void GenerateHandshake( bool blowfish = true, bool security_bytes = true, bool handshake = true );

	// Allows you to change the identity sent after the handshake has been
	// accepted. This function is only for advanced users and does not need
	// to be used for normal operations. Defaults to "SR_Client" and 0.
	void ChangeIdentity( const std::string & name, uint8_t flag );

	// Transfers raw incoming data into the security object. After calling, you
	// should check to see if there are any packets ready for processing via
	// the GetPacketToRecv function. Do not call with non-network data as 
	// the stream can corrupt! This is a very heavy function that should
	// only be called within a serialized network thread. Can throw.
	void Recv( const uint8_t * stream, int32_t count );
	void Recv( const std::vector< uint8_t > & stream );

	// Returns the next available packet that has been extracted from the stream.
	// NOTE: Certain packets are processed internally and then returned to the user
	// in a usable form. For example: 0x600D packets are handled internally and the
	// data they contain is returned through this function. You will never get a
	// a 0x600D packet to process. Can throw.
	std::list< PacketContainer > GetPacketToRecv();

	// Transfers formatted outgoing data into the security object. A packet
	// is then queued internally and will be processed when the GetPacketToSend
	// function is called. This function is very lightweight, so no heavy processing
	// is done.
	void Send( uint16_t opcode, const StreamUtility & data, bool encrypted = false, bool massive = false );
	void Send( uint16_t opcode, const uint8_t * data, int32_t count, bool encrypted = false, bool massive = false );

	// Returns the raw packet data to send, which has been properly formated to 
	// the Silkroad protocol. This is a very heavy function that should only be 
	// called within a serialized network thread. Can throw.
	std::list< std::vector< uint8_t > > GetPacketToSend();

	// When the security mode is set to include security bytes, certain opcodes 
	// must be added to comply with the security system. The security system will
	// pre-add the GatewayServer packet opcodes as needed. The user should add the
	// * item use opcode * for the current version of Silkroad they are using.
	void AddEncryptedOpcode( uint16_t opcode );
};

//-----------------------------------------------------------------------------

#endif