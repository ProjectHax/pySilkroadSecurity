#include "pch.h"

//-----------------------------------------------------------------------------

std::vector< uint8_t > FormatPacket( SilkroadSecurityData * silkroad_security_data, uint16_t opcode, StreamUtility & data, uint8_t encrypted );

//-----------------------------------------------------------------------------

// Base security values the client uses to build the security table from.
static uint8_t BaseSecurityTable[] = 
{
	0xB1, 0xD6, 0x8B, 0x96, 0x96, 0x30, 0x07, 0x77, 0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51, 0x09, 0x99, 
	0x19, 0xC4, 0x6D, 0x07, 0x8F, 0xF4, 0x6A, 0x70, 0x35, 0xA5, 0x63, 0xE9, 0xA3, 0x95, 0x64, 0x9E,
	0x32, 0x88, 0xDB, 0x0E, 0xA4, 0xB8, 0xDC, 0x79, 0x1E, 0xE9, 0xD5, 0xE0, 0x88, 0xD9, 0xD2, 0x97, 
	0x2B, 0x4C, 0xB6, 0x09, 0xBD, 0x7C, 0xB1, 0x7E, 0x07, 0x2D, 0xB8, 0xE7, 0x91, 0x1D, 0xBF, 0x90,
	0x64, 0x10, 0xB7, 0x1D, 0xF2, 0x20, 0xB0, 0x6A, 0x48, 0x71, 0xB1, 0xF3, 0xDE, 0x41, 0xBE, 0x8C, 
	0x7D, 0xD4, 0xDA, 0x1A, 0xEB, 0xE4, 0xDD, 0x6D, 0x51, 0xB5, 0xD4, 0xF4, 0xC7, 0x85, 0xD3, 0x83,
	0x56, 0x98, 0x6C, 0x13, 0xC0, 0xA8, 0x6B, 0x64, 0x7A, 0xF9, 0x62, 0xFD, 0xEC, 0xC9, 0x65, 0x8A, 
	0x4F, 0x5C, 0x01, 0x14, 0xD9, 0x6C, 0x06, 0x63, 0x63, 0x3D, 0x0F, 0xFA, 0xF5, 0x0D, 0x08, 0x8D,
	0xC8, 0x20, 0x6E, 0x3B, 0x5E, 0x10, 0x69, 0x4C, 0xE4, 0x41, 0x60, 0xD5, 0x72, 0x71, 0x67, 0xA2, 
	0xD1, 0xE4, 0x03, 0x3C, 0x47, 0xD4, 0x04, 0x4B, 0xFD, 0x85, 0x0D, 0xD2, 0x6B, 0xB5, 0x0A, 0xA5,
	0xFA, 0xA8, 0xB5, 0x35, 0x6C, 0x98, 0xB2, 0x42, 0xD6, 0xC9, 0xBB, 0xDB, 0x40, 0xF9, 0xBC, 0xAC, 
	0xE3, 0x6C, 0xD8, 0x32, 0x75, 0x5C, 0xDF, 0x45, 0xCF, 0x0D, 0xD6, 0xDC, 0x59, 0x3D, 0xD1, 0xAB,
	0xAC, 0x30, 0xD9, 0x26, 0x3A, 0x00, 0xDE, 0x51, 0x80, 0x51, 0xD7, 0xC8, 0x16, 0x61, 0xD0, 0xBF, 
	0xB5, 0xF4, 0xB4, 0x21, 0x23, 0xC4, 0xB3, 0x56, 0x99, 0x95, 0xBA, 0xCF, 0x0F, 0xA5, 0xB7, 0xB8,
	0x9E, 0xB8, 0x02, 0x28, 0x08, 0x88, 0x05, 0x5F, 0xB2, 0xD9, 0xEC, 0xC6, 0x24, 0xE9, 0x0B, 0xB1, 
	0x87, 0x7C, 0x6F, 0x2F, 0x11, 0x4C, 0x68, 0x58, 0xAB, 0x1D, 0x61, 0xC1, 0x3D, 0x2D, 0x66, 0xB6,
	0x90, 0x41, 0xDC, 0x76, 0x06, 0x71, 0xDB, 0x01, 0xBC, 0x20, 0xD2, 0x98, 0x2A, 0x10, 0xD5, 0xEF, 
	0x89, 0x85, 0xB1, 0x71, 0x1F, 0xB5, 0xB6, 0x06, 0xA5, 0xE4, 0xBF, 0x9F, 0x33, 0xD4, 0xB8, 0xE8,
	0xA2, 0xC9, 0x07, 0x78, 0x34, 0xF9, 0xA0, 0x0F, 0x8E, 0xA8, 0x09, 0x96, 0x18, 0x98, 0x0E, 0xE1, 
	0xBB, 0x0D, 0x6A, 0x7F, 0x2D, 0x3D, 0x6D, 0x08, 0x97, 0x6C, 0x64, 0x91, 0x01, 0x5C, 0x63, 0xE6,
	0xF4, 0x51, 0x6B, 0x6B, 0x62, 0x61, 0x6C, 0x1C, 0xD8, 0x30, 0x65, 0x85, 0x4E, 0x00, 0x62, 0xF2, 
	0xED, 0x95, 0x06, 0x6C, 0x7B, 0xA5, 0x01, 0x1B, 0xC1, 0xF4, 0x08, 0x82, 0x57, 0xC4, 0x0F, 0xF5,
	0xC6, 0xD9, 0xB0, 0x63, 0x50, 0xE9, 0xB7, 0x12, 0xEA, 0xB8, 0xBE, 0x8B, 0x7C, 0x88, 0xB9, 0xFC, 
	0xDF, 0x1D, 0xDD, 0x62, 0x49, 0x2D, 0xDA, 0x15, 0xF3, 0x7C, 0xD3, 0x8C, 0x65, 0x4C, 0xD4, 0xFB,
	0x58, 0x61, 0xB2, 0x4D, 0xCE, 0x51, 0xB5, 0x3A, 0x74, 0x00, 0xBC, 0xA3, 0xE2, 0x30, 0xBB, 0xD4, 
	0x41, 0xA5, 0xDF, 0x4A, 0xD7, 0x95, 0xD8, 0x3D, 0x6D, 0xC4, 0xD1, 0xA4, 0xFB, 0xF4, 0xD6, 0xD3,
	0x6A, 0xE9, 0x69, 0x43, 0xFC, 0xD9, 0x6E, 0x34, 0x46, 0x88, 0x67, 0xAD, 0xD0, 0xB8, 0x60, 0xDA, 
	0x73, 0x2D, 0x04, 0x44, 0xE5, 0x1D, 0x03, 0x33, 0x5F, 0x4C, 0x0A, 0xAA, 0xC9, 0x7C, 0x0D, 0xDD,
	0x3C, 0x71, 0x05, 0x50, 0xAA, 0x41, 0x02, 0x27, 0x10, 0x10, 0x0B, 0xBE, 0x86, 0x20, 0x0C, 0xC9, 
	0x25, 0xB5, 0x68, 0x57, 0xB3, 0x85, 0x6F, 0x20, 0x09, 0xD4, 0x66, 0xB9, 0x9F, 0xE4, 0x61, 0xCE,
	0x0E, 0xF9, 0xDE, 0x5E, 0x08, 0xC9, 0xD9, 0x29, 0x22, 0x98, 0xD0, 0xB0, 0xB4, 0xA8, 0x57, 0xC7, 
	0x17, 0x3D, 0xB3, 0x59, 0x81, 0x0D, 0xB4, 0x3E, 0x3B, 0x5C, 0xBD, 0xB7, 0xAD, 0x6C, 0xBA, 0xC0,
	0x20, 0x83, 0xB8, 0xED, 0xB6, 0xB3, 0xBF, 0x9A, 0x0C, 0xE2, 0xB6, 0x03, 0x9A, 0xD2, 0xB1, 0x74, 
	0x39, 0x47, 0xD5, 0xEA, 0xAF, 0x77, 0xD2, 0x9D, 0x15, 0x26, 0xDB, 0x04, 0x83, 0x16, 0xDC, 0x73,
	0x12, 0x0B, 0x63, 0xE3, 0x84, 0x3B, 0x64, 0x94, 0x3E, 0x6A, 0x6D, 0x0D, 0xA8, 0x5A, 0x6A, 0x7A, 
	0x0B, 0xCF, 0x0E, 0xE4, 0x9D, 0xFF, 0x09, 0x93, 0x27, 0xAE, 0x00, 0x0A, 0xB1, 0x9E, 0x07, 0x7D,
	0x44, 0x93, 0x0F, 0xF0, 0xD2, 0xA2, 0x08, 0x87, 0x68, 0xF2, 0x01, 0x1E, 0xFE, 0xC2, 0x06, 0x69, 
	0x5D, 0x57, 0x62, 0xF7, 0xCB, 0x67, 0x65, 0x80, 0x71, 0x36, 0x6C, 0x19, 0xE7, 0x06, 0x6B, 0x6E,
	0x76, 0x1B, 0xD4, 0xFE, 0xE0, 0x2B, 0xD3, 0x89, 0x5A, 0x7A, 0xDA, 0x10, 0xCC, 0x4A, 0xDD, 0x67, 
	0x6F, 0xDF, 0xB9, 0xF9, 0xF9, 0xEF, 0xBE, 0x8E, 0x43, 0xBE, 0xB7, 0x17, 0xD5, 0x8E, 0xB0, 0x60,
	0xE8, 0xA3, 0xD6, 0xD6, 0x7E, 0x93, 0xD1, 0xA1, 0xC4, 0xC2, 0xD8, 0x38, 0x52, 0xF2, 0xDF, 0x4F, 
	0xF1, 0x67, 0xBB, 0xD1, 0x67, 0x57, 0xBC, 0xA6, 0xDD, 0x06, 0xB5, 0x3F, 0x4B, 0x36, 0xB2, 0x48,
	0xDA, 0x2B, 0x0D, 0xD8, 0x4C, 0x1B, 0x0A, 0xAF, 0xF6, 0x4A, 0x03, 0x36, 0x60, 0x7A, 0x04, 0x41, 
	0xC3, 0xEF, 0x60, 0xDF, 0x55, 0xDF, 0x67, 0xA8, 0xEF, 0x8E, 0x6E, 0x31, 0x79, 0x0E, 0x69, 0x46,
	0x8C, 0xB3, 0x51, 0xCB, 0x1A, 0x83, 0x63, 0xBC, 0xA0, 0xD2, 0x6F, 0x25, 0x36, 0xE2, 0x68, 0x52, 
	0x95, 0x77, 0x0C, 0xCC, 0x03, 0x47, 0x0B, 0xBB, 0xB9, 0x14, 0x02, 0x22, 0x2F, 0x26, 0x05, 0x55,
	0xBE, 0x3B, 0xB6, 0xC5, 0x28, 0x0B, 0xBD, 0xB2, 0x92, 0x5A, 0xB4, 0x2B, 0x04, 0x6A, 0xB3, 0x5C, 
	0xA7, 0xFF, 0xD7, 0xC2, 0x31, 0xCF, 0xD0, 0xB5, 0x8B, 0x9E, 0xD9, 0x2C, 0x1D, 0xAE, 0xDE, 0x5B,
	0xB0, 0x72, 0x64, 0x9B, 0x26, 0xF2, 0xE3, 0xEC, 0x9C, 0xA3, 0x6A, 0x75, 0x0A, 0x93, 0x6D, 0x02, 
	0xA9, 0x06, 0x09, 0x9C, 0x3F, 0x36, 0x0E, 0xEB, 0x85, 0x68, 0x07, 0x72, 0x13, 0x07, 0x00, 0x05,
	0x82, 0x48, 0xBF, 0x95, 0x14, 0x7A, 0xB8, 0xE2, 0xAE, 0x2B, 0xB1, 0x7B, 0x38, 0x1B, 0xB6, 0x0C, 
	0x9B, 0x8E, 0xD2, 0x92, 0x0D, 0xBE, 0xD5, 0xE5, 0xB7, 0xEF, 0xDC, 0x7C, 0x21, 0xDF, 0xDB, 0x0B,
	0x94, 0xD2, 0xD3, 0x86, 0x42, 0xE2, 0xD4, 0xF1, 0xF8, 0xB3, 0xDD, 0x68, 0x6E, 0x83, 0xDA, 0x1F, 
	0xCD, 0x16, 0xBE, 0x81, 0x5B, 0x26, 0xB9, 0xF6, 0xE1, 0x77, 0xB0, 0x6F, 0x77, 0x47, 0xB7, 0x18,
	0xE0, 0x5A, 0x08, 0x88, 0x70, 0x6A, 0x0F, 0xF1, 0xCA, 0x3B, 0x06, 0x66, 0x5C, 0x0B, 0x01, 0x11, 
	0xFF, 0x9E, 0x65, 0x8F, 0x69, 0xAE, 0x62, 0xF8, 0xD3, 0xFF, 0x6B, 0x61, 0x45, 0xCF, 0x6C, 0x16,
	0x78, 0xE2, 0x0A, 0xA0, 0xEE, 0xD2, 0x0D, 0xD7, 0x54, 0x83, 0x04, 0x4E, 0xC2, 0xB3, 0x03, 0x39, 
	0x61, 0x26, 0x67, 0xA7, 0xF7, 0x16, 0x60, 0xD0, 0x4D, 0x47, 0x69, 0x49, 0xDB, 0x77, 0x6E, 0x3E,
	0x4A, 0x6A, 0xD1, 0xAE, 0xDC, 0x5A, 0xD6, 0xD9, 0x66, 0x0B, 0xDF, 0x40, 0xF0, 0x3B, 0xD8, 0x37, 
	0x53, 0xAE, 0xBC, 0xA9, 0xC5, 0x9E, 0xBB, 0xDE, 0x7F, 0xCF, 0xB2, 0x47, 0xE9, 0xFF, 0xB5, 0x30,
	0x1C, 0xF9, 0xBD, 0xBD, 0x8A, 0xCD, 0xBA, 0xCA, 0x30, 0x9E, 0xB3, 0x53, 0xA6, 0xA3, 0xBC, 0x24, 
	0x05, 0x3B, 0xD0, 0xBA, 0xA3, 0x06, 0xD7, 0xCD, 0xE9, 0x57, 0xDE, 0x54, 0xBF, 0x67, 0xD9, 0x23,
	0x2E, 0x72, 0x66, 0xB3, 0xB8, 0x4A, 0x61, 0xC4, 0x02, 0x1B, 0x38, 0x5D, 0x94, 0x2B, 0x6F, 0x2B, 
	0x37, 0xBE, 0xCB, 0xB4, 0xA1, 0x8E, 0xCC, 0xC3, 0x1B, 0xDF, 0x0D, 0x5A, 0x8D, 0xED, 0x02, 0x2D,
};

//-----------------------------------------------------------------------------

uint32_t SecurityTable[ 0x10000 ] = { 0 };
bool GenerateSecurityTable()
{
	uint32_t * outPtr = SecurityTable;
	for( uint32_t EDI = 0; EDI < 1024; EDI += 4 )
	{
		uint32_t EDX = *(uint32_t *)(BaseSecurityTable + EDI);
		for( int ECX = 0; ECX < 256; ++ECX )
		{
			uint32_t EAX = ECX >> 1;
			if( ECX & 1 )
			{
				EAX ^= EDX;
			}
			for( int bit = 0; bit < 7; ++bit )
			{
				if( EAX & 1 )
				{
					EAX >>= 1;
					EAX ^= EDX;
				}
				else
				{
					EAX >>= 1;
				}
			}
			*outPtr++ = EAX;
		}
	}

	return true;
}

static bool init_security_table = GenerateSecurityTable();

//-----------------------------------------------------------------------------

uint64_t rng()
{
	std::random_device dev;
	std::uniform_int_distribution<uint64_t> dist(0, 0xFFFFFFFFFFFFFFFF);
	return dist(dev);
}

//-----------------------------------------------------------------------------

#pragma pack( push, 1 )
struct TFlags
{
	uint8_t none : 1;
	uint8_t blowfish : 1;
	uint8_t security_bytes : 1;
	uint8_t handshake : 1;
	uint8_t handshake_response : 1;
	uint8_t _6 : 1;
	uint8_t _7 : 1;
	uint8_t _8 : 1;
};
#pragma pack( pop )

//-----------------------------------------------------------------------------

struct SilkroadSecurityData
{
	StreamUtility m_pending_stream;
	uint16_t m_massive_count;
	uint16_t m_massive_opcode;
	bool m_massive_header;
	StreamUtility m_massive_packet;
	std::list< PacketContainer > m_incoming_packets;
	std::list< PacketContainer > m_outgoing_packets;
	uint32_t m_value_x;
	uint32_t m_value_g;
	uint32_t m_value_p;
	uint32_t m_value_A;
	uint32_t m_value_B;
	uint32_t m_value_K;
	uint32_t m_seed_count;
	uint32_t m_crc_seed;
	uint64_t m_initial_blowfish_key;
	uint64_t m_handshake_blowfish_key;
	uint8_t m_count_byte_seeds[3];
	uint64_t m_client_key;
	uint64_t m_challenge_key;
	bool m_client_security;
	uint8_t m_security_flag;
	TFlags * m_security_flags;
	Blowfish m_blowfish;
	std::string m_identity_name;
	uint8_t m_identity_flag;
	bool m_accepted_handshake;
	bool m_started_handshake;
	std::set< uint16_t > m_enc_opcodes;

private:
	SilkroadSecurityData( const SilkroadSecurityData & rhs );
	SilkroadSecurityData & operator =( const SilkroadSecurityData & rhs );

public:
	SilkroadSecurityData()
		: m_massive_count( 0 ), m_massive_opcode( 0 ), m_massive_header( false ), m_accepted_handshake( false ), m_started_handshake( false )
	{
		m_identity_name = "SR_Client";
		m_identity_flag = 0;
		m_value_x = 0;
		m_value_g = 0;
		m_value_p = 0;
		m_value_A = 0;
		m_value_B = 0;
		m_value_K = 0;
		m_count_byte_seeds[0] = 0;
		m_count_byte_seeds[1] = 0;
		m_count_byte_seeds[2] = 0;
		m_crc_seed = 0;
		m_seed_count = 0;
		m_handshake_blowfish_key = 0;
		m_initial_blowfish_key = 0;
		m_challenge_key = 0;
		m_client_key = 0;
		m_client_security = false;
		m_security_flag = 0;
		m_security_flags = reinterpret_cast< TFlags *>( &m_security_flag );
		m_enc_opcodes.insert( 0x2001 );
		m_enc_opcodes.insert( 0x6100 );
		m_enc_opcodes.insert( 0x6101 );
		m_enc_opcodes.insert( 0x6102 );
		m_enc_opcodes.insert( 0x6103 );
	}

	~SilkroadSecurityData()
	{
	}

public:
	// This function's logic was written by jMerlin as part of the article "How to generate the security bytes for SRO"
	uint32_t GenerateValue( uint32_t * ptr )
	{
		uint32_t val = *ptr;
		for( int i = 0; i < 32; ++i )
		{
			val = ( ( ( ( ( ( ( ( ( ( ( val >> 2 ) ^ val ) >> 2 ) ^ val ) >> 1 ) ^ val ) >> 1 ) ^ val ) >> 1 ) ^ val ) & 1 ) | ( ( ( ( val & 1 ) << 31 ) |( val >> 1 ) ) & 0xFFFFFFFE );
		}
		return ( *ptr = val );
	}

	// Sets up the count bytes
	// This function's logic was written by jMerlin as part of the article "How to generate the security bytes for SRO"
	void SetupCountByte( uint32_t seed )
	{
		if( seed == 0 ) seed = 0x9ABFB3B6;
		uint32_t mut = seed;
		uint32_t mut1 = GenerateValue( &mut );
		uint32_t mut2 = GenerateValue( &mut );
		uint32_t mut3 = GenerateValue( &mut );
		GenerateValue( &mut );
		uint8_t byte1 = ( uint8_t )( ( mut & 0xFF ) ^ ( mut3 & 0xFF ) );
		uint8_t byte2 = ( uint8_t )( ( mut1 & 0xFF ) ^ ( mut2 & 0xFF ) );
		if( !byte1 ) byte1 = 1;
		if( !byte2 ) byte2 = 1;
		m_count_byte_seeds[ 0 ] = byte1 ^ byte2;
		m_count_byte_seeds[ 1 ] = byte2;
		m_count_byte_seeds[ 2 ] = byte1;
	}

	// Helper function used in the handshake, X may be a or b, this clean version of the function is from jMerlin (Func_X_4)
	uint32_t G_pow_X_mod_P( uint32_t P, uint32_t X, uint32_t G )
	{
		uint64_t result = 1;
		uint64_t mult = G;
		if( X == 0 ) return 1;
		while( X )
		{
			if( X & 1 ) result = ( mult * result ) % P;
			X = X >> 1;
			mult = ( mult * mult ) % P;
		}
		return static_cast< uint32_t >( result );
	}

	// Helper function used in the handshake (Func_X_2)
	void KeyTransformValue( uint64_t & val, uint32_t key, uint8_t key_byte )
	{
		uint8_t * stream = reinterpret_cast< uint8_t *>( &val );
		stream[ 0 ] ^= ( stream[ 0 ] + LOBYTE_( LOWORD_( key ) ) + key_byte );
		stream[ 1 ] ^= ( stream[ 1 ] + HIBYTE_( LOWORD_( key ) ) + key_byte );
		stream[ 2 ] ^= ( stream[ 2 ] + LOBYTE_( HIWORD_( key ) ) + key_byte );
		stream[ 3 ] ^= ( stream[ 3 ] + HIBYTE_( HIWORD_( key ) ) + key_byte );
		stream[ 4 ] ^= ( stream[ 4 ] + LOBYTE_( LOWORD_( key ) ) + key_byte );
		stream[ 5 ] ^= ( stream[ 5 ] + HIBYTE_( LOWORD_( key ) ) + key_byte );
		stream[ 6 ] ^= ( stream[ 6 ] + LOBYTE_( HIWORD_( key ) ) + key_byte );
		stream[ 7 ] ^= ( stream[ 7 ] + HIBYTE_( HIWORD_( key ) ) + key_byte );
	}

	// Function called to generate a count byte
	// This function's logic was written by jMerlin as part of the article "How to generate the security bytes for SRO"
	uint8_t GenerateCountByte( bool update )
	{
		uint8_t result = ( m_count_byte_seeds[ 2 ] * ( ~m_count_byte_seeds[ 0 ] + m_count_byte_seeds[ 1 ] ) );
		result = result ^ ( result >> 4 );
		if( update ) m_count_byte_seeds[ 0 ] = result;
		return result;
	}

	// Function called to generate the crc byte
	// This function's logic was written by jMerlin as part of the article "How to generate the security bytes for SRO"
	uint8_t GenerateCheckByte( StreamUtility & stream )
	{
		const std::vector< uint8_t > & packet = stream.GetStreamVector();
		uint32_t checksum = 0xFFFFFFFF;
		uint32_t moddedseed = m_crc_seed << 8;
		int32_t length = static_cast< int32_t >( packet.size() );
		for( int32_t x = 0; x < length; ++x )
		{
			checksum = ( checksum >> 8 ) ^ SecurityTable[ moddedseed + ( ( packet[ x ] ^ checksum ) & 0xFF ) ];
		}
		return ( uint8_t )( ( ( checksum >> 24 ) & 0xFF ) + ( ( checksum >> 8 ) & 0xFF ) + ( ( checksum >> 16 ) & 0xFF ) + ( checksum & 0xFF ) );
	}

	void GenerateHandshake( uint8_t mode )
	{
		m_security_flag = mode;
		m_client_security = true;
		PacketContainer response;
		response.opcode = 0x5000;
		response.data.Write< uint8_t >( mode );
		if( m_security_flags->blowfish )
		{
			m_initial_blowfish_key = rng();
			m_blowfish.Initialize( &m_initial_blowfish_key, sizeof( m_initial_blowfish_key ) );
			response.data.Write< uint64_t >( m_initial_blowfish_key );
		}
		if( m_security_flags->security_bytes )
		{
			m_seed_count = static_cast< uint32_t >( rng() % 0xFF );
			SetupCountByte( m_seed_count );
			m_crc_seed = static_cast< uint32_t >( rng() % 0xFF );
			response.data.Write< uint32_t >( m_seed_count );
			response.data.Write< uint32_t >( m_crc_seed );
		}
		if( m_security_flags->handshake )
		{
			m_handshake_blowfish_key = rng();
			m_value_x = static_cast< uint32_t >( rng() & 0x7FFFFFFF );
			m_value_g = static_cast< uint32_t >( rng() & 0x7FFFFFFF );
			m_value_p = static_cast< uint32_t >( rng() & 0x7FFFFFFF );
			m_value_A = G_pow_X_mod_P( m_value_p, m_value_x, m_value_g );
			response.data.Write< uint64_t >( m_handshake_blowfish_key );
			response.data.Write< uint32_t >( m_value_g );
			response.data.Write< uint32_t >( m_value_p );
			response.data.Write< uint32_t >( m_value_A );
		}
		m_outgoing_packets.push_front( response );
	}

	void Handshake( uint16_t packet_opcode, StreamUtility & packet_data, bool packet_encrypted )
	{
		if( packet_encrypted )
		{
			throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical [encrypted] handshake packet." ) );
		}
		if( m_client_security )
		{
			// If this object does not need a handshake
			if( m_security_flags->handshake == 0 )
			{
				// Client should only accept it then
				if( packet_opcode == 0x9000 )
				{
					if( m_accepted_handshake )
					{
						throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (duplicate 0x9000)." ) );
					}
					m_accepted_handshake = true; // Otherwise, all good here
					return;
				}
				// Client should not send any 0x5000s!
				else if( packet_opcode == 0x5000 )
				{
					throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (0x5000 with no handshake)." ) );
				}
				// Programmer made a mistake in calling this function
				else
				{
					throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (programmer error)." ) );
				}
			}
			else
			{
				// Client accepts the handshake
				if( packet_opcode == 0x9000 )
				{
					// Can't accept it before it's started!
					if( !m_started_handshake )
					{
						throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (out of order 0x9000)." ) );
					}
					if( m_accepted_handshake ) // Client error
					{
						throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (duplicate 0x9000)." ) );
					}
					// Otherwise, all good here
					m_accepted_handshake = true;
					return;
				}
				// Client sends a handshake response
				else if( packet_opcode == 0x5000 )
				{
					if( m_started_handshake ) // Client error
					{
						throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (duplicate 0x5000)." ) );
					}
					m_started_handshake = true;
				}
				// Programmer made a mistake in calling this function
				else
				{
					throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (programmer error)." ) );
				}
			}

			uint64_t key_array = 0;

			m_value_B = packet_data.Read< uint32_t >();
			m_client_key = packet_data.Read< uint64_t >();

			m_value_K = G_pow_X_mod_P( m_value_p, m_value_x, m_value_B );

			key_array = MAKELONGLONG_( m_value_A, m_value_B );
			KeyTransformValue( key_array, m_value_K, LOBYTE_( LOWORD_( m_value_K ) ) & 0x03 );
			m_blowfish.Initialize( &key_array, 8 );

			m_blowfish.Decode( &m_client_key, 8, &m_client_key, 8 );

			key_array = MAKELONGLONG_( m_value_B, m_value_A );
			KeyTransformValue( key_array, m_value_K, LOBYTE_( LOWORD_( m_value_B ) ) & 0x07 );
			if( m_client_key != key_array )
			{
				throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Client signature error." ) );
			}

			key_array = MAKELONGLONG_( m_value_A, m_value_B );
			KeyTransformValue( key_array, m_value_K, LOBYTE_( LOWORD_( m_value_K ) ) & 0x03 );
			m_blowfish.Initialize( &key_array, 8 );

			m_challenge_key = MAKELONGLONG_( m_value_A, m_value_B );
			KeyTransformValue( m_challenge_key, m_value_K, LOBYTE_( LOWORD_( m_value_A ) ) & 0x07 );
			m_blowfish.Encode( &m_challenge_key, 8, &m_challenge_key, 8 );

			KeyTransformValue( m_handshake_blowfish_key, m_value_K, 0x3 );
			m_blowfish.Initialize( &m_handshake_blowfish_key, 8 );

			uint8_t tmp_flag = 0;
			TFlags * tmp_flags = reinterpret_cast<TFlags *>( &tmp_flag );
			tmp_flags->handshake_response = 1;

			PacketContainer response;
			response.opcode = 0x5000;
			response.data.Write< uint8_t >( tmp_flag );
			response.data.Write< uint64_t >( m_challenge_key );
			m_outgoing_packets.push_front( response );
		}
		else
		{
			if( packet_opcode != 0x5000 )
			{
				throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (programmer error)." ) );
			}

			uint8_t flag = packet_data.Read< uint8_t >();

			TFlags * flags = (TFlags *)&flag;

			if( m_security_flag == 0 )
			{
				m_security_flag = flag;
			}

			if( flags->blowfish )
			{
				m_initial_blowfish_key = packet_data.Read< uint64_t >();
				m_blowfish.Initialize( &m_initial_blowfish_key, sizeof( m_initial_blowfish_key ) );
			}

			if( flags->security_bytes )
			{
				m_seed_count = packet_data.Read< uint32_t >();
				m_crc_seed = packet_data.Read< uint32_t >();
				SetupCountByte( m_seed_count );
			}

			if( flags->handshake )
			{
				m_handshake_blowfish_key = packet_data.Read< uint64_t >();
				m_value_g = packet_data.Read< uint32_t >();
				m_value_p = packet_data.Read< uint32_t >();
				m_value_A = packet_data.Read< uint32_t >();

				m_value_x = static_cast< uint32_t >( rng() & 0x7FFFFFFF );

				m_value_B = G_pow_X_mod_P( m_value_p, m_value_x, m_value_g );
				m_value_K = G_pow_X_mod_P( m_value_p, m_value_x, m_value_A );

				uint64_t key_array = MAKELONGLONG_( m_value_A, m_value_B );
				KeyTransformValue( key_array, m_value_K, LOBYTE_( LOWORD_( m_value_K ) ) & 0x03 );
				m_blowfish.Initialize( &key_array, 8 );

				m_client_key = MAKELONGLONG_( m_value_B, m_value_A );
				KeyTransformValue( m_client_key, m_value_K, LOBYTE_( LOWORD_( m_value_B ) ) & 0x07 );
				m_blowfish.Encode( &m_client_key, 8, &m_client_key, 8 );
			}

			if( flags->handshake_response )
			{
				m_challenge_key = packet_data.Read< uint64_t >();

				uint64_t expected_challenge_key = MAKELONGLONG_( m_value_A, m_value_B );
				KeyTransformValue( expected_challenge_key, m_value_K, LOBYTE_( LOWORD_( m_value_A ) ) & 0x07 );
				m_blowfish.Encode( &expected_challenge_key, 8, &expected_challenge_key, 8 );

				if( m_challenge_key != expected_challenge_key )
				{
					throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Server signature error." ) );
				}

				KeyTransformValue( m_handshake_blowfish_key, m_value_K, 0x3 );
				m_blowfish.Initialize( &m_handshake_blowfish_key, 8 );
			}

			// Generate the outgoing packet now
			if( flags->handshake && !flags->handshake_response )
			{
				// Check to see if we already started a handshake
				if( m_started_handshake || m_accepted_handshake )
				{
					throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (duplicate 0x5000).") );
				}

				// Handshake challenge
				PacketContainer response;
				response.opcode = 0x5000;
				response.data.Write< uint32_t >( m_value_B );
				response.data.Write< uint64_t >( m_client_key );
				m_outgoing_packets.push_front( response );

				// The handshake has started
				m_started_handshake = true;
			}
			else
			{
				// Check to see if we already accepted a handshake
				if( m_accepted_handshake )
				{
					throw( std::runtime_error( "[SilkroadSecurityData::Handshake] Received an illogical handshake packet (duplicate 0x5000).") );
				}

				// Handshake accepted
				PacketContainer response1;
				response1.opcode = 0x9000;

				// Identify
				PacketContainer response2;
				response2.opcode = 0x2001;
				response2.encrypted = true;
				response2.data.Write< uint16_t >( static_cast< uint16_t >( m_identity_name.size() ) );
				response2.data.Write_Ascii( m_identity_name );
				response2.data.Write< uint8_t >( m_identity_flag );

				m_outgoing_packets.push_front( response2 );
				m_outgoing_packets.push_front( response1 );

				// Mark the handshake as accepted now
				m_started_handshake = true;
				m_accepted_handshake = true;
			}
		}
	}

	bool HasPacketToSend() const
	{
		// No packets, easy case
		if( m_outgoing_packets.empty() )
		{
			return false;
		}

		// If we have packets and have accepted the handshake, we can send whenever,
		// so return true.
		if( m_accepted_handshake )
		{
			return true;
		}

		// Otherwise, check to see if we have pending handshake packets to send
		const PacketContainer & packet_container = m_outgoing_packets.front();
		if( packet_container.opcode == 0x5000 || packet_container.opcode == 0x9000 )
		{
			return true;
		}

		// If we get here, we have out of order packets that cannot be sent yet.
		return false;
	}

	std::vector< uint8_t > GetPacketToSend()
	{
		if( m_outgoing_packets.empty() )
		{
			throw( std::runtime_error( "[SilkroadSecurityData::GetPacketToSend] No packets are avaliable to send.") );
		}

		PacketContainer packet_container = m_outgoing_packets.front();
		m_outgoing_packets.pop_front();

		if( packet_container.massive )
		{
			uint8_t workspace[ 4089 ];
			uint16_t parts = 0;

			StreamUtility final;
			StreamUtility final_data;

			int32_t total_size = packet_container.data.GetStreamSize();
			while( total_size )
			{
				StreamUtility part_data;

				int32_t cur_size = total_size > 4089 ? 4089 : total_size; // Max buffer size is 4kb for the client

				part_data.Write< uint8_t >( 0 ); // Data flag

				packet_container.data.Read< uint8_t >( workspace, cur_size );
				part_data.Write< uint8_t >( workspace, cur_size );

				total_size -= cur_size; // Update the size

				final_data.Write( FormatPacket( this, 0x600D, part_data, packet_container.encrypted ) );

				++parts; // Track how many parts there are
			}

			// Write the final header packet to the front of the packet
			StreamUtility final_header;
			final_header.Write< uint8_t >( 1 ); // Header flag
			final_header.Write< uint16_t >( parts );
			final_header.Write< uint16_t >( packet_container.opcode );
			final.Write( FormatPacket( this, 0x600D, final_header, packet_container.encrypted ) );

			// Finish the large packet of all the data
			final.Write( final_data.GetStreamVector() );

			// Return the collated data
			return final.GetStreamVector();
		}
		else
		{
			if( !m_client_security )
			{
				if( m_enc_opcodes.find( packet_container.opcode ) != m_enc_opcodes.end() )
				{
					packet_container.encrypted = true;
				}
			}
			return FormatPacket( this, packet_container.opcode, packet_container.data, packet_container.encrypted );
		}
	}
};

//-----------------------------------------------------------------------------

SilkroadSecurity::SilkroadSecurity()
: m_data( new SilkroadSecurityData )
{
}

//-----------------------------------------------------------------------------

SilkroadSecurity::~SilkroadSecurity()
{
	delete m_data;
}

//-----------------------------------------------------------------------------

void SilkroadSecurity::ChangeIdentity( const std::string & name, uint8_t flag )
{
	m_data->m_identity_name = name;
	m_data->m_identity_flag = flag;
}

//-----------------------------------------------------------------------------

std::list< std::vector< uint8_t > > SilkroadSecurity::GetPacketToSend()
{
	std::list< std::vector< uint8_t > > packets;

	while( m_data->HasPacketToSend() )
	{
		packets.push_back( m_data->GetPacketToSend() );
	}

	return packets;
}

//-----------------------------------------------------------------------------

std::list<PacketContainer> SilkroadSecurity::GetPacketToRecv()
{
	std::list<PacketContainer> packets;

	while( !m_data->m_incoming_packets.empty() )
	{
		PacketContainer packet_container = m_data->m_incoming_packets.front();
		m_data->m_incoming_packets.pop_front();
		packets.push_back( packet_container );
	}

	return packets;
}

//-----------------------------------------------------------------------------

void SilkroadSecurity::Send( uint16_t opcode, const uint8_t * data, int32_t count, bool encrypted, bool massive )
{
	StreamUtility su;
	su.Write< uint8_t >( data, count );
	Send( opcode, su, encrypted, massive );
}

//-----------------------------------------------------------------------------

void SilkroadSecurity::Send( uint16_t opcode, const StreamUtility & data, bool encrypted, bool massive )
{
	if( opcode == 0x5000 || opcode == 0x9000 )
	{
		throw( std::runtime_error( "[SilkroadSecurity::Send] Handshake packets cannot be sent through this function.") );
	}
	m_data->m_outgoing_packets.push_back( PacketContainer( opcode, data, encrypted, massive ) );
}

//-----------------------------------------------------------------------------

void SilkroadSecurity::Recv( const std::vector< uint8_t > & stream )
{
	if( !stream.empty() )
	{
		Recv( &stream[0], static_cast< int32_t >( stream.size() ) );
	}
}

//-----------------------------------------------------------------------------

void SilkroadSecurity::Recv( const uint8_t * stream, int32_t count )
{
	m_data->m_pending_stream.Write< uint8_t >( stream, count );
	int32_t total_bytes = m_data->m_pending_stream.GetStreamSize();
	while( total_bytes > 2 )
	{
		bool packet_encrypted = false;

		uint16_t required_size = m_data->m_pending_stream.Read< uint16_t >( true );

		if( required_size & 0x8000 )
		{
			required_size &= 0x7FFF;
			if( m_data->m_security_flags->blowfish )
			{
				required_size = static_cast< uint16_t>( 2 + m_data->m_blowfish.GetOutputLength( required_size + 4 ) );
			}
			else
			{
				required_size += 6;
			}
			packet_encrypted = true;
		}
		else
		{
			required_size += 6;
		}

		// If we have enough bytes to extract the next packet
		if( required_size <= total_bytes )
		{
			if( packet_encrypted && m_data->m_security_flags->blowfish )
			{
				uint16_t index = 2;
				uint16_t left = required_size - 2;
				uint8_t work_buffer[ 8 ];
				m_data->m_pending_stream.SeekRead( 2, Seek_Set );
				while( left )
				{
					m_data->m_pending_stream.Read< uint8_t >( work_buffer, 8 );
					m_data->m_blowfish.Decode( work_buffer, 8, work_buffer, 8 );
					m_data->m_pending_stream.Overwrite< uint8_t >( index, work_buffer, 8 );
					left -= 8;
					index += 8;
				}
				m_data->m_pending_stream.SeekRead( 0, Seek_Set );
			}

			// Save the current packet's header
			uint16_t packet_size = m_data->m_pending_stream.Read< uint16_t >();
			uint16_t packet_opcode = m_data->m_pending_stream.Read< uint16_t >();
			uint8_t packet_security_count = m_data->m_pending_stream.Read< uint8_t >(); 
			uint8_t packet_security_crc = m_data->m_pending_stream.Read< uint8_t >(); 

			// Client object whose bytes the server might need to verify
			if( m_data->m_client_security )
			{
				if( m_data->m_security_flags->security_bytes )
				{
					StreamUtility whole_packet = m_data->m_pending_stream.Extract( 0, 6 + ( packet_size & 0x7FFF ) );

					uint8_t expected_count = m_data->GenerateCountByte( true );
					if( packet_security_count != expected_count )
					{
						throw( std::runtime_error( "[SilkroadSecurity::Recv] Count byte mismatch." ) );
					}

					if( m_data->m_security_flags->security_bytes && !m_data->m_security_flags->blowfish )
					{
						if( m_data->m_enc_opcodes.find( packet_opcode ) != m_data->m_enc_opcodes.end() )
						{
							whole_packet.Overwrite< uint16_t >( 0, packet_size | 0x8000 );
							packet_encrypted = true;
						}
					}

					whole_packet.Overwrite< uint8_t >( 5, 0 );
					uint8_t expected_crc = m_data->GenerateCheckByte( whole_packet );
					if( packet_security_crc != expected_crc )
					{
						throw( std::runtime_error( "[SilkroadSecurity::Recv] CRC byte mismatch." ) );
					}
				}
			}

			// Save the current packet's data
			StreamUtility packet_data = m_data->m_pending_stream.Extract( 6, packet_size & 0x7FFF );

			// Sliding window update of remaining bytes
			m_data->m_pending_stream.Delete( 0, required_size );
			m_data->m_pending_stream.SeekRead( 0, Seek_Set );
			total_bytes -= required_size;

			if( packet_opcode == 0x5000 || packet_opcode == 0x9000 ) // New logic processing!
			{
				m_data->Handshake( packet_opcode, packet_data, packet_encrypted );
			}
			else
			{
				if( m_data->m_client_security )
				{
					// Make sure the client accepted the security system first
					if( !m_data->m_accepted_handshake )
					{
						throw( std::runtime_error( "[SilkroadSecurity::Recv] The client has not accepted the handshake." ) );
					}
				}
				if( packet_opcode == 0x600D ) // Auto process massive messages for the user
				{
					uint8_t mode = packet_data.Read< uint8_t >();
					if( mode == 1 )
					{
						m_data->m_massive_header = true;
						m_data->m_massive_count = packet_data.Read< uint16_t >();
						m_data->m_massive_opcode = packet_data.Read< uint16_t >();
					}
					else
					{
						if( m_data->m_massive_header == false )
						{
							throw( std::runtime_error( "[SilkroadSecurity::Recv] A malformed 0x600D packet was received." ) );
						}
						packet_data.Delete( 0, 1 ); // Remove the data flag
						packet_data.SeekRead( 0, Seek_Set );
						m_data->m_massive_packet.Write( packet_data.GetStreamVector() );
						m_data->m_massive_count--;
						if( m_data->m_massive_count == 0 )
						{
							m_data->m_incoming_packets.push_back( PacketContainer( m_data->m_massive_opcode, m_data->m_massive_packet, packet_encrypted, true ) );
							m_data->m_massive_header = false;
							m_data->m_massive_packet = StreamUtility();
						}
					}
				}
				else // Everything else
				{
					m_data->m_incoming_packets.push_back( PacketContainer( packet_opcode, packet_data, packet_encrypted, false ) );
				}
			}
		}
		else
		{
			break; // Otherwise we are done in this loop
		}
	}
}

//-----------------------------------------------------------------------------

void SilkroadSecurity::GenerateHandshake( bool blowfish, bool security_bytes, bool handshake )
{
	uint8_t flag = 0;
	TFlags * flags = reinterpret_cast< TFlags * >( &flag );
	if( blowfish )
	{
		flags->none = 0;
		flags->blowfish = 1;
	}
	if( security_bytes )
	{
		flags->none = 0;
		flags->security_bytes = 1;
	}
	if( handshake )
	{
		flags->none = 0;
		flags->handshake = 1;
	}
	if( !blowfish && !security_bytes && !handshake )
	{
		flags->none = 1;
	}
	m_data->GenerateHandshake( flag );
}

//-----------------------------------------------------------------------------

void SilkroadSecurity::AddEncryptedOpcode( uint16_t opcode )
{
	m_data->m_enc_opcodes.insert( opcode );
}

//-----------------------------------------------------------------------------

std::vector< uint8_t > FormatPacket( SilkroadSecurityData * silkroad_security_data, uint16_t opcode, StreamUtility & data, uint8_t encrypted )
{
	// Sanity check
	if( data.GetStreamSize() > 0x7FFF )
	{
		throw( std::runtime_error( "[FormatPacket] Packet too large." ) );
	}

	// Add the packet header to the start of the data
	data.Insert< uint16_t >( 0, static_cast< uint16_t >( data.GetStreamSize() ) ); // packet size
	data.Insert< uint16_t >( 2, opcode ); // packet opcode
	data.Insert< uint16_t >( 4, 0 ); // packet security bytes

	// Determine if we need to mark the packet size as encrypted
	if( encrypted && ( silkroad_security_data->m_security_flags->blowfish || ( silkroad_security_data->m_security_flags->security_bytes && !silkroad_security_data->m_security_flags->blowfish ) ) )
	{
		uint16_t packet_size = static_cast< uint16_t >( data.GetStreamSize() - 6 );
		packet_size |= 0x8000;
		data.Overwrite< uint16_t >( 0, packet_size );
	}

	// Only need to stamp bytes if this is a clientless object
	if( !silkroad_security_data->m_client_security && silkroad_security_data->m_security_flags->security_bytes )
	{
		uint8_t sb = 0;

		sb = silkroad_security_data->GenerateCountByte( true );
		data.Overwrite< uint8_t >( 4, sb );

		sb = silkroad_security_data->GenerateCheckByte( data );
		data.Overwrite< uint8_t >( 5, sb );
	}

	// If the packet should be physically encrypted, return an encrypted version of it
	if( encrypted && silkroad_security_data->m_security_flags->blowfish )
	{
		// Store how many data bytes there are and how many encrypted bytes are needed
		int32_t total_bytes = data.GetStreamSize() - 2;
		int32_t needed_bytes = static_cast< int32_t >( silkroad_security_data->m_blowfish.GetOutputLength( total_bytes ) );

		// Write extra padding as needed
		for( int32_t x = 0; x < ( needed_bytes - total_bytes ); ++x )
		{
			data.Write< uint8_t >( 0 );
		}

		// Blowfish work buffer, has to be mod 8 in size!
		uint8_t work_buffer[ 8 ];

		// We want to start writing after the packet size field
		int32_t write_index = 2;

		// We want to start reading the data to be encrypted
		data.SeekRead( write_index, Seek_Set );

		// Store how many bytes there are to process
		int32_t bytes_left = total_bytes;

		// Loop while we have bytes left to process
		while( bytes_left )
		{
			// Calculate how many bytes we can process
			int32_t process_count = bytes_left > 8 ? 8 : bytes_left;

			// Read in the plain text
			data.Read< uint8_t >( work_buffer, process_count );

			// Generate the cipher text
			silkroad_security_data->m_blowfish.Encode( work_buffer, process_count, work_buffer, 8 );

			// Write the final data
			data.Overwrite< uint8_t >( write_index, work_buffer, 8 );

			// Update state
			bytes_left -= process_count;
			write_index += process_count;
		}
	}
	else
	{
		// Determine if we need to unmark the packet size from being encrypted but not physically encrypted
		if( encrypted && ( silkroad_security_data->m_security_flags->security_bytes && !silkroad_security_data->m_security_flags->blowfish ) )
		{
			uint16_t packet_size = static_cast< uint16_t >( data.GetStreamSize() - 6 );
			data.Overwrite< uint16_t >( 0, packet_size );
		}
	}

	// Return the final data
	return data.GetStreamVector();
}

//-----------------------------------------------------------------------------

PacketContainer::PacketContainer()
: opcode( 0 ), encrypted( 0 ), massive( 0 )
{
}

PacketContainer::PacketContainer( uint16_t packet_opcode, const StreamUtility & packet_data, bool packet_encrypted, bool packet_massive )
: opcode( packet_opcode ), data( packet_data ), encrypted( packet_encrypted ), massive( packet_massive )
{
}

PacketContainer::PacketContainer( const PacketContainer & rhs )
{
	opcode = rhs.opcode;
	data = rhs.data;
	encrypted = rhs.encrypted;
	massive = rhs.massive;
}

PacketContainer & PacketContainer::operator =( const PacketContainer & rhs )
{
	if( this != &rhs )
	{
		opcode = rhs.opcode;
		data = rhs.data;
		encrypted = rhs.encrypted;
		massive = rhs.massive;
	}
	return *this;
}

PacketContainer::~PacketContainer()
{
}

//-----------------------------------------------------------------------------