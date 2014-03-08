//-----------------------------------------------------------------------------
/*
	Standardized (Little-Endian) Blowfish Implementation
	pushedx

	This version is based off of the Jim Conger implementation of 
	Bruce Schneier's Blowfish algorithm. This version makes use of
	stdint for types to get rid of the Windows dependencies. In addition,
	the code has been modified to be x64 compatible but uses 32bit types.

	The original URL for the base implementations can be found here:
	http://www.schneier.com/blowfish-download.html
*/
//-----------------------------------------------------------------------------

#pragma once

#ifndef BLOWFISH_H_
#define BLOWFISH_H_

//-----------------------------------------------------------------------------

#include <stdint.h>

//-----------------------------------------------------------------------------

// Rather than using a real PIMPL, I've changed this version to use the stack
// instead so there is no extra overhead from heap allocations for each
// Blowfish object. However, this can still be changed if desired by
// moving this definition back into std_blowfish.cpp and forward declaring
// the type.
struct BlowfishPIMPL
{
	uint32_t PArray[18];
	uint32_t SBoxes[4][256];

	void Blowfish_encipher( uint32_t * xl, uint32_t * xr );
	void Blowfish_decipher( uint32_t * xl, uint32_t * xr );
	bool Initialize( const void * const key_ptr, int32_t key_size );
	int32_t GetOutputLength( int32_t input_size );
	bool Encode( void const * const input_ptr, int32_t input_size, void * output_ptr, int32_t output_size );
	bool Decode( const void * const input_ptr, int32_t input_size, void * output_ptr, int32_t output_size );
};

//-----------------------------------------------------------------------------

class Blowfish
{
private:
	BlowfishPIMPL m_BlowfishPIMPL;

public:
	Blowfish();
	~Blowfish();

	// Sets up the blowfish object with this specific key. If the key is too
	// long (56 bytes max) or too short (0) or key_ptr is null, then false is returned.
	bool Initialize( const void * const key_ptr, int32_t key_size );
	// Returns the output length based on the size. This can be used to 
	// determine how many bytes of output space is needed for data that
	// is about to be encoded or decoded.
	int32_t GetOutputLength( int32_t input_size );

	// Encodes/Decodes the data. Returns false on an error (such as invalid 
	// sizes, or invalid parameters) and true on success.
	bool Encode( const void * const input_ptr, int32_t input_size, void * output_ptr, int32_t output_size );
	bool Decode( const void * const input_ptr, int32_t input_size, void * output_ptr, int32_t output_size );
};

//-----------------------------------------------------------------------------

#endif
