#pragma once

#include <stdint.h>
#include <string.h>
#include <array>

/*
 * @brief Size of the chunks used for the calculations.
 *
 * @note This should mostly be ignored by the user, although when using the streaming API, it has an impact for
 * performance. Add chunks whose size is a multiple of this, and you will avoid a lot of superfluous copying in RAM!
 */
#define SIZE_OF_SHA_256_CHUNK 64

/*
 * @brief The opaque SHA-256 type, that should be instantiated when using the streaming API.
 *
 * @note Although the details are exposed here, in order to make instantiation easy, you should refrain from directly
 * accessing the fields, as they may change in the future.
 */
class sha256_hasher {
public:
	sha256_hasher();
	void update(const uint8_t* data, size_t len);
	std::array<uint8_t, 32> finalize();

private:
	std::array<uint8_t, 32> hash;
	uint8_t chunk[SIZE_OF_SHA_256_CHUNK];
	uint8_t *chunk_pos;
	size_t space_left;
	uint64_t total_len;
	uint32_t h[8];
};
