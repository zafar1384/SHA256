// Author: Remco Bloemen
// Based on:
//   http://en.wikipedia.org/wiki/SHA-2
//   http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
//   OpenSSL optimizations

#pragma once
#include <string.h>
#include <string>

/// Class to quickly compute SHA-256 hashes
///
/// This class has been heavily optimized for speed
/// at a slight expense of code size.
///
/// Example usage:
/// @code
///   SHA256 hash;
///   hash.append("The quick brown fox jumps over the lazy dog.");
///   hash.finalize();
///   std::cout << "Digest: " << hash.hexString() << std::endl;
/// @endcode
class SHA256 {
public:

    //// Create a new instance, ready for appending
    SHA256() { reset(); }
    
    /// Reset this instance so you can calculate a new hash
    void reset();
    
    /// Append data to the hash
    ///
    /// Note: due to word-allignment optimizations
    /// the function may read up to three bytes beyond
    /// the end of data.
    ///
    /// @param data the bytes to be added.
    /// @param size the number of bytes to read from data, but see the note.
    void append(const char* data, int size);
    
    /// Append a single byte
    ///
    /// Avoid this function if performance is important.
    ///
    /// @param c the character to be appended.
    void append(char c) { append(&c, 1); }
    
    /// Append a zero terminated string
    ///
    /// The terminating zero itself is not appended.
    ///
    /// @param str the zero terminated string to be appended.
    void append(const char* str) { append(str, strlen(str)); }
    
    /// Append a std::string
    ///
    /// @param str The std::string to be appended.
    void append(const std::string& str) { append(str.data(), str.length()); }
    
    /// Append the required padding and compute the final digest
    ///
    /// Always call this function first before requesting the digest.
    ///
    /// After finalization you must call reset() before you can append again.
    ///
    /// However, you can do this:
    /// @code
    ///   SHA256 A, AB;
    ///   A.append("First part");
    ///   AB = A;
    ///   A.finalize();
    ///   do_something(A.digest());
    ///   AB.append("Second part");
    ///   AB.finalize();
    ///   do_something(AB.digest());
    /// @endcode
    void finalize();
    
    /// Returns a pointer to the 32 bytes of the digest
    ///
    /// @returns a pointer to a non-zero-terminated block of
    /// 32 bytes containting the digest.
    const char* digest() { return reinterpret_cast<char*>(hash); }
    
    /// Return the digest as a binary std::string
    ///
    /// Avoid this function if performance is important,
    /// the std::string constructor will make a copy of the
    /// digest internally, doing a malloc and memcpy.
    ///
    /// @returns a std::string containing the digest as raw binary bits.
    std::string binString() { return std::string(digest(), 32); }
    
    /// Return the digest as a hexadecimal std::string
    ///
    /// In addition to the note for binaryString, this function
    /// also does conversion.
    ///
    /// @returns a std::string containing the digest in hexadecimal ascii.
    std::string hexString();
    
protected:
    int length;
    unsigned int hash[8];
    unsigned int w[16];
    void process_chunk();
};

