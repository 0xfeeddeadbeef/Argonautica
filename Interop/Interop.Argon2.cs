// Copyright © 2015 Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves.

#pragma warning disable IDE1006, CA5392

using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Argonautica.Interop;

// Consider adding other Argon2 variations too. Although, they are less secure and not recommended.

[SupportedOSPlatform("linux")]
[SupportedOSPlatform("windows")]
internal static partial class Argon2
{
    /// <summary>
    ///   This resolves to <c>libargon2.so</c> or <c>argon2.dll</c> depending on the operating system.
    ///   <para>See <see href="https://learn.microsoft.com/en-us/dotnet/standard/native-interop/native-library-loading">Native library loading</see></para>
    /// </summary>
    public const string Argon2Dll = @"argon2";

    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe argon2_error_codes argon2id_hash_raw(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        void* pwd,
        nuint pwdlen,
        void* salt,
        nuint saltlen,
        void* hash,
        nuint hashlen);

    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe argon2_error_codes argon2id_hash_encoded(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        void* pwd,
        nuint pwdlen,
        void* salt,
        nuint saltlen,
        nuint hashlen,
        byte* encoded,
        nuint encodedlen);

    /// <summary>
    ///   Verifies a password against an encoded string using Argon2id hashing algorithm.
    /// </summary>
    /// <param name="encoded">Encoding parameters, salt, hash.</param>
    /// <param name="pwd">Pointer to password.</param>
    /// <param name="pwdlen">Length of password.</param>
    /// <returns>Returns <see cref="argon2_error_codes.ARGON2_OK"/> if successful.</returns>
    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe argon2_error_codes argon2id_verify(byte* encoded, void* pwd, nuint pwdlen);

    // Generic function underlying the above ones
    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe argon2_error_codes argon2_verify(
        byte* encoded,
        void* pwd,
        nuint pwdlen,
        argon2_type type);

    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe nuint argon2_encodedlen(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        uint saltlen,
        uint hashlen,
        argon2_type type);

    /// <summary>
    ///   Argon2id: Version of Argon2 where the first half-pass over memory is password-independent, the rest are
    ///   password-dependent (on the password and salt). OK against side channels (they reduce to 1/2-pass Argon2i),
    ///   and better with w.r.t. tradeoff attacks (similar to Argon2d).
    /// </summary>
    /// <param name="context">Pointer to current <see cref="argon2_context"/>.</param>
    /// <returns>Zero if successful, a non zero error code otherwise.</returns>
    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe argon2_error_codes argon2id_ctx(argon2_context* context);

    /// <summary>
    ///   Verify if a given password is correct for Argon2id hashing.
    /// </summary>
    /// <param name="context">Pointer to current <see cref="argon2_context"/>.</param>
    /// <param name="hash">
    ///   The password hash to verify. The length of the hash is specified by
    ///   the <see cref="argon2_context.outlen"/> member.
    /// </param>
    /// <returns>Zero if successful, a non zero error code otherwise.</returns>
    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe argon2_error_codes argon2id_verify_ctx(argon2_context* context, byte* hash);

    /// <summary>
    ///   Encode an Argon2 hash string into the provided buffer.
    /// </summary>
    /// <param name="dst">
    ///   Destination buffer for ASCII string of the following format:
    ///   <para><c><![CDATA[$argon2<T>[$v=<num>]$m=<num>,t=<num>,p=<num>$<bin>$<bin>]]></c></para>
    ///   where <c>T</c> is either 'd', 'id', or 'i', <c>num</c> is a decimal integer (positive,
    ///   fits in an 'unsigned long'), and <c>bin</c> is Base64-encoded data (no '=' padding
    ///   characters, no newline or whitespace).
    ///   <para>The last two binary chunks (encoded in Base64) are, in that order,
    ///   the salt and the output. Both are required. The binary salt length and the
    ///   output length must be in the allowed ranges.</para>
    /// </param>
    /// <param name="dst_len">
    ///   Contains the size, in characters, of the <paramref name="dst"/> buffer.
    /// </param>
    /// <param name="ctx">
    ///   The ctx struct must contain buffers large enough to hold the salt and pwd
    ///   when it is fed into decode_string.
    /// </param>
    /// <param name="type">Type of Argon2 algorithm.</param>
    /// <returns>
    ///   If <paramref name="dst_len"/> is less than the number of required characters (including the terminating 0),
    ///   then this function returns <see cref="argon2_error_codes.ARGON2_ENCODING_FAIL"/>.
    ///   <para>On success, <see cref="argon2_error_codes.ARGON2_OK"/> is returned.</para>
    /// </returns>
    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe argon2_error_codes encode_string(
        byte* dst,
        nuint dst_len,
        argon2_context* ctx,
        argon2_type type);

    /// <summary>
    ///   Decodes an Argon2 hash string into the provided structure <paramref name="ctx"/>.
    ///   The only fields that must be set prior to this call are <see cref="argon2_context.saltlen"/> and
    ///   <see cref="argon2_context.outlen"/> (which must be the maximal salt and out length values that are
    ///   allowed), <see cref="argon2_context.salt"/> and <see cref="argon2_context.@out"/> (which must be buffers
    ///   of the specified length), and <see cref="argon2_context.pwd"/> and <see cref="argon2_context.pwdlen"/>
    ///   which must hold a valid password.
    ///   <para>Invalid input string causes an error. On success, the ctx is valid and all
    ///   fields have been initialized.</para>
    /// </summary>
    /// <returns>
    ///   Returned value is ARGON2_OK on success, other ARGON2_ codes on error.
    /// </returns>
    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe argon2_error_codes decode_string(argon2_context* ctx, char* str, argon2_type type);

    /// <summary>
    ///   Get the associated error message for given error code.
    /// </summary>
    /// <param name="error_code">The Argon2 error code.</param>
    /// <returns>The error message associated with the given error code.</returns>
    [DllImport(Argon2Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = false, ExactSpelling = true)]
    internal extern static unsafe byte* argon2_error_message(argon2_error_codes error_code);

    public const uint ARGON2_VERSION_10 = 0x10;
    public const uint ARGON2_VERSION_13 = 0x13;

    //
    // Argon2 input parameter restrictions
    //

    /* Minimum and maximum number of lanes (degree of parallelism) */
    public const int ARGON2_MIN_LANES = 1;
    public const int ARGON2_MAX_LANES = 0xFFFFFF;

    /* Minimum and maximum number of threads */
    public const int ARGON2_MIN_THREADS = 1;
    public const int ARGON2_MAX_THREADS = 0xFFFFFF;

    /* Number of synchronization points between lanes per pass */
    public const int ARGON2_SYNC_POINTS = 4;

    /* Minimum and maximum digest size in bytes */
    public const int ARGON2_MIN_OUTLEN = 4;
    public const int ARGON2_MAX_OUTLEN = int.MaxValue;

    /* Minimum and maximum number of memory blocks (each of BLOCK_SIZE bytes) */
    public const int ARGON2_MIN_MEMORY = (2 * ARGON2_SYNC_POINTS);  /* 2 blocks per slice */

    /* Actually: Max memory size is addressing-space/2, topping at 2^32 blocks (4 TB) */
    /* But we limit it to 2 GB */
    public const int ARGON2_MAX_MEMORY = int.MaxValue;

    /* Minimum and maximum number of passes */
    public const int ARGON2_MIN_TIME = 1;
    public const int ARGON2_MAX_TIME = int.MaxValue;

    /* Minimum and maximum password length in bytes */
    public const int ARGON2_MIN_PWD_LENGTH = 0;
    public const int ARGON2_MAX_PWD_LENGTH = int.MaxValue;

    /* Minimum and maximum associated data length in bytes */
    public const int ARGON2_MIN_AD_LENGTH = 0;
    public const int ARGON2_MAX_AD_LENGTH = int.MaxValue;

    /* Minimum and maximum salt length in bytes */
    public const int ARGON2_MIN_SALT_LENGTH = 8;
    public const int ARGON2_MAX_SALT_LENGTH = int.MaxValue;

    /* Minimum and maximum key length in bytes */
    public const int ARGON2_MIN_SECRET = 0;
    public const int ARGON2_MAX_SECRET = int.MaxValue;

    /* Flags to determine which fields are securely wiped (default = no wipe). */
    public const uint ARGON2_DEFAULT_FLAGS = 0U;
    public const uint ARGON2_FLAG_CLEAR_PASSWORD = (1U << 0);
    public const uint ARGON2_FLAG_CLEAR_SECRET = (1U << 1);
}

/// <summary>
///   Argon2 error codes.
/// </summary>
internal enum argon2_error_codes
{
    ARGON2_OK = 0,
    ARGON2_OUTPUT_PTR_NULL = -1,
    ARGON2_OUTPUT_TOO_SHORT = -2,
    ARGON2_OUTPUT_TOO_LONG = -3,
    ARGON2_PWD_TOO_SHORT = -4,
    ARGON2_PWD_TOO_LONG = -5,
    ARGON2_SALT_TOO_SHORT = -6,
    ARGON2_SALT_TOO_LONG = -7,
    ARGON2_AD_TOO_SHORT = -8,
    ARGON2_AD_TOO_LONG = -9,
    ARGON2_SECRET_TOO_SHORT = -10,
    ARGON2_SECRET_TOO_LONG = -11,
    ARGON2_TIME_TOO_SMALL = -12,
    ARGON2_TIME_TOO_LARGE = -13,
    ARGON2_MEMORY_TOO_LITTLE = -14,
    ARGON2_MEMORY_TOO_MUCH = -15,
    ARGON2_LANES_TOO_FEW = -16,
    ARGON2_LANES_TOO_MANY = -17,
    ARGON2_PWD_PTR_MISMATCH = -18,    /* NULL ptr with non-zero length */
    ARGON2_SALT_PTR_MISMATCH = -19,   /* NULL ptr with non-zero length */
    ARGON2_SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
    ARGON2_AD_PTR_MISMATCH = -21,     /* NULL ptr with non-zero length */
    ARGON2_MEMORY_ALLOCATION_ERROR = -22,
    ARGON2_FREE_MEMORY_CBK_NULL = -23,
    ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,
    ARGON2_INCORRECT_PARAMETER = -25,
    ARGON2_INCORRECT_TYPE = -26,
    ARGON2_OUT_PTR_MISMATCH = -27,
    ARGON2_THREADS_TOO_FEW = -28,
    ARGON2_THREADS_TOO_MANY = -29,
    ARGON2_MISSING_ARGS = -30,
    ARGON2_ENCODING_FAIL = -31,
    ARGON2_DECODING_FAIL = -32,
    ARGON2_THREAD_FAIL = -33,
    ARGON2_DECODING_LENGTH_FAIL = -34,
    ARGON2_VERIFY_MISMATCH = -35,
}

/// <summary>
///   Argon2 primitive type.
/// </summary>
internal enum argon2_type
{
    Argon2_d = 0,
    Argon2_i = 1,
    Argon2_id = 2,
}

// Pack=16 is for x64 platform
// TODO: Create another struct with Pack=8 when you add 32-bit platform target to this project (Do not reuse this one)
[StructLayout(LayoutKind.Sequential, Pack = 16)]
internal unsafe struct argon2_context
{
    /// <summary>
    ///   Output array.
    /// </summary>
    public byte* @out;
    /// <summary>
    ///   Digest length.
    /// </summary>
    public uint outlen;

    /// <summary>
    ///   Password array.
    /// </summary>
    public byte* pwd;
    /// <summary>
    ///   Password length.
    /// </summary>
    public uint pwdlen;

    /// <summary>
    ///   Salt array.
    /// </summary>
    public byte* salt;
    /// <summary>
    ///   Salt length.
    /// </summary>
    public uint saltlen;

    /// <summary>
    ///   Key array.
    /// </summary>
    public byte* secret;
    /// <summary>
    ///   Key length.
    /// </summary>
    public uint secretlen;

    /// <summary>
    ///   Associated data array.
    /// </summary>
    public byte* ad;
    /// <summary>
    ///   Associated data length.
    /// </summary>
    public uint adlen;

    /// <summary>
    ///   Number of passes.
    /// </summary>
    public uint t_cost;
    /// <summary>
    ///   Amount of memory requested (KB).
    /// </summary>
    public uint m_cost;
    /// <summary>
    ///   Number of lanes.
    /// </summary>
    public uint lanes;
    /// <summary>
    ///   Maximum number of threads.
    /// </summary>
    public uint threads;

    /// <summary>
    ///   Version number.
    /// </summary>
    public uint version;

    /// <summary>
    ///   Pointer to memory allocator.
    /// </summary>
    public IntPtr allocate_cbk;
    /// <summary>
    ///   pointer to memory deallocator.
    /// </summary>
    public IntPtr free_cbk;

    /// <summary>
    ///   Array of bool options.
    /// </summary>
    public uint flags;
}
