// Copyright © 2015 Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves.

#pragma warning disable CS0809, IDE1006

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Argonautica.Interop;
using static Argonautica.Interop.Argon2;

namespace Argonautica
{
    /// <summary>
    ///   Argon2id: Version of Argon2 where the first half-pass over memory is password-independent, the rest are
    ///   password-dependent (On the password and salt). OK against side channels (They reduce to 1/2-pass Argon2i),
    ///   and better with reference to tradeoff attacks (Similar to Argon2d).
    /// </summary>
    /// <remarks>
    ///   <para>Modeled after the <see cref="Rfc2898DeriveBytes"/> class, but does not support stream-like operation.</para>
    ///   <para>Usage of instance methods is strongly discouraged.</para>
    /// </remarks>
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("windows")]
    public class Argon2idDeriveBytes : DeriveBytes
    {
        // Throws on invalid input:
        private static readonly UTF8Encoding s_throwingUtf8Encoding = new(false, true);
        private static Dictionary<argon2_error_codes, string?>? s_argon2Errors;
        private readonly byte[] _password;
        private readonly byte[] _salt;
        private readonly int _iterations;
        private readonly int _memoryCost;
        private readonly int _parallelism;

        //
        // Note about password length: Argon2 allows 0-length (but not null) passwords
        //

        /// <summary>
        ///   Gets a value that indicates whether the algorithm is supported on the current platform.
        /// </summary>
        /// <value>
        ///   <see langword="true"/> if the algorithm is supported; otherwise, <see langword="false"/>.
        /// </value>
        /// <remarks>
        ///   Currently the native package is available only for these OSes.
        /// </remarks>
        [SupportedOSPlatformGuard("linux")]
        [SupportedOSPlatformGuard("windows")]
        public static bool IsSupported { get; } = OperatingSystem.IsWindows() || OperatingSystem.IsLinux();

        /// <summary>
        ///   Initializes a new instance of the <see cref="Argon2idDeriveBytes"/> class.
        /// </summary>
        /// <param name="password">A password bytes. Can be an empty array, but not <see langword="null"/>.</param>
        /// <param name="salt">A random salt bytes. Must be at least 8 bytes.</param>
        /// <param name="iterations">Number of iterations. Must be at least 1.</param>
        /// <param name="memoryCost">In kilobytes (KB). Memory cost per single hash calculation.</param>
        /// <param name="parallelism">Number of threads. Must be at least 1.</param>
        /// <exception cref="ArgumentNullException">
        ///   Either <paramref name="password"/> or <paramref name="salt"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   Length of one of the arguments is out of range of allowed bounds.
        /// </exception>
        [Obsolete("Usage of instance methods is strongly discouraged. Use static ones instead.",
            DiagnosticId = "ARGON2_0001")]
        public Argon2idDeriveBytes(
            byte[] password,
            byte[] salt,
            int iterations,
            int memoryCost,
            int parallelism)
        {
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(salt);

            if (salt.Length < ARGON2_MIN_SALT_LENGTH)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(salt));
            }

            if (iterations < ARGON2_MIN_TIME)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(iterations));
            }

            if (memoryCost < ARGON2_MIN_MEMORY)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(memoryCost));
            }

            if (parallelism < ARGON2_MIN_THREADS)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(parallelism));
            }

            _password = password;
            _salt = salt;
            _iterations = iterations;
            _memoryCost = memoryCost;
            _parallelism = parallelism;
        }

        /// <summary>
        ///   Generates pseudo-random key bytes using the Argon2id password hashing function.
        /// </summary>
        /// <param name="cb">The number of pseudo-random key bytes to generate.</param>
        /// <returns>Pseudo-random key bytes.</returns>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   The <paramref name="cb"/> is zero or negative number.
        /// </exception>
        [Obsolete("Usage of instance methods is strongly discouraged. Use static ones instead.",
            DiagnosticId = "ARGON2_0001")]
        public override byte[] GetBytes(int cb)
        {
            if (cb <= 0)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(cb));
            }

            var hash = new byte[cb];
            Argon2id(
                new ReadOnlySpan<byte>(_password),
                new ReadOnlySpan<byte>(_salt),
                hash.AsSpan(),
                _iterations, _memoryCost, _parallelism);
            return hash;
        }

        /// <summary>
        ///   Does nothing. The <see cref="Argon2idDeriveBytes"/> does not support stream-like operations.
        /// </summary>
        [Obsolete("Usage of instance methods is strongly discouraged. Use static ones instead.",
            DiagnosticId = "ARGON2_0001")]
        public override void Reset()
        {
        }

        /// <summary>
        ///   Calculates an Argon2id hash from password bytes.
        /// </summary>
        /// <param name="password">The password. Can be empty, but not <see langword="null"/>.</param>
        /// <param name="salt">The salt. Must be at least 8 bytes.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="memoryCost">Kilobytes of memory to be allocated for the operation.</param>
        /// <param name="parallelism">Number of parallel threads.</param>
        /// <param name="outputLength">Size of output byte array.</param>
        /// <returns>A byte array containing the hash with <paramref name="outputLength"/> bytes length.</returns>
        public static byte[] Argon2id(
            byte[] password,
            byte[] salt,
            int iterations,
            int memoryCost,
            int parallelism,
            int outputLength)
        {
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(salt);

            if (salt.Length < ARGON2_MIN_SALT_LENGTH)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(salt));
            }

            if (iterations < ARGON2_MIN_TIME)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(iterations));
            }

            if (memoryCost < ARGON2_MIN_MEMORY)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(memoryCost));
            }

            if (parallelism < ARGON2_MIN_THREADS)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(parallelism));
            }

            if (outputLength < ARGON2_MIN_OUTLEN)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(outputLength));
            }

            return Argon2id(
                new ReadOnlySpan<byte>(password),
                new ReadOnlySpan<byte>(salt),
                iterations, memoryCost, parallelism,
                outputLength);
        }

        /// <summary>
        ///   Calculates an Argon2id hash from password bytes.
        /// </summary>
        /// <param name="password">The password. Can be empty, but not <see langword="null"/>.</param>
        /// <param name="salt">The salt. Must be at least 8 bytes.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="memoryCost">Kilobytes of memory to be allocated for the operation.</param>
        /// <param name="parallelism">Number of parallel threads.</param>
        /// <param name="outputLength">Size of output byte array.</param>
        /// <returns>A byte array containing the hash with <paramref name="outputLength"/> bytes length.</returns>
        public static byte[] Argon2id(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            int iterations,
            int memoryCost,
            int parallelism,
            int outputLength)
        {
            if (Unsafe.IsNullRef(ref MemoryMarshal.GetReference(password)))
            {
                ThrowHelper.ThrowArgumentNullException(nameof(password));
            }

            if (salt.Length < ARGON2_MIN_SALT_LENGTH)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(salt));
            }

            if (iterations < ARGON2_MIN_TIME)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(iterations));
            }

            if (memoryCost < ARGON2_MIN_MEMORY)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(memoryCost));
            }

            if (parallelism < ARGON2_MIN_THREADS)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(parallelism));
            }

            if (outputLength < ARGON2_MIN_OUTLEN)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(outputLength));
            }

            var result = new byte[outputLength];
            Argon2idCore(password, salt, result.AsSpan(), iterations, memoryCost, parallelism);
            return result;
        }

        /// <summary>
        ///   Calculates an Argon2id hash from password bytes. Uses secret key and additional data for peppering.
        /// </summary>
        /// <param name="password">The password. Can be empty, but not <see langword="null"/>.</param>
        /// <param name="salt">The salt. Must be at least 8 bytes.</param>
        /// <param name="secret">The optional secret key.</param>
        /// <param name="additionalData">The optional additional data. Can be anything. Not necessarily a secret.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="memoryCost">Kilobytes of memory to be allocated for the operation.</param>
        /// <param name="parallelism">Number of parallel threads.</param>
        /// <param name="outputLength">Size of output byte array.</param>
        /// <returns>A byte array containing the hash with <paramref name="outputLength"/> bytes length.</returns>
        public static byte[] Argon2id(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> secret,
            ReadOnlySpan<byte> additionalData,
            int iterations,
            int memoryCost,
            int parallelism,
            int outputLength)
        {
            if (Unsafe.IsNullRef(ref MemoryMarshal.GetReference(password)))
            {
                ThrowHelper.ThrowArgumentNullException(nameof(password));
            }

            if (salt.Length < ARGON2_MIN_SALT_LENGTH)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(salt));
            }

            if (iterations < ARGON2_MIN_TIME)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(iterations));
            }

            if (memoryCost < ARGON2_MIN_MEMORY)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(memoryCost));
            }

            if (parallelism < ARGON2_MIN_THREADS)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(parallelism));
            }

            if (outputLength < ARGON2_MIN_OUTLEN)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(outputLength));
            }

            var result = new byte[outputLength];
            Argon2idCore(password, salt,
                secret, additionalData, result.AsSpan(),
                iterations, memoryCost, parallelism);
            return result;
        }

        /// <summary>
        ///   Calculates an Argon2id hash from password bytes.
        /// </summary>
        /// <param name="password">The password. Can be empty, but not <see langword="null"/>.</param>
        /// <param name="salt">The salt. Must be at least 8 bytes.</param>
        /// <param name="destination">The destination buffer that can hold the calculated hash. Must not be null or empty.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="memoryCost">Kilobytes of memory to be allocated for the operation.</param>
        /// <param name="parallelism">Number of parallel threads.</param>
        public static void Argon2id(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> destination,
            int iterations,
            int memoryCost,
            int parallelism)
        {
            if (Unsafe.IsNullRef(ref MemoryMarshal.GetReference(password)))
            {
                ThrowHelper.ThrowArgumentNullException(nameof(password));
            }

            if (Unsafe.IsNullRef(ref MemoryMarshal.GetReference(destination)))
            {
                ThrowHelper.ThrowArgumentNullException(nameof(destination));
            }

            if (salt.Length < ARGON2_MIN_SALT_LENGTH)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(salt));
            }

            if (iterations < ARGON2_MIN_TIME)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(iterations));
            }

            if (memoryCost < ARGON2_MIN_MEMORY)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(memoryCost));
            }

            if (parallelism < ARGON2_MIN_THREADS)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(parallelism));
            }

            Argon2idCore(password, salt, destination, iterations, memoryCost, parallelism);
        }

        /// <summary>
        ///   Calculates an Argon2id hash from password bytes. Uses secret key and additional data for peppering.
        /// </summary>
        /// <param name="password">The password. Can be empty, but not <see langword="null"/>.</param>
        /// <param name="salt">The salt. Must be at least 8 bytes.</param>
        /// <param name="secret">The optional secret key.</param>
        /// <param name="additionalData">The optional additional data. Can be anything. Not necessarily a secret.</param>
        /// <param name="destination">The destination buffer that can hold the calculated hash. Must not be null or empty.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="memoryCost">Kilobytes of memory to be allocated for the operation.</param>
        /// <param name="parallelism">Number of parallel threads.</param>
        public static void Argon2id(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> secret,
            ReadOnlySpan<byte> additionalData,
            Span<byte> destination,
            int iterations,
            int memoryCost,
            int parallelism)
        {
            if (Unsafe.IsNullRef(ref MemoryMarshal.GetReference(password)))
            {
                ThrowHelper.ThrowArgumentNullException(nameof(password));
            }

            if (Unsafe.IsNullRef(ref MemoryMarshal.GetReference(destination)))
            {
                ThrowHelper.ThrowArgumentNullException(nameof(destination));
            }

            if (salt.Length < ARGON2_MIN_SALT_LENGTH)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(salt));
            }

            if (iterations < ARGON2_MIN_TIME)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(iterations));
            }

            if (memoryCost < ARGON2_MIN_MEMORY)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(memoryCost));
            }

            if (parallelism < ARGON2_MIN_THREADS)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(parallelism));
            }

            Argon2idCore(password, salt,
                secret, additionalData,
                destination, iterations,
                memoryCost, parallelism);
        }

        /// <summary>
        ///   Calculates an Argon2id hash from password string. Uses UTF-8 encoding to convert password to bytes.
        /// </summary>
        /// <param name="password">The password. Can be empty, but not <see langword="null"/>.</param>
        /// <param name="salt">The salt. Must be at least 8 bytes.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="memoryCost">Kilobytes of memory to be allocated for the operation.</param>
        /// <param name="parallelism">Number of parallel threads.</param>
        /// <param name="outputLength">Size of output byte array.</param>
        /// <returns>A byte array containing the hash with <paramref name="outputLength"/> bytes length.</returns>
        public static byte[] Argon2id(
            string password,
            byte[] salt,
            int iterations,
            int memoryCost,
            int parallelism,
            int outputLength)
        {
            ArgumentNullException.ThrowIfNull(password);
            ArgumentNullException.ThrowIfNull(salt);

            if (salt.Length < ARGON2_MIN_SALT_LENGTH)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(salt));
            }

            if (iterations < ARGON2_MIN_TIME)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(iterations));
            }

            if (memoryCost < ARGON2_MIN_MEMORY)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(memoryCost));
            }

            if (parallelism < ARGON2_MIN_THREADS)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(parallelism));
            }

            if (outputLength < ARGON2_MIN_OUTLEN)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(outputLength));
            }

            return Argon2id(password.AsSpan(), new ReadOnlySpan<byte>(salt),
                iterations, memoryCost, parallelism, outputLength);
        }

        /// <summary>
        ///   Calculates an Argon2id hash from password string. Uses UTF-8 encoding to convert password to bytes.
        /// </summary>
        /// <param name="password">The password. Can be empty, but not <see langword="null"/>.</param>
        /// <param name="salt">The salt. Must be at least 8 bytes.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="memoryCost">Kilobytes of memory to be allocated for the operation.</param>
        /// <param name="parallelism">Number of parallel threads.</param>
        /// <param name="outputLength">Size of output byte array.</param>
        /// <returns>A byte array containing the hash with <paramref name="outputLength"/> bytes length.</returns>
        public static byte[] Argon2id(
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> salt,
            int iterations,
            int memoryCost,
            int parallelism,
            int outputLength)
        {
            if (Unsafe.IsNullRef(ref MemoryMarshal.GetReference(password)))
            {
                ThrowHelper.ThrowArgumentNullException(nameof(password));
            }

            if (salt.Length < ARGON2_MIN_SALT_LENGTH)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(salt));
            }

            if (iterations < ARGON2_MIN_TIME)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(iterations));
            }

            if (memoryCost < ARGON2_MIN_MEMORY)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(memoryCost));
            }

            if (parallelism < ARGON2_MIN_THREADS)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(parallelism));
            }

            if (outputLength < ARGON2_MIN_OUTLEN)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(outputLength));
            }

            var result = new byte[outputLength];
            Argon2idCore(password, salt, result.AsSpan(), iterations, memoryCost, parallelism);
            return result;
        }

        /// <summary>
        ///   Calculates an Argon2id hash from password string. Uses UTF-8 encoding to convert password to bytes.
        /// </summary>
        /// <param name="password">The password. Can be empty, but not <see langword="null"/>.</param>
        /// <param name="salt">The salt. Must be at least 8 bytes.</param>
        /// <param name="destination">The destination buffer that can hold the calculated hash. Must not be null or empty.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="memoryCost">Kilobytes of memory to be allocated for the operation.</param>
        /// <param name="parallelism">Number of parallel threads.</param>
        /// <param name="outputLength">Size of output byte array.</param>
        public static void Argon2id(
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> salt,
            Span<byte> destination,
            int iterations,
            int memoryCost,
            int parallelism,
            int outputLength)
        {
            if (Unsafe.IsNullRef(ref MemoryMarshal.GetReference(password)))
            {
                ThrowHelper.ThrowArgumentNullException(nameof(password));
            }

            if (Unsafe.IsNullRef(ref MemoryMarshal.GetReference(destination)))
            {
                ThrowHelper.ThrowArgumentNullException(nameof(destination));
            }

            if (salt.Length < ARGON2_MIN_SALT_LENGTH)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(salt));
            }

            if (iterations < ARGON2_MIN_TIME)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(iterations));
            }

            if (memoryCost < ARGON2_MIN_MEMORY)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(memoryCost));
            }

            if (parallelism < ARGON2_MIN_THREADS)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(parallelism));
            }

            if (outputLength < ARGON2_MIN_OUTLEN)
            {
                ThrowHelper.ThrowArgumentOutOfRangeException(nameof(outputLength));
            }

            Argon2idCore(password, salt, destination, iterations, memoryCost, parallelism);
        }

        //
        // Private methods:
        //

        private static void Argon2idCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            Span<byte> destination,
            int iterations,
            int memoryCost,
            int parallelism)
        {
            Debug.Assert(iterations > 0);
            Debug.Assert(memoryCost > 0);
            Debug.Assert(parallelism > 0);

            if (destination.IsEmpty)
            {
                return;
            }

            argon2_error_codes err = argon2_error_codes.ARGON2_OK;
            unsafe
            {
                fixed (byte* passwordPtr = password)
                fixed (byte* saltPtr = salt)
                fixed (byte* hashPtr = &SpanHelpers.GetNonNullPinnableReference(destination))
                {
                    err = argon2id_hash_raw(
                        (uint)iterations, (uint)memoryCost, (uint)parallelism,
                        passwordPtr, (nuint)password.Length,
                        saltPtr, (nuint)salt.Length,
                        hashPtr, (nuint)destination.Length);
                }
            }

            if (err != argon2_error_codes.ARGON2_OK)
            {
                ThrowHelper.ThrowCryptographicException(GetNativeErrorMessage(err));
            }
        }

        private static void Argon2idCore(
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> salt,
            Span<byte> destination,
            int iterations,
            int memoryCost,
            int parallelism)
        {
            Debug.Assert(iterations > 0);
            Debug.Assert(memoryCost > 0);
            Debug.Assert(parallelism > 0);

            if (destination.IsEmpty)
            {
                return;
            }

            const int maxPasswordStackSize = 384;

            // Believe or not, this is how Rfc2898DeriveBytes does it:
            byte[]? rentedPasswordBuffer = null;
            int maxEncodedSize = s_throwingUtf8Encoding.GetMaxByteCount(password.Length);
            Span<byte> passwordBuffer = maxEncodedSize > maxPasswordStackSize ?
                (rentedPasswordBuffer = CryptoPool.Rent(maxEncodedSize)) :
                stackalloc byte[maxPasswordStackSize];
            int passwordBytesWritten = s_throwingUtf8Encoding.GetBytes(password, passwordBuffer);
            Span<byte> passwordBytes = passwordBuffer[..passwordBytesWritten];

            argon2_error_codes err = argon2_error_codes.ARGON2_OK;
            try
            {
                unsafe
                {
                    fixed (byte* passwordPtr = passwordBuffer)
                    fixed (byte* saltPtr = salt)
                    fixed (byte* hashPtr = &SpanHelpers.GetNonNullPinnableReference(destination))
                    {
                        err = argon2id_hash_raw(
                            (uint)iterations, (uint)memoryCost, (uint)parallelism,
                            passwordPtr, (nuint)password.Length,
                            saltPtr, (nuint)salt.Length,
                            hashPtr, (nuint)destination.Length);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(passwordBytes);
            }

            if (rentedPasswordBuffer is not null)
            {
                CryptoPool.Return(rentedPasswordBuffer, clearSize: 0);  // Manually cleared above
            }

            if (err != argon2_error_codes.ARGON2_OK)
            {
                ThrowHelper.ThrowCryptographicException(GetNativeErrorMessage(err));
            }
        }

        //
        // Advanced
        //

        private static void Argon2idCore(
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> secret,
            ReadOnlySpan<byte> additionalData,
            Span<byte> destination,
            int iterations,
            int memoryCostInKilobytes,
            int parallelism)
        {
            Debug.Assert(iterations > 0);
            Debug.Assert(memoryCostInKilobytes > 0);
            Debug.Assert(parallelism > 0);

            if (destination.IsEmpty)
            {
                return;
            }

            argon2_error_codes err = argon2_error_codes.ARGON2_OK;
            unsafe
            {
                fixed (byte* passwordPtr = password)
                fixed (byte* saltPtr = salt)
                fixed (byte* hashPtr = &SpanHelpers.GetNonNullPinnableReference(destination))
                fixed (byte* secretPtr = &SpanHelpers.GetNonNullPinnableReference(secret))
                fixed (byte* additionalDataPtr = &SpanHelpers.GetNonNullPinnableReference(additionalData))
                {
                    argon2_context ctx = default;
                    ctx.@out = hashPtr;
                    ctx.outlen = (uint)destination.Length;
                    ctx.pwd = passwordPtr;
                    ctx.pwdlen = (uint)password.Length;
                    ctx.salt = saltPtr;
                    ctx.saltlen = (uint)salt.Length;

                    if (!secret.IsEmpty)
                    {
                        ctx.secret = secretPtr;
                        ctx.secretlen = (uint)secret.Length;
                    }

                    if (!additionalData.IsEmpty)
                    {
                        ctx.ad = additionalDataPtr;
                        ctx.adlen = (uint)additionalData.Length;
                    }

                    ctx.t_cost = (uint)iterations;
                    ctx.m_cost = (uint)memoryCostInKilobytes;
                    ctx.lanes = (uint)parallelism;
                    ctx.threads = (uint)parallelism;
                    ctx.version = ARGON2_VERSION_13;

                    err = argon2id_ctx(&ctx);
                }
            }

            if (err != argon2_error_codes.ARGON2_OK)
            {
                ThrowHelper.ThrowCryptographicException(GetNativeErrorMessage(err));
            }
        }

        /// <summary>
        ///   Retrieve Argon2 error message.
        /// </summary>
        /// <param name="errorCode">Argon2 error code.</param>
        /// <returns>Argon2 error message.</returns>
        [MethodImpl(MethodImplOptions.NoInlining)]  // This is intentional (Explained in ThrowHelper.cs)
        internal static string GetNativeErrorMessage(argon2_error_codes errorCode)
        {
            _ = Argon2Errors.TryGetValue(errorCode, out var errorMessage);
            return errorMessage ?? "Unknown error";
        }

        private static Dictionary<argon2_error_codes, string?> Argon2Errors
        {
            get => LazyInitializer.EnsureInitialized(ref s_argon2Errors, static () =>
            {
                unsafe
                {
                    return new Dictionary<argon2_error_codes, string?>(capacity: 36)
                    {
                        [argon2_error_codes.ARGON2_OK] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_OK))),
                        [argon2_error_codes.ARGON2_OUTPUT_PTR_NULL] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_OUTPUT_PTR_NULL))),
                        [argon2_error_codes.ARGON2_OUTPUT_TOO_SHORT] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_OUTPUT_TOO_SHORT))),
                        [argon2_error_codes.ARGON2_OUTPUT_TOO_LONG] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_OUTPUT_TOO_LONG))),
                        [argon2_error_codes.ARGON2_PWD_TOO_SHORT] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_PWD_TOO_SHORT))),
                        [argon2_error_codes.ARGON2_PWD_TOO_LONG] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_PWD_TOO_LONG))),
                        [argon2_error_codes.ARGON2_SALT_TOO_SHORT] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_SALT_TOO_SHORT))),
                        [argon2_error_codes.ARGON2_SALT_TOO_LONG] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_SALT_TOO_LONG))),
                        [argon2_error_codes.ARGON2_AD_TOO_SHORT] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_AD_TOO_SHORT))),
                        [argon2_error_codes.ARGON2_AD_TOO_LONG] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_AD_TOO_LONG))),
                        [argon2_error_codes.ARGON2_SECRET_TOO_SHORT] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_SECRET_TOO_SHORT))),
                        [argon2_error_codes.ARGON2_SECRET_TOO_LONG] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_SECRET_TOO_LONG))),
                        [argon2_error_codes.ARGON2_TIME_TOO_SMALL] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_TIME_TOO_SMALL))),
                        [argon2_error_codes.ARGON2_TIME_TOO_LARGE] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_TIME_TOO_LARGE))),
                        [argon2_error_codes.ARGON2_MEMORY_TOO_LITTLE] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_MEMORY_TOO_LITTLE))),
                        [argon2_error_codes.ARGON2_MEMORY_TOO_MUCH] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_MEMORY_TOO_MUCH))),
                        [argon2_error_codes.ARGON2_LANES_TOO_FEW] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_LANES_TOO_FEW))),
                        [argon2_error_codes.ARGON2_LANES_TOO_MANY] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_LANES_TOO_MANY))),
                        [argon2_error_codes.ARGON2_PWD_PTR_MISMATCH] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_PWD_PTR_MISMATCH))),
                        [argon2_error_codes.ARGON2_SALT_PTR_MISMATCH] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_SALT_PTR_MISMATCH))),
                        [argon2_error_codes.ARGON2_SECRET_PTR_MISMATCH] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_SECRET_PTR_MISMATCH))),
                        [argon2_error_codes.ARGON2_AD_PTR_MISMATCH] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_AD_PTR_MISMATCH))),
                        [argon2_error_codes.ARGON2_MEMORY_ALLOCATION_ERROR] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_MEMORY_ALLOCATION_ERROR))),
                        [argon2_error_codes.ARGON2_FREE_MEMORY_CBK_NULL] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_FREE_MEMORY_CBK_NULL))),
                        [argon2_error_codes.ARGON2_ALLOCATE_MEMORY_CBK_NULL] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_ALLOCATE_MEMORY_CBK_NULL))),
                        [argon2_error_codes.ARGON2_INCORRECT_PARAMETER] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_INCORRECT_PARAMETER))),
                        [argon2_error_codes.ARGON2_INCORRECT_TYPE] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_INCORRECT_TYPE))),
                        [argon2_error_codes.ARGON2_OUT_PTR_MISMATCH] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_OUT_PTR_MISMATCH))),
                        [argon2_error_codes.ARGON2_THREADS_TOO_FEW] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_THREADS_TOO_FEW))),
                        [argon2_error_codes.ARGON2_THREADS_TOO_MANY] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_THREADS_TOO_MANY))),
                        [argon2_error_codes.ARGON2_MISSING_ARGS] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_MISSING_ARGS))),
                        [argon2_error_codes.ARGON2_ENCODING_FAIL] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_ENCODING_FAIL))),
                        [argon2_error_codes.ARGON2_DECODING_FAIL] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_DECODING_FAIL))),
                        [argon2_error_codes.ARGON2_THREAD_FAIL] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_THREAD_FAIL))),
                        [argon2_error_codes.ARGON2_DECODING_LENGTH_FAIL] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_DECODING_LENGTH_FAIL))),
                        [argon2_error_codes.ARGON2_VERIFY_MISMATCH] = Marshal.PtrToStringAnsi(new IntPtr(argon2_error_message(argon2_error_codes.ARGON2_VERIFY_MISMATCH))),
                    };
                }
            });
        }
    }
}
