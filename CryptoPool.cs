// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Argonautica
{
    /// <summary>
    ///   ArrayPool wrapper intended for cryptographic operations.
    /// </summary>
    /// <see href="https://github.com/dotnet/runtime/blob/main/src/libraries/Common/src/System/Security/Cryptography/CryptoPool.cs"/>
    internal static class CryptoPool
    {
        internal const int ClearAll = -1;

        internal static byte[] Rent(int minimumLength) => ArrayPool<byte>.Shared.Rent(minimumLength);

        internal static void Return(ArraySegment<byte> arraySegment)
        {
            Debug.Assert(arraySegment.Array is not null);
            Debug.Assert(arraySegment.Offset == 0);

            Return(arraySegment.Array, arraySegment.Count);
        }

        internal static void Return(byte[] array, int clearSize = ClearAll)
        {
            Debug.Assert(clearSize <= array.Length);
            bool clearWholeArray = clearSize < 0;

            if (!clearWholeArray && clearSize != 0)
            {
#if (NETCOREAPP || NETSTANDARD2_1)
                CryptographicOperations.ZeroMemory(array.AsSpan(0, clearSize));
#else
                Array.Clear(array, 0, clearSize);
#endif
            }

            ArrayPool<byte>.Shared.Return(array, clearWholeArray);
        }
    }
}
