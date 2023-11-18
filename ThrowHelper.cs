// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Argonautica
{
    // * Taken from .NET's ThrowHelper.cs
    //
    // The aim of this pattern is three-fold:
    // 1. Extracting the throw makes the method preforming the throw in a conditional branch smaller and more inlinable
    // 2. Extracting the throw from generic method to non-generic method reduces the repeated codegen size for value types
    // 3a. Newer JITs will not inline the methods that only throw and also recognise them, move the call to cold section
    //     and not add stack prep and unwind before calling https://github.com/dotnet/coreclr/pull/6103
    // 3b. Older JITs will inline the throw itself and move to cold section; but not inline the non-inlinable exception
    //     factory methods - still maintaining advantages 1 & 2
    //
    [StackTraceHidden]
    internal static class ThrowHelper
    {
        [DoesNotReturn]
        internal static void ThrowArgumentNullException(string? paramName) =>
            throw CreateArgumentNullException(paramName);

        [DoesNotReturn]
        internal static void ThrowArgumentOutOfRangeException(string? paramName) =>
            throw CreateArgumentOutOfRangeException(paramName);

        [DoesNotReturn]
        internal static void ThrowCryptographicException(string? message) =>
            throw CreateCryptographicException(message);

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static ArgumentNullException CreateArgumentNullException(string? paramName) =>
            new(paramName);

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static ArgumentOutOfRangeException CreateArgumentOutOfRangeException(string? paramName) =>
            new(paramName);

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static CryptographicException CreateCryptographicException(string? message) =>
            new(message);
    }
}
