// Copyright © 2015 Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves.

#pragma warning disable CA1303, CA1711

using System;
using System.Diagnostics.Tracing;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace Argonautica
{
    [CollectionDefinition("AssemblyLoader")]
    public sealed class AssemblyLoaderTracingCollection : ICollectionFixture<AssemblyLoaderTracingFixture>
    {
    }

    public sealed class AssemblyLoaderTracingFixture : IAsyncLifetime, IDisposable
    {
        private readonly IMessageSink _output;
        private AssemblyLoadEventListener? _listener;

        public AssemblyLoaderTracingFixture(IMessageSink output)
        {
            ArgumentNullException.ThrowIfNull(output);
            _output = output;
        }

        public Task InitializeAsync()
        {
            _output.OnMessage(new DiagnosticMessage("RID={0}", RuntimeInformation.RuntimeIdentifier));

            _listener = new AssemblyLoadEventListener(_output);
            return Task.CompletedTask;
        }

        public Task DisposeAsync()
        {
            _listener?.Dispose();
            _listener = null;
            return Task.CompletedTask;
        }

        public void Dispose()
        {
            _listener?.Dispose();
            _listener = null;
        }
    }

    public sealed class AssemblyLoadEventListener : EventListener
    {
        private readonly IMessageSink _output;

        public AssemblyLoadEventListener(IMessageSink output)
        {
            ArgumentNullException.ThrowIfNull(output);
            _output = output;
        }

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource is not null)
            {
                if (string.Equals(eventSource.Name, "Microsoft-Windows-DotNETRuntime", StringComparison.Ordinal))
                {
                    EnableEvents(eventSource, EventLevel.Verbose, EventKeywords.All);
                }

                base.OnEventSourceCreated(eventSource);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            const int assemblyLoadStart = 290;
            const int resolutionAttempted = 292;
            const int knownPathProbed = 296;

            if (eventData is not null)
            {
                var source = eventData.EventSource.Name;
                var id = eventData.EventId;

                if (string.Equals(source, "Microsoft-Windows-DotNETRuntime", StringComparison.Ordinal))
                {
                    var payload = eventData.Payload;

                    if (id == assemblyLoadStart)
                    {
                        _output.OnMessage(new DiagnosticMessage("[AssemblyLoadStart] Name='{0}', Path='{1}'",
                            payload![1], payload![2]));
                    }
                    else if (id == resolutionAttempted)
                    {
                        _output.OnMessage(new DiagnosticMessage("[ResolutionAttempted] Name='{0}', Result={1}, Error='{3}'",
                            payload![1] ?? "(null)", payload![4], payload![7] ?? "(null)"));

                    }
                    else if (id == knownPathProbed)
                    {
                        _output.OnMessage(new DiagnosticMessage("[KnownPathProbed] Path='{0}', Result={1}", payload![1], payload![3]));
                    }
                }
            }
        }
    }
}
