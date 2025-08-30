// 2_Runtime_Discovery_Windows_Java_DotNet/Windows_ETW/CarnotEngine_ETW_Schannel_Consumer.cs
// Conceptual C# ETW consumer using Microsoft.Diagnostics.Tracing.TraceEvent
// Requires NuGet package: Microsoft.Diagnostics.Tracing.TraceEvent

using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing;
using System;
using System.Text.Json;

public class SChannelMonitor
{
    // Provider GUID for Microsoft-Windows-Schannel
    // Verify using: logman query providers "Microsoft-Windows-Schannel"
    private static readonly Guid SChannelProviderGuid = new Guid("1f678132-5938-4686-9f55-c8df9f226e64");

    public static void StartMonitoring()
    {
        // Requires Administrator privileges
        if (!TraceEventSession.IsElevated() ?? false)
        {
            Console.WriteLine("ERROR: Must run as Administrator to create ETW session.");
            return;
        }

        Console.WriteLine("Starting CarnotEngine ETW Session...");

        try
        {
            using (var session = new TraceEventSession("CarnotEngineSchannelSession"))
            {
                Console.CancelKeyPress += (sender, e) => {
                    Console.WriteLine("Stopping session...");
                    session.Stop();
                };

                // Enable the SChannel provider (Level 4 = Informational)
                session.EnableProvider(SChannelProviderGuid, TraceEventLevel.Informational);

                session.Source.Dynamic.All += (traceEvent) =>
                {
                    // Event ID 36880: TlsHandshakeCompleted (Common event for capturing results)
                    if (traceEvent.ProviderGuid == SChannelProviderGuid && (int)traceEvent.ID == 36880)
                    {
                        // Extract CryptoBOM relevant facts
                        var observation = new {
                            Source = "ETW_SChannel_CarnotEngine",
                            Timestamp = traceEvent.TimeStamp,
                            PID = traceEvent.ProcessID,
                            EventName = traceEvent.EventName,
                            // Payload fields are specific to the SChannel provider manifest
                            Protocol = traceEvent.PayloadByName("Protocol")?.ToString(),
                            CipherSuite = traceEvent.PayloadByName("CipherSuite")?.ToString(),
                            // TargetName (SNI) might be available depending on context (Client/Server)
                            TargetHost = traceEvent.PayloadByName("TargetName")?.ToString()
                        };
                        
                        // Output as JSONL (JSON Lines) for ingestion
                        Console.WriteLine(JsonSerializer.Serialize(observation));
                    }
                };

                Console.WriteLine("Monitoring SChannel ETW events... Press Ctrl+C to stop.");
                session.Source.Process(); // Blocking call that processes events
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred during ETW session: {ex.Message}");
        }
    }
}

// Entry point for testing
// public class Program { static void Main() { SChannelMonitor.StartMonitoring(); } }