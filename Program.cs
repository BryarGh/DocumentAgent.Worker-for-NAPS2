using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

var builder = WebApplication.CreateBuilder(args);

// Allows the app to run as a Windows Service (sc create / sc start).
// On macOS/Linux this is a no-op.
builder.Host.UseWindowsService(options =>
{
    options.ServiceName = "DocumentAgent";
});

builder.Logging.ClearProviders();
var appState = new AppState();
builder.Logging.AddProvider(new FileJsonLoggerProvider(appState));
builder.Logging.AddJsonConsole();

var selectedPort = PortFinder.FindFirstAvailable(new[] { 3333, 3334, 3335 });

builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Loopback, selectedPort);
});

builder.Services.Configure<AppPathsOptions>(options =>
{
    options.BasePath = AgentEnvironmentPaths.GetAgentBasePath();
});

// Read laravel_origin from agent.config.json early (before DI builds) so CORS is
// configured from the same file each laptop already has, with fallback to the
// AGENT_ALLOWED_ORIGIN env var, then wildcard for development.
var earlyConfigPath = Path.Combine(
    AgentEnvironmentPaths.GetAgentBasePath(),
    "agent.config.json");

string? laravelOriginFromFile = null;
if (File.Exists(earlyConfigPath))
{
    try
    {
        var earlyJson = File.ReadAllText(earlyConfigPath);
        // Auto-fix unescaped backslashes (common in Windows paths written by hand)
        earlyJson = System.Text.RegularExpressions.Regex.Replace(
            earlyJson,
            @"(?<!\\)\\(?![""\\\/bfnrtu])",
            @"\\");
        using var doc = JsonDocument.Parse(earlyJson);
        if (doc.RootElement.TryGetProperty("laravel_origin", out var prop))
        {
            laravelOriginFromFile = prop.GetString();
            // Strip invisible Unicode chars that get embedded when copy-pasting URLs
            if (laravelOriginFromFile is not null)
                laravelOriginFromFile = new string(laravelOriginFromFile.Where(c =>
                    c != '\u200B' && c != '\u200C' && c != '\u200D' &&
                    c != '\u200E' && c != '\u200F' && c != '\u202A' &&
                    c != '\u202B' && c != '\u202C' && c != '\u202D' &&
                    c != '\u202E' && c != '\uFEFF').ToArray()).Trim();
        }
    }
    catch { /* ignore — AgentConfigProvider will log it properly later */ }
}

builder.Services.Configure<SecurityOptions>(options =>
{
    var raw = laravelOriginFromFile
        ?? builder.Configuration["AGENT_ALLOWED_ORIGIN"]
        ?? "*";
    // Origins never include a trailing slash; trim it so comparisons work.
    options.AllowedOrigin = raw != "*" ? raw.TrimEnd('/') : raw;
});

builder.Services.AddHttpClient();
builder.Services.AddSingleton<AppPaths>();
builder.Services.AddSingleton(appState);
builder.Services.AddSingleton<AgentConfigProvider>();
builder.Services.AddSingleton<PersistentJobStore>();
builder.Services.AddSingleton<ScanJobQueue>();
builder.Services.AddSingleton<ScanProfileStore>();
builder.Services.AddSingleton<ScannerService>();
builder.Services.AddSingleton<IUploadClient, HttpUploadClient>();
builder.Services.AddHostedService<ScanJobProcessor>();
builder.Services.AddSingleton<PersistentWhatsAppMessageStore>();
builder.Services.AddSingleton<WhatsAppMessageQueue>();
builder.Services.AddSingleton<IWhatsAppRuntimeCredentialProvider, WhatsAppRuntimeCredentialProvider>();
builder.Services.AddSingleton<IWhatsAppSender, TwilioWhatsAppSender>();
builder.Services.AddHostedService<WhatsAppMessageProcessor>();
builder.Services.AddHostedService<CleanupService>();

var app = builder.Build();

app.UseMiddleware<LoopbackAndOriginMiddleware>();

app.MapGet("/health", (AppState state) => Results.Json(new
{
    status = "ok",
    version = state.Version,
    machine_uuid = state.MachineUuid
}));

app.MapGet("/port", () => Results.Json(new { port = selectedPort }));

app.MapGet("/status", (AppState state, ScanJobQueue queue, WhatsAppMessageQueue whatsappQueue, ScannerService scannerService, AgentConfigProvider configProvider) =>
{
    var diskOk = SystemInfo.HasSufficientDiskSpace();
    var scannerOk = scannerService.HasAvailableScanner;
    var naps2Ok = configProvider.Naps2ExecutableExists;
    var degraded = !scannerOk || !naps2Ok || !diskOk || state.ConsecutiveScanFailures >= 3;

    return Results.Json(new
    {
        scanner_connected = scannerOk && naps2Ok && diskOk,
        printer_connected = state.PrinterConnected,
        last_scan_time = state.LastScanTimeUtc,
        queued_uploads_count = queue.CountQueuedUploads,
        failed_uploads_count = queue.CountFailedUploads,
        queued_whatsapp_count = whatsappQueue.CountQueued,
        failed_whatsapp_count = whatsappQueue.CountFailed,
        degraded,
        queued_jobs = queue.CountQueuedUploads,
        failed_jobs = queue.CountFailedUploads,
        last_completed_scan_time = state.LastCompletedScanTimeUtc,
        disk_free_mb = SystemInfo.GetFreeDiskSpaceMb(state.BasePathRoot),
        agent_uptime_seconds = state.UptimeSeconds,
        default_scanner_available = scannerService.HasAvailableScanner,
        naps2_path = configProvider.Config.Naps2Path
    });
});

app.MapGet("/scanners", (ScannerService scannerService) =>
{
    var profiles = scannerService.GetScanners();
    return Results.Json(new
    {
        profiles = profiles.Select(p => new { name = p.Name }),
        default_available = profiles.Any()
    });
});

app.MapGet("/profiles", (ScanProfileStore store) => Results.Json(new
{
    profiles = store.GetAll()
}));

app.MapPost("/profiles", (ProfileRequest request, ScanProfileStore store, ScannerService scannerService) =>
{
    var profileName = request.ProfileName ?? request.Name;
    if (string.IsNullOrWhiteSpace(profileName))
    {
        return Results.Json(new { error = "profile_name_required" }, statusCode: StatusCodes.Status400BadRequest);
    }

    var scannerName = request.ScannerName;
    if (string.IsNullOrWhiteSpace(scannerName))
    {
        scannerName = scannerService.GetScanners().FirstOrDefault(s => s.IsDefault)?.Name;
        if (string.IsNullOrWhiteSpace(scannerName))
        {
            return Results.Json(new { error = "scanner_required" }, statusCode: StatusCodes.Status400BadRequest);
        }
    }

    var configuredDriver = request.Driver;
    if (string.IsNullOrWhiteSpace(configuredDriver))
    {
        configuredDriver = scannerService.GetScanners()
            .FirstOrDefault(s => string.Equals(s.Name, scannerName, StringComparison.OrdinalIgnoreCase))
            ?.Driver;
    }

    var profile = new ScanProfile
    {
        ProfileName = profileName,
        ScannerName = scannerName,
        Driver = configuredDriver,
        Dpi = request.Dpi ?? 300,
        ColorMode = request.ColorMode ?? "color",
        Source = request.Source ?? "ADF",
        Duplex = request.Duplex ?? false,
        PaperSize = request.PaperSize ?? "A4"
    };

    store.Save(profile);
    return Results.Json(new { saved = true, profile });
});

app.MapPost("/register", (AppState state) =>
{
    // TODO: perform handshake with Laravel, store encrypted token per OS
    state.EnsureMachineUuid();
    return Results.Json(new { machine_uuid = state.MachineUuid });
});

app.MapPost("/scan", (ScanRequest request, ScanJobQueue queue, AppState state, ScannerService scannerService, ScanProfileStore profiles, ILoggerFactory loggerFactory) =>
{
    var logger = loggerFactory.CreateLogger("Scan");

    logger.LogInformation(
        "Scan request received document_id={DocumentId} profile_name={ProfileName} client_request_id={ClientRequestId}",
        request.DocumentId ?? "(null)",
        request.ProfileName ?? "(null)",
        request.ClientRequestId ?? "(null)");

    if (string.IsNullOrWhiteSpace(request.DocumentId) || string.IsNullOrWhiteSpace(request.ProfileName))
    {
        return Results.Json(new { error = "missing_required_fields" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (!SystemInfo.HasSufficientDiskSpace())
    {
        return Results.Json(new { error = "insufficient_disk_space" }, statusCode: StatusCodes.Status400BadRequest);
    }

    var profile = profiles.Get(request.ProfileName);
    if (profile is null)
    {
        var knownProfiles = profiles.GetAll().Select(p => p.ProfileName).ToArray();
        logger.LogWarning(
            "Scan refused: profile not found profile_name={ProfileName} known_profiles={KnownProfiles}",
            request.ProfileName,
            knownProfiles.Length == 0 ? "(none)" : string.Join(" | ", knownProfiles));
        return Results.Json(new { error = "profile_not_found" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (!scannerService.IsDeviceAvailable(profile.ScannerName))
    {
        var availableScanners = scannerService.GetScanners().Select(s => $"{s.Name} [{s.Driver}]").ToArray();
        logger.LogWarning(
            "Scan refused: device missing configured_device={Device} configured_driver={Driver} available_scanners={AvailableScanners}",
            profile.ScannerName,
            profile.Driver ?? "(not set)",
            availableScanners.Length == 0 ? "(none)" : string.Join(" | ", availableScanners));
        return Results.Json(new { error = "scanner_unavailable" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (queue.TryFindByClientRequest(request.ClientRequestId, request.DocumentId!, out var existingJob))
    {
        return Results.Accepted($"/scan/{existingJob.JobId}", new { job_id = existingJob.JobId, status = existingJob.Status.ToString().ToLowerInvariant(), deduped = true });
    }

    var job = queue.Enqueue(profile, request.DocumentId!, request.ClientRequestId);
    logger.LogInformation(
        "Scan job queued job_id={JobId} profile_name={ProfileName} scanner_name={ScannerName} driver={Driver} dpi={Dpi} source={Source} duplex={Duplex}",
        job.JobId,
        profile.ProfileName,
        profile.ScannerName,
        profile.Driver ?? "(not set)",
        profile.Dpi,
        profile.Source,
        profile.Duplex);
    return Results.Accepted($"/scan/{job.JobId}", new { job_id = job.JobId, status = job.Status.ToString().ToLowerInvariant() });
});

app.MapGet("/scan/{jobId}", (string jobId, ScanJobQueue queue) =>
{
    if (queue.TryGet(jobId, out var job))
    {
        return Results.Json(new
        {
            job_id = job.JobId,
            status = job.Status.ToString().ToLowerInvariant(),
            error_message = job.ErrorMessage,
            error_code = job.ErrorCode,
            attempt_kind = job.LastAttemptKind,
            attempt_message = job.LastAttemptMessage,
            updated_at = job.UpdatedUtc
        });
    }

    return Results.NotFound(new { error = "job_not_found" });
});

app.MapPost("/send-whatsapp", (WhatsAppRequest request, WhatsAppMessageQueue queue, ILoggerFactory loggerFactory) =>
{
    var logger = loggerFactory.CreateLogger("WhatsApp");

    if (string.IsNullOrWhiteSpace(request.PhoneNumber) || string.IsNullOrWhiteSpace(request.Content))
    {
        return Results.Json(new { error = "missing_required_fields" }, statusCode: StatusCodes.Status400BadRequest);
    }

    var message = queue.Enqueue(request);
    logger.LogInformation(
        "WhatsApp job queued message_id={MessageId} notification_id={NotificationId} event_type={EventType}",
        message.MessageId,
        message.NotificationId,
        message.EventType ?? "(unknown)");

    return Results.Accepted($"/whatsapp/{message.MessageId}", new
    {
        message_id = message.MessageId,
        status = message.Status.ToString().ToLowerInvariant(),
    });
});

app.MapGet("/whatsapp/{messageId}", (string messageId, WhatsAppMessageQueue queue) =>
{
    if (queue.TryGet(messageId, out var message))
    {
        return Results.Json(new
        {
            message_id = message.MessageId,
            notification_id = message.NotificationId,
            status = message.Status.ToString().ToLowerInvariant(),
            provider_message_sid = message.ProviderMessageSid,
            error_message = message.ErrorMessage,
            error_code = message.ErrorCode,
            updated_at = message.UpdatedUtc,
        });
    }

    return Results.NotFound(new { error = "message_not_found" });
});

app.Run();

internal record ScanRequest
{
    [JsonPropertyName("document_id")]
    public string? DocumentId { get; init; }

    [JsonPropertyName("profile_name")]
    public string? ProfileName { get; init; }

    [JsonPropertyName("client_request_id")]
    public string? ClientRequestId { get; init; }
}

internal record WhatsAppRequest
{
    [JsonPropertyName("notification_id")]
    public long? NotificationId { get; init; }

    [JsonPropertyName("event_type")]
    public string? EventType { get; init; }

    [JsonPropertyName("phone_number")]
    public string? PhoneNumber { get; init; }

    [JsonPropertyName("content")]
    public string? Content { get; init; }

    [JsonPropertyName("callback_url")]
    public string? CallbackUrl { get; init; }
}

internal enum WhatsAppMessageStatus
{
    Queued,
    Sending,
    Delivered,
    Failed
}

internal sealed class WhatsAppMessage
{
    public string MessageId { get; set; } = string.Empty;
    public long? NotificationId { get; set; }
    public string? EventType { get; set; }
    public string PhoneNumber { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public string? CallbackUrl { get; set; }
    public WhatsAppMessageStatus Status { get; set; } = WhatsAppMessageStatus.Queued;
    public string? ProviderMessageSid { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
    public int Attempts { get; set; }
}

internal sealed class ProfileRequest
{
    [JsonPropertyName("profile_name")]
    public string? ProfileName { get; init; }

    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("scanner_name")]
    public string? ScannerName { get; init; }

    [JsonPropertyName("driver")]
    public string? Driver { get; init; }

    [JsonPropertyName("dpi")]
    public int? Dpi { get; init; }

    [JsonPropertyName("color_mode")]
    public string? ColorMode { get; init; }

    [JsonPropertyName("source")]
    public string? Source { get; init; }

    [JsonPropertyName("duplex")]
    public bool? Duplex { get; init; }

    [JsonPropertyName("paper_size")]
    public string? PaperSize { get; init; }
}

internal enum ScanJobStatus
{
    Queued,
    Acquiring,
    Processing,
    Uploading,
    Completed,
    Failed
}

internal sealed class ScanJob
{
    public string JobId { get; set; } = string.Empty;
    public string DocumentId { get; set; } = string.Empty;
    public ScanProfile Profile { get; set; } = new();
    public ScanJobStatus Status { get; set; } = ScanJobStatus.Queued;
    public string? ErrorMessage { get; set; }
    public string? ErrorCode { get; set; }
    public DateTime CreatedUtc { get; init; } = DateTime.UtcNow;
    public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
    public int Attempts { get; set; }
    public List<string> LocalFilePaths { get; set; } = new();
    public string? ClientRequestId { get; set; }
    public string? LastAttemptKind { get; set; }
    public string? LastAttemptMessage { get; set; }
}

internal sealed class ScanJobQueue
{
    private readonly ConcurrentDictionary<string, ScanJob> _jobs = new();
    private readonly Channel<ScanJob> _channel = Channel.CreateUnbounded<ScanJob>();
    private readonly PersistentJobStore _store;
    private readonly ConcurrentDictionary<string, ScanJob> _jobsByClientRequest = new();

    public ScanJobQueue(PersistentJobStore store)
    {
        _store = store;

        foreach (var job in _store.LoadPending())
        {
            _jobs.TryAdd(job.JobId, job);
            if (!string.IsNullOrWhiteSpace(job.ClientRequestId))
            {
                _jobsByClientRequest.TryAdd(job.ClientRequestId, job);
            }
            _channel.Writer.TryWrite(job);
        }
    }

    public ScanJob Enqueue(ScanProfile profile, string documentId, string? clientRequestId)
    {
        var job = new ScanJob
        {
            JobId = Guid.NewGuid().ToString("N"),
            DocumentId = documentId,
            Profile = profile,
            ClientRequestId = clientRequestId
        };
        _jobs.TryAdd(job.JobId, job);
        if (!string.IsNullOrWhiteSpace(clientRequestId))
        {
            _jobsByClientRequest.TryAdd(clientRequestId, job);
        }
        _store.Save(job);
        _channel.Writer.TryWrite(job);
        return job;
    }

    public bool TryGet(string jobId, out ScanJob job) => _jobs.TryGetValue(jobId, out job!);

    public bool TryFindByClientRequest(string? clientRequestId, string documentId, out ScanJob job)
    {
        job = null!;
        if (string.IsNullOrWhiteSpace(clientRequestId))
        {
            return false;
        }

        if (_jobsByClientRequest.TryGetValue(clientRequestId, out var existing))
        {
            if (existing.DocumentId == documentId && (DateTime.UtcNow - existing.CreatedUtc) <= TimeSpan.FromMinutes(5))
            {
                job = existing;
                return true;
            }
        }
        return false;
    }

    public IAsyncEnumerable<ScanJob> ReadAllAsync(CancellationToken token) => _channel.Reader.ReadAllAsync(token);

    public int CountQueuedUploads => _jobs.Values.Count(j => j.Status is ScanJobStatus.Uploading or ScanJobStatus.Queued or ScanJobStatus.Acquiring or ScanJobStatus.Processing);
    public int CountFailedUploads => _jobs.Values.Count(j => j.Status == ScanJobStatus.Failed);

    public void Update(ScanJob job)
    {
        job.UpdatedUtc = DateTime.UtcNow;
        _store.Save(job);
    }
}

internal sealed class WhatsAppMessageQueue
{
    private readonly ConcurrentDictionary<string, WhatsAppMessage> _messages = new();
    private readonly Channel<WhatsAppMessage> _channel = Channel.CreateUnbounded<WhatsAppMessage>();
    private readonly PersistentWhatsAppMessageStore _store;

    public WhatsAppMessageQueue(PersistentWhatsAppMessageStore store)
    {
        _store = store;

        foreach (var message in _store.LoadPending())
        {
            _messages.TryAdd(message.MessageId, message);
            _channel.Writer.TryWrite(message);
        }
    }

    public int CountQueued => _messages.Values.Count(m => m.Status is WhatsAppMessageStatus.Queued or WhatsAppMessageStatus.Sending);

    public int CountFailed => _messages.Values.Count(m => m.Status == WhatsAppMessageStatus.Failed);

    public WhatsAppMessage Enqueue(WhatsAppRequest request)
    {
        var message = new WhatsAppMessage
        {
            MessageId = Guid.NewGuid().ToString("N"),
            NotificationId = request.NotificationId,
            EventType = request.EventType,
            PhoneNumber = request.PhoneNumber!.Trim(),
            Content = request.Content!.Trim(),
            CallbackUrl = string.IsNullOrWhiteSpace(request.CallbackUrl) ? null : request.CallbackUrl.Trim(),
            Status = WhatsAppMessageStatus.Queued,
        };

        _messages.TryAdd(message.MessageId, message);
        _store.Save(message);
        _channel.Writer.TryWrite(message);
        return message;
    }

    public IAsyncEnumerable<WhatsAppMessage> ReadAllAsync(CancellationToken token) => _channel.Reader.ReadAllAsync(token);

    public bool TryGet(string messageId, out WhatsAppMessage message) => _messages.TryGetValue(messageId, out message!);

    public void Update(WhatsAppMessage message)
    {
        message.UpdatedUtc = DateTime.UtcNow;
        _store.Save(message);
    }
}

internal interface IWhatsAppSender
{
    Task<string> SendAsync(WhatsAppMessage message, CancellationToken cancellationToken);
}

internal sealed class TwilioWhatsAppSender : IWhatsAppSender
{
    private readonly AgentConfigProvider _config;
    private readonly IWhatsAppRuntimeCredentialProvider _credentialProvider;

    public TwilioWhatsAppSender(AgentConfigProvider config, IWhatsAppRuntimeCredentialProvider credentialProvider)
    {
        _config = config;
        _credentialProvider = credentialProvider;
    }

    public async Task<string> SendAsync(WhatsAppMessage message, CancellationToken cancellationToken)
    {
        if (!_config.Config.WhatsAppEnabled)
        {
            throw new InvalidOperationException("whatsapp_disabled");
        }

        var runtimeCredentials = await _credentialProvider.GetAsync(cancellationToken);
        if (runtimeCredentials is null || !runtimeCredentials.Enabled)
        {
            throw new InvalidOperationException("whatsapp_disabled");
        }

        if (string.IsNullOrWhiteSpace(runtimeCredentials.TwilioAccountSid)
            || string.IsNullOrWhiteSpace(runtimeCredentials.TwilioAuthToken)
            || string.IsNullOrWhiteSpace(runtimeCredentials.TwilioWhatsAppFrom))
        {
            throw new InvalidOperationException("twilio_not_configured");
        }

        var to = NormalizeWhatsAppAddress(message.PhoneNumber);
        var from = NormalizeWhatsAppAddress(runtimeCredentials.TwilioWhatsAppFrom);

        TwilioClient.Init(runtimeCredentials.TwilioAccountSid, runtimeCredentials.TwilioAuthToken);

        var created = await MessageResource.CreateAsync(
            to: new PhoneNumber(to),
            from: new PhoneNumber(from),
            body: message.Content);

        return created.Sid;
    }

    private static string NormalizeWhatsAppAddress(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith("whatsapp:", StringComparison.OrdinalIgnoreCase))
        {
            return "whatsapp:" + trimmed[9..].Trim();
        }

        return "whatsapp:" + trimmed;
    }
}

internal sealed class WhatsAppMessageProcessor : BackgroundService
{
    private readonly WhatsAppMessageQueue _queue;
    private readonly IWhatsAppSender _sender;
    private readonly AgentConfigProvider _config;
    private readonly IHttpClientFactory _factory;
    private readonly ILogger<WhatsAppMessageProcessor> _logger;

    public WhatsAppMessageProcessor(WhatsAppMessageQueue queue, IWhatsAppSender sender, AgentConfigProvider config, IHttpClientFactory factory, ILogger<WhatsAppMessageProcessor> logger)
    {
        _queue = queue;
        _sender = sender;
        _config = config;
        _factory = factory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var message in _queue.ReadAllAsync(stoppingToken))
        {
            var maxAttempts = Math.Max(1, _config.Config.WhatsAppMaxRetries);
            while (!stoppingToken.IsCancellationRequested && message.Attempts < maxAttempts)
            {
                try
                {
                    message.Status = WhatsAppMessageStatus.Sending;
                    message.Attempts += 1;
                    _queue.Update(message);

                    await SendCallbackAsync(message, "sending", null, null, stoppingToken);

                    var sid = await _sender.SendAsync(message, stoppingToken);
                    message.ProviderMessageSid = sid;
                    message.Status = WhatsAppMessageStatus.Delivered;
                    message.ErrorCode = null;
                    message.ErrorMessage = null;
                    _queue.Update(message);

                    await SendCallbackAsync(message, "delivered", null, null, stoppingToken);
                    _logger.LogInformation("WhatsApp message delivered message_id={MessageId} sid={Sid}", message.MessageId, sid);
                    break;
                }
                catch (Exception ex) when (message.Attempts < maxAttempts)
                {
                    message.ErrorCode = "send_failed_retryable";
                    message.ErrorMessage = ex.Message;
                    _queue.Update(message);

                    _logger.LogWarning(ex, "WhatsApp send failed message_id={MessageId} attempt={Attempt}", message.MessageId, message.Attempts);
                    var delaySeconds = Math.Min(Math.Pow(2, message.Attempts), 30);
                    await Task.Delay(TimeSpan.FromSeconds(delaySeconds), stoppingToken);
                }
                catch (Exception ex)
                {
                    message.Status = WhatsAppMessageStatus.Failed;
                    message.ErrorCode = "send_failed";
                    message.ErrorMessage = ex.Message;
                    _queue.Update(message);

                    await SendCallbackAsync(message, "failed", "send_failed", ex.Message, stoppingToken);
                    _logger.LogError(ex, "WhatsApp message failed permanently message_id={MessageId}", message.MessageId);
                    break;
                }
            }
        }
    }

    private async Task SendCallbackAsync(WhatsAppMessage message, string status, string? errorCode, string? errorMessage, CancellationToken cancellationToken)
    {
        var callbackUrl = message.CallbackUrl;
        if (string.IsNullOrWhiteSpace(callbackUrl) || message.NotificationId is null)
        {
            return;
        }

        try
        {
            var payload = new Dictionary<string, object?>
            {
                ["notification_id"] = message.NotificationId,
                ["status"] = status,
                ["machine_uuid"] = Environment.MachineName,
                ["provider_message_sid"] = message.ProviderMessageSid,
                ["error_code"] = errorCode,
                ["error_message"] = errorMessage,
                ["response_payload"] = new Dictionary<string, object?>
                {
                    ["message_id"] = message.MessageId,
                    ["attempts"] = message.Attempts,
                    ["event_type"] = message.EventType,
                },
            };

            var client = _factory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(Math.Max(5, _config.Config.WhatsAppTimeoutSeconds));

            using var request = new HttpRequestMessage(HttpMethod.Post, callbackUrl)
            {
                Content = JsonContent.Create(payload)
            };

            if (!string.IsNullOrWhiteSpace(_config.Config.AgentToken))
            {
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _config.Config.AgentToken);
            }

            using var response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("WhatsApp callback returned status {Status} for message {MessageId}", (int) response.StatusCode, message.MessageId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "WhatsApp callback failed message_id={MessageId}", message.MessageId);
        }
    }
}

internal sealed class ScanJobProcessor : BackgroundService
{
    private readonly ScanJobQueue _queue;
    private readonly AppPaths _paths;
    private readonly ScannerService _scannerService;
    private readonly ILogger<ScanJobProcessor> _logger;
    private readonly AppState _state;
    private readonly IUploadClient _uploader;
    private readonly AgentConfigProvider _config;
    private readonly TimeSpan _acquireTimeout = TimeSpan.FromMinutes(10);

    public ScanJobProcessor(ScanJobQueue queue, AppPaths paths, ScannerService scannerService, AppState state, AgentConfigProvider config, IUploadClient uploader, ILogger<ScanJobProcessor> logger)
    {
        _queue = queue;
        _paths = paths;
        _scannerService = scannerService;
        _logger = logger;
        _state = state;
        _config = config;
        _uploader = uploader;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var job in _queue.ReadAllAsync(stoppingToken))
        {
            try
            {
                job.Status = ScanJobStatus.Acquiring;
                job.Attempts += 1;
                job.LastAttemptKind = "acquiring";
                job.LastAttemptMessage = "Starting acquisition";
                _queue.Update(job);
                _logger.LogInformation("Acquiring scan job {JobId}", job.JobId);

                var jobFolder = Path.Combine(_paths.Scanned, job.JobId);
                Directory.CreateDirectory(jobFolder);

                var outputPdf = Path.Combine(jobFolder, job.JobId + ".pdf");
                if (File.Exists(outputPdf) && new FileInfo(outputPdf).Length > 0)
                {
                    job.LocalFilePaths = new List<string> { outputPdf };
                }
                else
                {
                    await AcquireWithNaps2Async(job, outputPdf, stoppingToken);
                }

                _queue.Update(job);

                // Stage 2: Process (placeholder passthrough)
                job.Status = ScanJobStatus.Processing;
                _queue.Update(job);
                // No processing required yet for PDF passthrough

                // Stage 3: Upload (placeholder)
                job.Status = ScanJobStatus.Uploading;
                _queue.Update(job);
                await _uploader.UploadAsync(job, stoppingToken);

                job.Status = ScanJobStatus.Completed;
                _queue.Update(job);
                _state.LastScanTimeUtc = DateTime.UtcNow;
                _state.LastCompletedScanTimeUtc = _state.LastScanTimeUtc;
                _state.ConsecutiveScanFailures = 0;
                _logger.LogInformation("Scan job {JobId} completed", job.JobId);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                job.Status = ScanJobStatus.Failed;
                if (string.IsNullOrWhiteSpace(job.ErrorMessage) ||
                    string.Equals(job.ErrorMessage, "scan_failed", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(job.ErrorMessage, "scan_timeout", StringComparison.OrdinalIgnoreCase))
                {
                    job.ErrorMessage = ex.Message;
                }
                job.ErrorCode = ex is TimeoutException
                    ? "scan_timeout"
                    : ex.Message.StartsWith("upload_", StringComparison.OrdinalIgnoreCase)
                        ? "upload_failed"
                        : job.ErrorCode ?? "scan_failed";
                if (string.IsNullOrWhiteSpace(job.LastAttemptKind))
                {
                    job.LastAttemptKind = "failed";
                }
                _queue.Update(job);
                _state.ConsecutiveScanFailures += 1;
                _logger.LogError(ex, "Scan job {JobId} failed", job.JobId);
            }
        }
    }

    private async Task AcquireWithNaps2Async(ScanJob job, string outputPdf, CancellationToken stoppingToken)
    {
        if (!_config.Naps2ExecutableExists)
        {
            _logger.LogError(
                "NAPS2 not configured or missing path={Path}",
                _config.Config.Naps2Path ?? "(not configured)");
            throw new InvalidOperationException("naps2_not_configured");
        }

        var acquireStartedAt = DateTime.UtcNow;
        var acquireDeadline = acquireStartedAt + _acquireTimeout;

        var profileAttempt = BuildScanByProfileStartInfo(job, outputPdf);
        var profileResult = await RunNaps2ScanAsync(job, profileAttempt, stoppingToken, "profile", acquireDeadline);
        if (profileResult.IsSuccess)
        {
            job.LocalFilePaths = new List<string> { outputPdf };
            job.LastAttemptKind = "profile";
            job.LastAttemptMessage = "Acquisition succeeded using profile";
            return;
        }

        var shouldFallbackToDevice = OperatingSystem.IsWindows()
            && !string.IsNullOrWhiteSpace(job.Profile.ScannerName)
            && ShouldAttemptDeviceFallback(profileResult.Stdout, profileResult.Stderr);

        if (shouldFallbackToDevice)
        {
            if (IsImmediateDeviceFailure(profileResult.Stdout, profileResult.Stderr))
            {
                _logger.LogWarning(
                    "Skipping fallback driver retries due to immediate device failure markers job_id={JobId} stdout={Stdout} stderr={Stderr}",
                    job.JobId,
                    DiagnosticLogHelper.TruncateForLog(profileResult.Stdout),
                    DiagnosticLogHelper.TruncateForLog(profileResult.Stderr));
            }

            _logger.LogWarning(
                "Profile-based scan failed with unavailable/ambiguous profile. Retrying by scanner device name job_id={JobId} scanner_name={ScannerName}",
                job.JobId,
                job.Profile.ScannerName);

            var attemptedDrivers = new List<string>();
            foreach (var driver in GetDeviceFallbackDriverCandidates(job))
            {
                if (DateTime.UtcNow >= acquireDeadline)
                {
                    _logger.LogWarning("Stopping fallback retries due to acquire timeout budget exhaustion job_id={JobId}", job.JobId);
                    throw new TimeoutException("scan_timeout");
                }

                var deviceName = ResolveDeviceNameForDriver(job, driver);
                if (string.IsNullOrWhiteSpace(deviceName))
                {
                    _logger.LogWarning(
                        "Skipping fallback driver due to no known device mapping job_id={JobId} scanner_name={ScannerName} driver={Driver}",
                        job.JobId,
                        job.Profile.ScannerName,
                        driver);
                    continue;
                }

                attemptedDrivers.Add(driver);
                var deviceAttempt = BuildScanByDeviceStartInfo(job, outputPdf, driver, deviceName);
                var deviceResult = await RunNaps2ScanAsync(job, deviceAttempt, stoppingToken, $"device/{driver}", acquireDeadline, TimeSpan.FromSeconds(25));
                if (deviceResult.IsSuccess)
                {
                    job.Profile.Driver = driver;
                    job.LocalFilePaths = new List<string> { outputPdf };
                    job.LastAttemptKind = $"device/{driver}";
                    job.LastAttemptMessage = $"Acquisition succeeded using driver {driver}";
                    _logger.LogInformation(
                        "Device fallback scan succeeded job_id={JobId} scanner_name={ScannerName} driver={Driver}",
                        job.JobId,
                        job.Profile.ScannerName,
                        driver);
                    return;
                }

                if (IsImmediateDeviceFailure(deviceResult.Stdout, deviceResult.Stderr))
                {
                    _logger.LogWarning(
                        "Stopping remaining fallback retries due to immediate device failure markers job_id={JobId} attempt_driver={Driver} stdout={Stdout} stderr={Stderr}",
                        job.JobId,
                        driver,
                        DiagnosticLogHelper.TruncateForLog(deviceResult.Stdout),
                        DiagnosticLogHelper.TruncateForLog(deviceResult.Stderr));
                    break;
                }
            }

            _logger.LogError(
                "All device fallback attempts failed job_id={JobId} scanner_name={ScannerName} attempted_drivers={Drivers}",
                job.JobId,
                job.Profile.ScannerName,
                string.Join(",", attemptedDrivers));

            var reason = DiagnosticLogHelper.ExtractPrimaryFailureReason(profileResult.Stdout, profileResult.Stderr);
            job.LastAttemptKind = "device-fallback";
            job.LastAttemptMessage = $"All fallback attempts failed ({string.Join(",", attemptedDrivers)})";
            job.ErrorMessage = string.IsNullOrWhiteSpace(reason)
                ? "scan_failed: device fallback attempts failed"
                : $"scan_failed: {reason}";
        }

        job.ErrorCode = "scan_failed";
        if (string.IsNullOrWhiteSpace(job.ErrorMessage))
        {
            var profileReason = DiagnosticLogHelper.ExtractPrimaryFailureReason(profileResult.Stdout, profileResult.Stderr);
            job.ErrorMessage = string.IsNullOrWhiteSpace(profileReason)
                ? "scan_failed"
                : $"scan_failed: {profileReason}";
        }
        throw new InvalidOperationException("scan_failed");
    }

    private IEnumerable<string> GetDeviceFallbackDriverCandidates(ScanJob job)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(job.Profile.Driver) && seen.Add(job.Profile.Driver))
        {
            yield return job.Profile.Driver;
        }

        var knownDrivers = _scannerService.GetScanners()
            .Where(s => string.Equals(s.Name, job.Profile.ScannerName, StringComparison.OrdinalIgnoreCase))
            .Select(s => s.Driver)
            .Where(d => !string.IsNullOrWhiteSpace(d));

        foreach (var driver in knownDrivers)
        {
            if (seen.Add(driver!))
            {
                yield return driver!;
            }
        }

        foreach (var fallback in DiagnosticLogHelper.GetWindowsDriverCandidates(job.Profile.Driver))
        {
            if (seen.Add(fallback))
            {
                yield return fallback;
            }
        }
    }

    private static bool IsImmediateDeviceFailure(string stdout, string stderr)
    {
        var text = (stdout + "\n" + stderr).ToLowerInvariant();
        return text.Contains("paper jam")
            || text.Contains("cover open");
    }

    private static bool ShouldAttemptDeviceFallback(string stdout, string stderr)
    {
        var text = (stdout + "\n" + stderr).ToLowerInvariant();
        // Trigger fallback on various profile/scanner failure patterns
        return text.Contains("unavailable or ambiguous")
            || text.Contains("could not be found")
            || text.Contains("not found")
            || text.Contains("no scanner")
            || text.Contains("no device")
            || text.Contains("device not found")
            || text.Contains("scanner not found")
            || text.Contains("no scanned pages")
            || text.Contains("seqerror")
            || text.Contains("sequence error");
    }

    private string ResolveDeviceNameForDriver(ScanJob job, string driver)
    {
        var scanners = _scannerService.GetScanners();
        var profileName = job.Profile.ScannerName ?? string.Empty;

        // 1. Exact match: profile scanner name + driver
        var exact = scanners.FirstOrDefault(s =>
            string.Equals(s.Driver, driver, StringComparison.OrdinalIgnoreCase)
            && string.Equals(s.Name, profileName, StringComparison.OrdinalIgnoreCase));
        if (exact is not null)
        {
            return exact.Name;
        }

        // 2. Any scanner discovered for this driver
        var firstForDriver = scanners.FirstOrDefault(s =>
            string.Equals(s.Driver, driver, StringComparison.OrdinalIgnoreCase));
        if (firstForDriver is not null)
        {
            _logger.LogWarning(
                "Using discovered device for driver job_id={JobId} requested_scanner={RequestedScanner} resolved_scanner={ResolvedScanner} driver={Driver}",
                job.JobId,
                profileName,
                firstForDriver.Name,
                driver);
            return firstForDriver.Name;
        }

        // 3. Fallback: strip driver suffixes from profile name and use directly
        // e.g. "HP ScanJet Pro 2500 f1 TWAIN" -> "HP ScanJet Pro 2500 f1"
        var baseName = StripDriverSuffix(profileName);
        _logger.LogWarning(
            "No discovered device for driver, using stripped profile name job_id={JobId} profile_scanner={ProfileScanner} base_name={BaseName} driver={Driver}",
            job.JobId,
            profileName,
            baseName,
            driver);
        return baseName;
    }

    private static string StripDriverSuffix(string scannerName)
    {
        if (string.IsNullOrWhiteSpace(scannerName))
            return scannerName;

        // Remove common driver suffixes that TWAIN/WIA/ESCL append
        var suffixes = new[] { " TWAIN", " WIA", " ESCL", " (TWAIN)", " (WIA)", " (ESCL)" };
        var result = scannerName.Trim();
        foreach (var suffix in suffixes)
        {
            if (result.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                result = result[..^suffix.Length].Trim();
            }
        }
        return result;
    }

    private ProcessStartInfo BuildScanByProfileStartInfo(ScanJob job, string outputPdf)
    {
        var psi = CreateBaseNaps2StartInfo(outputPdf);
        psi.ArgumentList.Add("--profile");
        psi.ArgumentList.Add(job.Profile.ProfileName);
        psi.ArgumentList.Add("--output");
        psi.ArgumentList.Add(outputPdf);
        return psi;
    }

    private ProcessStartInfo BuildScanByDeviceStartInfo(ScanJob job, string outputPdf, string driver, string deviceName)
    {
        var psi = CreateBaseNaps2StartInfo(outputPdf);
        psi.ArgumentList.Add("--driver");
        psi.ArgumentList.Add(driver);
        psi.ArgumentList.Add("--device");
        psi.ArgumentList.Add(deviceName);
        psi.ArgumentList.Add("--output");
        psi.ArgumentList.Add(outputPdf);
        return psi;
    }

    private ProcessStartInfo CreateBaseNaps2StartInfo(string outputPdf)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _config.Config.Naps2Path!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(outputPdf) ?? _paths.Scanned
        };

        // On macOS/Linux NAPS2 uses a 'console' subcommand.
        // On Windows the dedicated naps2.console.exe is used directly — no subcommand needed.
        if (!OperatingSystem.IsWindows())
        {
            psi.ArgumentList.Add("console");
        }

        return psi;
    }

    private async Task<ScanAttemptResult> RunNaps2ScanAsync(ScanJob job, ProcessStartInfo psi, CancellationToken stoppingToken, string attemptKind, DateTime acquireDeadlineUtc, TimeSpan? perAttemptTimeout = null)
    {
        job.LastAttemptKind = attemptKind;
        job.LastAttemptMessage = $"Running {attemptKind}";
        _queue.Update(job);

        _logger.LogInformation(
            "Launching NAPS2 scan job_id={JobId} attempt_kind={AttemptKind} naps2_path={Naps2Path} working_dir={WorkingDir} args={Args} profile_name={ProfileName} scanner_name={ScannerName} configured_driver={Driver}",
            job.JobId,
            attemptKind,
            psi.FileName,
            psi.WorkingDirectory,
            DiagnosticLogHelper.FormatArguments(psi.ArgumentList),
            job.Profile.ProfileName,
            job.Profile.ScannerName,
            job.Profile.Driver ?? "(not set)");

        using var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);

        var remaining = acquireDeadlineUtc - DateTime.UtcNow;
        if (remaining <= TimeSpan.Zero)
        {
            throw new TimeoutException("scan_timeout");
        }

        var thisAttemptTimeout = perAttemptTimeout is null
            ? remaining
            : (remaining < perAttemptTimeout.Value ? remaining : perAttemptTimeout.Value);

        cts.CancelAfter(thisAttemptTimeout);

        try
        {
            proc.Start();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "Failed to start NAPS2 process job_id={JobId} attempt_kind={AttemptKind} naps2_path={Naps2Path} args={Args}",
                job.JobId,
                attemptKind,
                psi.FileName,
                DiagnosticLogHelper.FormatArguments(psi.ArgumentList));
            throw;
        }

        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();

        try
        {
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try
            {
                proc.Kill(entireProcessTree: true);
            }
            catch
            {
                // ignore kill errors
            }
            throw new TimeoutException("scan_timeout");
        }

        sw.Stop();
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var exitCode = proc.ExitCode;
        var outputPath = psi.ArgumentList.LastOrDefault() ?? string.Empty;
        var outputExists = !string.IsNullOrWhiteSpace(outputPath) && File.Exists(outputPath);
        var outputBytes = outputExists ? new FileInfo(outputPath).Length : 0L;
        var success = exitCode == 0 && outputExists && outputBytes > 0;

        _logger.LogInformation(
            "NAPS2 finished job_id={JobId} attempt_kind={AttemptKind} exit={Exit} duration_ms={Duration} output_exists={OutputExists} output_bytes={OutputBytes} stdout={Stdout} stderr={Stderr}",
            job.JobId,
            attemptKind,
            exitCode,
            sw.ElapsedMilliseconds,
            outputExists,
            outputBytes,
            DiagnosticLogHelper.TruncateForLog(stdout),
            DiagnosticLogHelper.TruncateForLog(stderr));

        if (!success)
        {
            var reason = DiagnosticLogHelper.ExtractPrimaryFailureReason(stdout, stderr);
            job.LastAttemptMessage = string.IsNullOrWhiteSpace(reason)
                ? $"{attemptKind} failed (exit {exitCode})"
                : $"{attemptKind} failed: {reason}";
            _queue.Update(job);

            _logger.LogWarning(
                "NAPS2 attempt failed job_id={JobId} attempt_kind={AttemptKind} exit={Exit} output_exists={OutputExists} output_bytes={OutputBytes} args={Args}",
                job.JobId,
                attemptKind,
                exitCode,
                outputExists,
                outputBytes,
                DiagnosticLogHelper.FormatArguments(psi.ArgumentList));
        }
        else
        {
            job.LastAttemptMessage = $"{attemptKind} completed";
            _queue.Update(job);
        }

        return new ScanAttemptResult(success, stdout, stderr);
    }

    private readonly record struct ScanAttemptResult(bool IsSuccess, string Stdout, string Stderr);
}

internal static class DiagnosticLogHelper
{
    public static string FormatArguments(IEnumerable<string> args)
    {
        return string.Join(" ", args.Select(QuoteArgument));
    }

    public static string TruncateForLog(string? value, int max = 2000)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "(empty)";
        }

        var cleaned = value.Trim();
        if (cleaned.Length <= max)
        {
            return cleaned;
        }

        return cleaned[..max] + "... (truncated)";
    }

    public static IEnumerable<string> GetWindowsDriverCandidates(string? preferredDriver)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(preferredDriver) && seen.Add(preferredDriver))
        {
            yield return preferredDriver;
        }

        foreach (var driver in new[] { "twain", "wia", "escl" })
        {
            if (seen.Add(driver))
            {
                yield return driver;
            }
        }
    }

    public static string ExtractPrimaryFailureReason(string? stdout, string? stderr)
    {
        var combined = string.Join("\n", new[] { stdout, stderr }.Where(v => !string.IsNullOrWhiteSpace(v))).Trim();
        if (string.IsNullOrWhiteSpace(combined))
        {
            return string.Empty;
        }

        var firstLine = combined
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault()?.Trim();

        return firstLine ?? string.Empty;
    }

    private static string QuoteArgument(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "\"\"";
        }

        if (value.Any(char.IsWhiteSpace) || value.Contains('"'))
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        return value;
    }
}

internal sealed class AppPaths
{
    public AppPaths(IOptions<AppPathsOptions> options)
    {
        BasePath = options.Value.BasePath ?? throw new InvalidOperationException("Base path not set");
        Logs = Ensure(Path.Combine(BasePath, "logs"));
        Queue = Ensure(Path.Combine(BasePath, "queue"));
        Tmp = Ensure(Path.Combine(BasePath, "tmp"));
        Scanned = Ensure(Path.Combine(BasePath, "scanned"));
        Cache = Ensure(Path.Combine(BasePath, "cache"));
        Failed = Ensure(Path.Combine(BasePath, "failed"));
    }

    public string BasePath { get; }
    public string Logs { get; }
    public string Queue { get; }
    public string Tmp { get; }
    public string Scanned { get; }
    public string Cache { get; }
    public string Failed { get; }

    private static string Ensure(string path)
    {
        Directory.CreateDirectory(path);
        return path;
    }
}

internal sealed class AppPathsOptions
{
    public string? BasePath { get; set; }
}

internal sealed class AgentConfig
{
    [JsonPropertyName("naps2_path")]
    public string? Naps2Path { get; set; }

    [JsonPropertyName("upload_url")]
    public string? UploadUrl { get; set; }

    [JsonPropertyName("agent_token")]
    public string? AgentToken { get; set; }

    [JsonPropertyName("laravel_origin")]
    public string? LaravelOrigin { get; set; }

    [JsonPropertyName("whatsapp_enabled")]
    public bool WhatsAppEnabled { get; set; } = false;

    [JsonPropertyName("whatsapp_credentials_source")]
    public string? WhatsAppCredentialsSource { get; set; } = "local";

    [JsonPropertyName("whatsapp_credentials_url")]
    public string? WhatsAppCredentialsUrl { get; set; }

    [JsonPropertyName("whatsapp_credentials_ttl_seconds")]
    public int WhatsAppCredentialsTtlSeconds { get; set; } = 900;

    [JsonPropertyName("twilio_account_sid")]
    public string? TwilioAccountSid { get; set; }

    [JsonPropertyName("twilio_auth_token")]
    public string? TwilioAuthToken { get; set; }

    [JsonPropertyName("twilio_whatsapp_from")]
    public string? TwilioWhatsAppFrom { get; set; }

    [JsonPropertyName("whatsapp_max_retries")]
    public int WhatsAppMaxRetries { get; set; } = 5;

    [JsonPropertyName("whatsapp_timeout_seconds")]
    public int WhatsAppTimeoutSeconds { get; set; } = 30;
}

internal sealed class RuntimeWhatsAppCredentials
{
    public bool Enabled { get; init; }

    public string? TwilioAccountSid { get; init; }

    public string? TwilioAuthToken { get; init; }

    public string? TwilioWhatsAppFrom { get; init; }

    public int Version { get; init; }
}

internal sealed class WhatsAppCredentialApiResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("version")]
    public int Version { get; set; }

    [JsonPropertyName("ttl_seconds")]
    public int TtlSeconds { get; set; }

    [JsonPropertyName("credentials")]
    public WhatsAppCredentialApiPayload? Credentials { get; set; }
}

internal sealed class WhatsAppCredentialApiPayload
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("twilio_account_sid")]
    public string? TwilioAccountSid { get; set; }

    [JsonPropertyName("twilio_auth_token")]
    public string? TwilioAuthToken { get; set; }

    [JsonPropertyName("twilio_whatsapp_from")]
    public string? TwilioWhatsAppFrom { get; set; }
}

internal interface IWhatsAppRuntimeCredentialProvider
{
    Task<RuntimeWhatsAppCredentials?> GetAsync(CancellationToken cancellationToken);
}

internal sealed class WhatsAppRuntimeCredentialProvider : IWhatsAppRuntimeCredentialProvider
{
    private readonly AgentConfigProvider _configProvider;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<WhatsAppRuntimeCredentialProvider> _logger;
    private readonly object _sync = new();

    private RuntimeWhatsAppCredentials? _cached;
    private DateTime _expiresUtc = DateTime.MinValue;

    public WhatsAppRuntimeCredentialProvider(
        AgentConfigProvider configProvider,
        IHttpClientFactory httpClientFactory,
        ILogger<WhatsAppRuntimeCredentialProvider> logger)
    {
        _configProvider = configProvider;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<RuntimeWhatsAppCredentials?> GetAsync(CancellationToken cancellationToken)
    {
        var cfg = _configProvider.Config;
        var source = (cfg.WhatsAppCredentialsSource ?? "local").Trim().ToLowerInvariant();

        if (source == "local")
        {
            return LocalCredentials(cfg);
        }

        if (source is "igms" or "igms_with_fallback")
        {
            if (TryGetCached(out var cached))
            {
                return cached;
            }

            var fetched = await TryFetchFromIgmsAsync(cfg, cancellationToken);
            if (fetched is not null)
            {
                return fetched;
            }

            if (source == "igms_with_fallback")
            {
                _logger.LogWarning("Using local WhatsApp credentials fallback because IGMS fetch failed.");
                return LocalCredentials(cfg);
            }

            return null;
        }

        return LocalCredentials(cfg);
    }

    private bool TryGetCached(out RuntimeWhatsAppCredentials? credentials)
    {
        lock (_sync)
        {
            if (_cached is not null && DateTime.UtcNow < _expiresUtc)
            {
                credentials = _cached;
                return true;
            }
        }

        credentials = null;
        return false;
    }

    private async Task<RuntimeWhatsAppCredentials?> TryFetchFromIgmsAsync(AgentConfig cfg, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(cfg.WhatsAppCredentialsUrl))
        {
            _logger.LogWarning("whatsapp_credentials_url is missing while source is configured for IGMS.");
            return null;
        }

        try
        {
            var separator = cfg.WhatsAppCredentialsUrl.Contains('?') ? "&" : "?";
            var url = cfg.WhatsAppCredentialsUrl + separator + "machine_uuid=" + Uri.EscapeDataString(Environment.MachineName);

            var client = _httpClientFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(Math.Max(5, cfg.WhatsAppTimeoutSeconds));

            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrWhiteSpace(cfg.AgentToken))
            {
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", cfg.AgentToken);
            }

            using var response = await client.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("IGMS credential fetch failed with status {StatusCode}", (int) response.StatusCode);
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            var parsed = JsonSerializer.Deserialize<WhatsAppCredentialApiResponse>(body, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            if (parsed?.Credentials is null)
            {
                _logger.LogWarning("IGMS credential fetch response missing credential payload.");
                return null;
            }

            var runtime = new RuntimeWhatsAppCredentials
            {
                Enabled = parsed.Credentials.Enabled,
                TwilioAccountSid = parsed.Credentials.TwilioAccountSid?.Trim(),
                TwilioAuthToken = parsed.Credentials.TwilioAuthToken?.Trim(),
                TwilioWhatsAppFrom = parsed.Credentials.TwilioWhatsAppFrom?.Trim(),
                Version = parsed.Version,
            };

            if (runtime.Enabled
                && (string.IsNullOrWhiteSpace(runtime.TwilioAccountSid)
                    || string.IsNullOrWhiteSpace(runtime.TwilioAuthToken)
                    || string.IsNullOrWhiteSpace(runtime.TwilioWhatsAppFrom)))
            {
                _logger.LogWarning("IGMS credential payload is incomplete while enabled=true; refusing payload and preserving fallback.");
                return null;
            }

            var ttl = parsed.TtlSeconds > 0
                ? parsed.TtlSeconds
                : Math.Max(30, cfg.WhatsAppCredentialsTtlSeconds);

            lock (_sync)
            {
                _cached = runtime;
                _expiresUtc = DateTime.UtcNow.AddSeconds(ttl);
            }

            _configProvider.PersistFetchedWhatsAppCredentials(runtime);

            return runtime;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to fetch WhatsApp credentials from IGMS.");
            return null;
        }
    }

    private static RuntimeWhatsAppCredentials LocalCredentials(AgentConfig cfg)
    {
        return new RuntimeWhatsAppCredentials
        {
            Enabled = cfg.WhatsAppEnabled,
            TwilioAccountSid = cfg.TwilioAccountSid,
            TwilioAuthToken = cfg.TwilioAuthToken,
            TwilioWhatsAppFrom = cfg.TwilioWhatsAppFrom,
            Version = 0,
        };
    }
}

internal sealed class AgentConfigProvider
{
    private readonly string _configPath;
    private readonly ILogger<AgentConfigProvider> _logger;

    public AgentConfigProvider(AppPaths paths, ILogger<AgentConfigProvider> logger)
    {
        _configPath = Path.Combine(paths.BasePath, "agent.config.json");
        _logger = logger;
        Config = Load();
    }

    public AgentConfig Config { get; private set; }

    public bool Naps2ExecutableExists => !string.IsNullOrWhiteSpace(Config.Naps2Path) && File.Exists(Config.Naps2Path);

    public AgentConfig Load()
    {
        try
        {
            if (!File.Exists(_configPath))
            {
                _logger.LogWarning("agent.config.json not found at {Path}", _configPath);
                return Config = new AgentConfig();
            }

            var json = File.ReadAllText(_configPath);
            Config = TryDeserialize(json) ?? new AgentConfig();

            // Strip invisible Unicode directional/formatting characters from paths.
            // These are silently inserted when copying paths from browsers, Word, or PDFs.
            if (Config.Naps2Path is not null)
                Config.Naps2Path = StripInvisibleChars(Config.Naps2Path);
            if (Config.UploadUrl is not null)
                Config.UploadUrl = StripInvisibleChars(Config.UploadUrl);
            if (Config.TwilioAccountSid is not null)
                Config.TwilioAccountSid = StripInvisibleChars(Config.TwilioAccountSid);
            if (Config.TwilioAuthToken is not null)
                Config.TwilioAuthToken = StripInvisibleChars(Config.TwilioAuthToken);
            if (Config.TwilioWhatsAppFrom is not null)
                Config.TwilioWhatsAppFrom = StripInvisibleChars(Config.TwilioWhatsAppFrom);
            if (Config.WhatsAppCredentialsUrl is not null)
                Config.WhatsAppCredentialsUrl = StripInvisibleChars(Config.WhatsAppCredentialsUrl);
            if (Config.WhatsAppCredentialsSource is not null)
                Config.WhatsAppCredentialsSource = StripInvisibleChars(Config.WhatsAppCredentialsSource);

            return Config;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load agent.config.json");
            Config = new AgentConfig();
            return Config;
        }
    }

    /// <summary>
    /// Removes invisible Unicode formatting/directional characters (e.g. U+202A, U+200B, U+FEFF)
    /// that get silently embedded when paths are copy-pasted from browsers, PDFs, or Office apps.
    /// </summary>
    private static string StripInvisibleChars(string value) =>
        new string(value.Where(c =>
            c != '\u200B' && // zero-width space
            c != '\u200C' && // zero-width non-joiner
            c != '\u200D' && // zero-width joiner
            c != '\u200E' && // left-to-right mark
            c != '\u200F' && // right-to-left mark
            c != '\u202A' && // left-to-right embedding
            c != '\u202B' && // right-to-left embedding
            c != '\u202C' && // pop directional formatting
            c != '\u202D' && // left-to-right override
            c != '\u202E' && // right-to-left override
            c != '\uFEFF'    // byte order mark / zero-width no-break space
        ).ToArray()).Trim();

    /// <summary>
    /// Tries to deserialise the JSON. If it fails (common on Windows when the user wrote
    /// single backslashes in paths, e.g. "C:\Program Files\..."), automatically escapes
    /// backslashes and retries once before giving up.
    /// </summary>
    private AgentConfig? TryDeserialize(string json)
    {
        var opts = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        try
        {
            return JsonSerializer.Deserialize<AgentConfig>(json, opts);
        }
        catch (JsonException firstEx)
        {
            // Replace unescaped backslashes inside JSON string values.
            // Only replace \ that are NOT already part of a valid escape sequence.
            var fixed_json = System.Text.RegularExpressions.Regex.Replace(
                json,
                @"(?<!\\)\\(?![""\\\/bfnrtu])",
                @"\\");

            if (fixed_json == json)
            {
                // Nothing changed — re-throw the original error.
                throw;
            }

            try
            {
                var result = JsonSerializer.Deserialize<AgentConfig>(fixed_json, opts);
                _logger.LogWarning("agent.config.json contained unescaped backslashes (Windows paths) — loaded successfully after auto-correction. Consider using forward slashes or double backslashes in the config.");
                return result;
            }
            catch (JsonException)
            {
                // Throw the original, more meaningful exception.
                throw firstEx;
            }
        }
    }

    public void PersistFetchedWhatsAppCredentials(RuntimeWhatsAppCredentials credentials)
    {
        try
        {
            if (credentials.Enabled
                && (string.IsNullOrWhiteSpace(credentials.TwilioAccountSid)
                    || string.IsNullOrWhiteSpace(credentials.TwilioAuthToken)
                    || string.IsNullOrWhiteSpace(credentials.TwilioWhatsAppFrom)))
            {
                _logger.LogWarning("Skipping local credential mirror update because fetched credentials are incomplete.");
                return;
            }

            Config.WhatsAppEnabled = credentials.Enabled;
            Config.TwilioAccountSid = credentials.TwilioAccountSid;
            Config.TwilioAuthToken = credentials.TwilioAuthToken;
            Config.TwilioWhatsAppFrom = credentials.TwilioWhatsAppFrom;

            if (!File.Exists(_configPath))
            {
                return;
            }

            var json = File.ReadAllText(_configPath);
            var dict = JsonSerializer.Deserialize<Dictionary<string, object?>>(json)
                ?? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

            dict["whatsapp_enabled"] = credentials.Enabled;
            dict["twilio_account_sid"] = credentials.TwilioAccountSid;
            dict["twilio_auth_token"] = credentials.TwilioAuthToken;
            dict["twilio_whatsapp_from"] = credentials.TwilioWhatsAppFrom;
            dict["whatsapp_credentials_cached_version"] = credentials.Version;
            dict["whatsapp_credentials_cached_at_utc"] = DateTime.UtcNow.ToString("O");

            var output = JsonSerializer.Serialize(dict, new JsonSerializerOptions
            {
                WriteIndented = true,
            });

            File.WriteAllText(_configPath, output);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist fetched WhatsApp credentials to local config mirror.");
        }
    }
}

internal sealed class AppState
{
    private readonly object _sync = new();

    public string Version { get; } = "1.0.0-phase1";

    public string SessionId { get; } = Guid.NewGuid().ToString("N");

    public DateTime StartTimeUtc { get; } = DateTime.UtcNow;

    public string? MachineUuid { get; private set; }

    public DateTime? LastScanTimeUtc { get; set; }

    public DateTime? LastCompletedScanTimeUtc { get; set; }

    public bool PrinterConnected { get; set; }

    public string BasePathRoot { get; set; } = AgentEnvironmentPaths.GetDiskRoot();

    public double UptimeSeconds => (DateTime.UtcNow - StartTimeUtc).TotalSeconds;

    public int ConsecutiveScanFailures { get; set; }

    public void EnsureMachineUuid()
    {
        if (MachineUuid is not null)
        {
            return;
        }

        lock (_sync)
        {
            MachineUuid ??= Guid.NewGuid().ToString();
        }
    }
}

internal static class PortFinder
{
    public static int FindFirstAvailable(IEnumerable<int> preferredPorts)
    {
        foreach (var port in preferredPorts)
        {
            if (IsPortFree(port))
            {
                return port;
            }
        }

        throw new InvalidOperationException("No available ports in preferred list.");
    }

    private static bool IsPortFree(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            listener.Stop();
            return true;
        }
        catch
        {
            return false;
        }
    }
}

internal sealed class PersistentJobStore
{
    private readonly AppPaths _paths;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };

    public PersistentJobStore(AppPaths paths)
    {
        _paths = paths;
        Directory.CreateDirectory(Path.Combine(_paths.Queue, "jobs"));
    }

    public IEnumerable<ScanJob> LoadPending()
    {
        var dir = Path.Combine(_paths.Queue, "jobs");
        foreach (var file in Directory.GetFiles(dir, "*.json"))
        {
                ScanJob? job = null;
                try
                {
                    job = JsonSerializer.Deserialize<ScanJob>(File.ReadAllText(file), _jsonOptions);
                }
                catch
                {
                    // Ignore corrupt job files for now
                }

                if (job is null)
                {
                    continue;
                }
                if (job.Status is ScanJobStatus.Completed or ScanJobStatus.Failed)
                {
                    continue;
                }
                job.Status = ScanJobStatus.Queued;
                yield return job;
        }
    }

    public void Save(ScanJob job)
    {
        var dir = Path.Combine(_paths.Queue, "jobs");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, job.JobId + ".json");
        var json = JsonSerializer.Serialize(job, _jsonOptions);
        File.WriteAllText(path, json);
    }
}

internal sealed class PersistentWhatsAppMessageStore
{
    private readonly AppPaths _paths;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };

    public PersistentWhatsAppMessageStore(AppPaths paths)
    {
        _paths = paths;
        Directory.CreateDirectory(Path.Combine(_paths.Queue, "whatsapp"));
    }

    public IEnumerable<WhatsAppMessage> LoadPending()
    {
        var dir = Path.Combine(_paths.Queue, "whatsapp");
        foreach (var file in Directory.GetFiles(dir, "*.json"))
        {
            WhatsAppMessage? message = null;
            try
            {
                message = JsonSerializer.Deserialize<WhatsAppMessage>(File.ReadAllText(file), _jsonOptions);
            }
            catch
            {
                // Ignore corrupt files.
            }

            if (message is null)
            {
                continue;
            }

            if (message.Status is WhatsAppMessageStatus.Delivered or WhatsAppMessageStatus.Failed)
            {
                continue;
            }

            message.Status = WhatsAppMessageStatus.Queued;
            yield return message;
        }
    }

    public void Save(WhatsAppMessage message)
    {
        var dir = Path.Combine(_paths.Queue, "whatsapp");
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, message.MessageId + ".json");
        var json = JsonSerializer.Serialize(message, _jsonOptions);
        File.WriteAllText(path, json);
    }
}

internal sealed class ScanProfile
{
    [JsonPropertyName("profile_name")]
    public string ProfileName { get; set; } = string.Empty;

    [JsonPropertyName("scanner_name")]
    public string ScannerName { get; set; } = string.Empty;

    [JsonPropertyName("driver")]
    public string? Driver { get; set; }

    [JsonPropertyName("dpi")]
    public int Dpi { get; set; } = 300;

    [JsonPropertyName("color_mode")]
    public string ColorMode { get; set; } = "color";

    [JsonPropertyName("source")]
    public string Source { get; set; } = "ADF";

    [JsonPropertyName("duplex")]
    public bool Duplex { get; set; }

    [JsonPropertyName("paper_size")]
    public string PaperSize { get; set; } = "A4";
}

internal sealed class ScanProfileStore
{
    private readonly string _path;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly object _sync = new();

    public ScanProfileStore(AppPaths paths)
    {
        _path = Path.Combine(paths.Cache, "profiles.json");
    }

    public IReadOnlyCollection<ScanProfile> GetAll()
    {
        lock (_sync)
        {
            if (!File.Exists(_path))
            {
                return Array.Empty<ScanProfile>();
            }
            var json = File.ReadAllText(_path);
            return JsonSerializer.Deserialize<List<ScanProfile>>(json, _jsonOptions) ?? new List<ScanProfile>();
        }
    }

    public ScanProfile? Get(string profileName)
    {
        return GetAll().FirstOrDefault(p => string.Equals(p.ProfileName, profileName, StringComparison.OrdinalIgnoreCase));
    }

    public void Save(ScanProfile profile)
    {
        lock (_sync)
        {
            var list = GetAll().ToList();
            var existing = list.FindIndex(p => string.Equals(p.ProfileName, profile.ProfileName, StringComparison.OrdinalIgnoreCase));
            if (existing >= 0)
            {
                list[existing] = profile;
            }
            else
            {
                list.Add(profile);
            }
            var json = JsonSerializer.Serialize(list, _jsonOptions);
            File.WriteAllText(_path, json);
        }
    }
}

internal sealed class ScannerInfo
{
    public string Name { get; set; } = string.Empty;
    public string Driver { get; set; } = string.Empty;
    public bool IsDefault { get; set; }
    public DateTime? LastSeenAt { get; set; }
}

internal sealed class ScannerService
{
    private readonly List<ScannerInfo> _scanners = new();
    private readonly object _sync = new();
    private readonly AgentConfigProvider _config;
    private readonly ScanProfileStore _profileStore;
    private readonly ILogger<ScannerService> _logger;
    private DateTime _lastRefresh = DateTime.MinValue;
    private readonly TimeSpan _refreshInterval = TimeSpan.FromSeconds(30);

    public ScannerService(AgentConfigProvider config, ScanProfileStore profileStore, ILogger<ScannerService> logger)
    {
        _config = config;
        _profileStore = profileStore;
        _logger = logger;
    }

    public IReadOnlyCollection<ScannerInfo> GetScanners()
    {
        EnsureRefreshed();
        lock (_sync)
        {
            return _scanners.ToList();
        }
    }

    public bool HasAvailableScanner
    {
        get
        {
            EnsureRefreshed();
            lock (_sync)
            {
                return _scanners.Any();
            }
        }
    }

    public bool HasProfile(string profileName)
    {
        EnsureRefreshed();
        lock (_sync)
        {
            return _scanners.Any(s => string.Equals(s.Name, profileName, StringComparison.OrdinalIgnoreCase));
        }
    }

    public bool IsDeviceAvailable(string? scannerName, string? driver = null)
    {
        EnsureRefreshed();

        lock (_sync)
        {
            if (_scanners.Count == 0)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(scannerName))
            {
                return true;
            }

            if (_scanners.Any(s => string.Equals(s.Name, scannerName, StringComparison.OrdinalIgnoreCase)
                && (string.IsNullOrWhiteSpace(driver) || string.Equals(s.Driver, driver, StringComparison.OrdinalIgnoreCase))))
            {
                return true;
            }
        }

        if ((DateTime.UtcNow - _lastRefresh) > TimeSpan.FromSeconds(5))
        {
            Refresh();
            lock (_sync)
            {
                return _scanners.Any(s => string.Equals(s.Name, scannerName, StringComparison.OrdinalIgnoreCase)
                    && (string.IsNullOrWhiteSpace(driver) || string.Equals(s.Driver, driver, StringComparison.OrdinalIgnoreCase)));
            }
        }

        return false;
    }

    private void EnsureRefreshed()
    {
        if ((DateTime.UtcNow - _lastRefresh) < _refreshInterval)
        {
            return;
        }

        Refresh();
    }

    private void Refresh()
    {
        _lastRefresh = DateTime.UtcNow;

        if (!_config.Naps2ExecutableExists)
        {
            _logger.LogWarning("Skipping scanner refresh — NAPS2 not found at path: {Path}", _config.Config.Naps2Path ?? "(not configured)");
            lock (_sync)
            {
                _scanners.Clear();
            }
            return;
        }

        try
        {
            // Windows uses TWAIN/WIA drivers; macOS uses Apple/SANE/ESCL; Linux uses SANE/ESCL.
            // Note: ESCL is notoriously slow (can take 60+ seconds) and often returns empty,
            // so we skip it on Windows once we find scanners via TWAIN or WIA.
            var drivers = OperatingSystem.IsWindows()
                ? new[] { "twain", "wia", "escl" }
                : OperatingSystem.IsMacOS()
                    ? new[] { "apple", "escl", "sane" }
                    : new[] { "sane", "escl" };
            var found = false;
            var discovered = new List<ScannerInfo>();
            
            // Timeout per driver enumeration to prevent blocking (ESCL is especially slow)
            var driverTimeout = TimeSpan.FromSeconds(10);
            
            foreach (var driver in drivers)
            {
                // Skip ESCL on Windows if we already found scanners via faster drivers
                if (string.Equals(driver, "escl", StringComparison.OrdinalIgnoreCase) 
                    && OperatingSystem.IsWindows() 
                    && discovered.Count > 0)
                {
                    _logger.LogInformation("Skipping ESCL enumeration — already found {Count} scanner(s) via faster drivers", discovered.Count);
                    continue;
                }
                
                var psi = new ProcessStartInfo
                {
                    FileName = _config.Config.Naps2Path!,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                // On macOS/Linux NAPS2 uses a 'console' subcommand.
                // On Windows the dedicated naps2.console.exe is used directly — no subcommand needed.
                if (!OperatingSystem.IsWindows())
                {
                    psi.ArgumentList.Add("console");
                }
                psi.ArgumentList.Add("--driver");
                psi.ArgumentList.Add(driver);
                psi.ArgumentList.Add("--listdevices");

                using var proc = new Process { StartInfo = psi };
                proc.Start();
                
                // Read output with timeout to prevent blocking on slow drivers
                var readTask = Task.Run(() =>
                {
                    var stdout = proc.StandardOutput.ReadToEnd();
                    var stderr = proc.StandardError.ReadToEnd();
                    return (stdout, stderr);
                });
                
                string stdout, stderr;
                if (readTask.Wait(driverTimeout))
                {
                    (stdout, stderr) = readTask.Result;
                    proc.WaitForExit(1000); // Brief wait for process to fully exit
                }
                else
                {
                    // Timeout - kill the process and skip this driver
                    _logger.LogWarning("NAPS2 listdevices for driver {Driver} timed out after {Timeout}s — killing process", 
                        driver, driverTimeout.TotalSeconds);
                    try
                    {
                        proc.Kill(entireProcessTree: true);
                    }
                    catch { /* ignore kill errors */ }
                    continue;
                }

                _logger.LogInformation(
                    "NAPS2 listdevices driver={Driver} exit={Exit} stdout={Stdout} stderr={Stderr}",
                    driver, proc.ExitCode,
                    string.IsNullOrWhiteSpace(stdout) ? "(empty)" : stdout.Trim(),
                    string.IsNullOrWhiteSpace(stderr) ? "(empty)" : stderr.Trim());

                if (proc.ExitCode != 0)
                {
                    _logger.LogWarning("NAPS2 listdevices failed for driver {Driver}: {Code} {Error}", driver, proc.ExitCode, stderr);
                    continue;
                }

                var lines = stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(l => l.Trim())
                    .Where(l => !string.IsNullOrWhiteSpace(l))
                    .ToList();

                if (lines.Count == 0)
                {
                    continue;
                }

                found = true;

                for (var i = 0; i < lines.Count; i++)
                {
                    var name = lines[i];
                    if (!discovered.Any(s =>
                        string.Equals(s.Name, name, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(s.Driver, driver, StringComparison.OrdinalIgnoreCase)))
                    {
                        discovered.Add(new ScannerInfo
                        {
                            Name = name,
                            Driver = driver,
                            IsDefault = discovered.Count == 0,
                            LastSeenAt = DateTime.UtcNow
                        });
                    }
                }

                // Auto-create a default profile for any newly discovered scanner
                // that doesn't already have one, so users don't need to POST /profiles manually.
                foreach (var scanner in lines)
                {
                    var profileName = scanner; // use scanner name as default profile name
                    if (_profileStore.Get(profileName) is null)
                    {
                        _profileStore.Save(new ScanProfile
                        {
                            ProfileName = profileName,
                            ScannerName = scanner,
                            Driver = driver,
                            Dpi = 300,
                            ColorMode = "color",
                            Source = "ADF",
                            Duplex = false,
                            PaperSize = "A4"
                        });
                        _logger.LogInformation("Auto-created default profile for scanner {Scanner}", scanner);
                    }
                }
            }

            if (!found)
            {
                lock (_sync)
                {
                    _scanners.Clear();
                }
                return;
            }

            lock (_sync)
            {
                _scanners.Clear();
                _scanners.AddRange(discovered);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to list NAPS2 devices");
            lock (_sync)
            {
                _scanners.Clear();
            }
        }
    }
}

internal interface IUploadClient
{
    Task UploadAsync(ScanJob job, CancellationToken token);
}

internal sealed class HttpUploadClient : IUploadClient
{
    private readonly IHttpClientFactory _factory;
    private readonly AgentConfigProvider _config;
    private readonly AppPaths _paths;
    private readonly AppState _state;
    private readonly ILogger<HttpUploadClient> _logger;

    public HttpUploadClient(IHttpClientFactory factory, AgentConfigProvider config, AppPaths paths, AppState state, ILogger<HttpUploadClient> logger)
    {
        _factory = factory;
        _config = config;
        _paths = paths;
        _state = state;
        _logger = logger;
    }

    public async Task UploadAsync(ScanJob job, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(_config.Config.UploadUrl))
        {
            throw new InvalidOperationException("upload_url_missing");
        }

        if (job.LocalFilePaths.Count == 0)
        {
            throw new InvalidOperationException("no_files_to_upload");
        }

        _state.EnsureMachineUuid();

        var client = _factory.CreateClient();
        client.Timeout = TimeSpan.FromMinutes(10); // allow large uploads/slower endpoints
        var attempts = 0;
        var backoff = TimeSpan.FromSeconds(1);
        var maxAttempts = 5;

        while (true)
        {
            attempts++;
            var sw = Stopwatch.StartNew();
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, _config.Config.UploadUrl);

                if (!string.IsNullOrWhiteSpace(_config.Config.AgentToken))
                {
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _config.Config.AgentToken);
                }

                var filePath = job.LocalFilePaths.First();
                var hash = ComputeSha256(filePath);

                var content = new MultipartFormDataContent();
                var fileContent = new StreamContent(File.OpenRead(filePath));
                content.Add(fileContent, "file", Path.GetFileName(filePath));

                content.Add(new StringContent(job.DocumentId), "document_id");
                content.Add(new StringContent(job.Profile.ProfileName), "scan_profile");
                content.Add(new StringContent(job.Profile.ScannerName), "scanner_name");
                content.Add(new StringContent(job.Profile.Dpi.ToString()), "dpi");
                content.Add(new StringContent(job.Profile.ColorMode), "color_mode");
                content.Add(new StringContent(job.JobId), "job_id");
                content.Add(new StringContent(_state.MachineUuid ?? string.Empty), "machine_uuid");
                content.Add(new StringContent(DateTime.UtcNow.ToString("O")), "scanned_at");
                content.Add(new StringContent("0"), "page_count");
                content.Add(new StringContent(hash), "file_hash");

                request.Headers.TryAddWithoutValidation("X-File-Hash", hash);
                request.Content = content;

                var response = await client.SendAsync(request, token);
                var body = await response.Content.ReadAsStringAsync(token);
                sw.Stop();

                _logger.LogInformation("upload_attempt job {JobId} attempt {Attempt} status {Status} duration_ms {Duration}", job.JobId, attempts, (int)response.StatusCode, sw.ElapsedMilliseconds);

                if (!response.IsSuccessStatusCode)
                {
                    throw new InvalidOperationException($"upload_failed_status_{(int)response.StatusCode}");
                }

                var confirmed = ConfirmHash(body, hash);
                if (!confirmed)
                {
                    throw new InvalidOperationException("upload_hash_mismatch");
                }

                MoveToCache(filePath, job.JobId);
                return;
            }
            catch (Exception ex) when (attempts < maxAttempts)
            {
                sw.Stop();
                _logger.LogWarning(ex, "Upload attempt {Attempt} failed for job {JobId}", attempts, job.JobId);
                await Task.Delay(backoff, token);
                backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 2, 16));
            }
            catch (Exception)
            {
                throw;
            }
        }
    }

    private static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static bool ConfirmHash(string body, string expected)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("file_hash", out var fh))
            {
                return string.Equals(fh.GetString(), expected, StringComparison.OrdinalIgnoreCase);
            }
            if (doc.RootElement.TryGetProperty("hash", out var h))
            {
                return string.Equals(h.GetString(), expected, StringComparison.OrdinalIgnoreCase);
            }
        }
        catch
        {
            return false;
        }
        return false;
    }

    private void MoveToCache(string filePath, string jobId)
    {
        try
        {
            var completedDir = Path.Combine(_paths.Cache, "completed");
            Directory.CreateDirectory(completedDir);
            var dest = Path.Combine(completedDir, Path.GetFileName(filePath));
            if (File.Exists(dest))
            {
                dest = Path.Combine(completedDir, jobId + "_" + Path.GetFileName(filePath));
            }
            File.Copy(filePath, dest, true);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to copy file to cache after upload {JobId}", jobId);
        }
    }
}

internal sealed class FileJsonLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentDictionary<string, FileJsonLogger> _loggers = new();
    private readonly AppState _state;

    public FileJsonLoggerProvider(AppState state)
    {
        _state = state;
    }

    public ILogger CreateLogger(string categoryName)
    {
        return _loggers.GetOrAdd(categoryName, name => new FileJsonLogger(name, _state));
    }

    public void Dispose()
    {
    }
}

internal sealed class FileJsonLogger : ILogger
{
    private readonly string _category;
    private readonly AppState _state;
    private static readonly object _sync = new();

    public FileJsonLogger(string category, AppState state)
    {
        _category = category;
        _state = state;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var message = formatter(state, exception);
        var entry = new
        {
            timestamp = DateTime.UtcNow.ToString("O"),
            level = logLevel.ToString(),
            component = _category,
            session_id = _state.SessionId,
            job_id = TryGetJobId(state),
            message,
            exception = exception?.ToString()
        };

        var json = JsonSerializer.Serialize(entry);
        WriteLog(json);
    }

    private static string? TryGetJobId<TState>(TState state)
    {
        if (state is IReadOnlyList<KeyValuePair<string, object>> list)
        {
            var kv = list.FirstOrDefault(k => k.Key == "JobId" || k.Key == "job_id");
            return kv.Value?.ToString();
        }
        return null;
    }

    private static void WriteLog(string line)
    {
        lock (_sync)
        {
            var basePath = Path.Combine(AgentEnvironmentPaths.GetAgentBasePath(), "logs");
            Directory.CreateDirectory(basePath);
            var path = Path.Combine(basePath, DateTime.UtcNow.ToString("yyyy-MM-dd") + ".log");
            File.AppendAllText(path, line + Environment.NewLine);
        }
    }
}

/// <summary>
/// Runs hourly and removes temporary / old files that are no longer needed:
/// - tmp/ folder: always cleared
/// - scanned/ PDFs: removed after 7 days (uploaded files) or kept for failed jobs (up to 30 days)
/// - queue/jobs/ JSON: completed/failed entries older than 7 days
/// </summary>
internal sealed class CleanupService : BackgroundService
{
    private readonly AppPaths _paths;
    private readonly ILogger<CleanupService> _logger;
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);
    private static readonly TimeSpan KeepCompleted = TimeSpan.FromDays(7);
    private static readonly TimeSpan KeepFailed = TimeSpan.FromDays(30);

    public CleanupService(AppPaths paths, ILogger<CleanupService> logger)
    {
        _paths = paths;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Run once shortly after startup, then every hour.
        await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { RunCleanup(); }
            catch (Exception ex) { _logger.LogError(ex, "Cleanup error"); }

            await Task.Delay(Interval, stoppingToken);
        }
    }

    private void RunCleanup()
    {
        var deleted = 0;

        // 1. Wipe tmp/ entirely
        deleted += WipeDirectory(_paths.Tmp);

        // 2. Remove old scanned job folders
        var scannedDir = new DirectoryInfo(_paths.Scanned);
        if (scannedDir.Exists)
        {
            foreach (var jobDir in scannedDir.GetDirectories())
            {
                var age = DateTime.UtcNow - jobDir.CreationTimeUtc;
                if (age > KeepCompleted)
                {
                    try { jobDir.Delete(recursive: true); deleted++; }
                    catch (Exception ex) { _logger.LogWarning(ex, "Could not delete scanned folder {Dir}", jobDir.FullName); }
                }
            }
        }

        // 3. Remove old completed/failed queue job JSON files
        var jobsDir = Path.Combine(_paths.Queue, "jobs");
        if (Directory.Exists(jobsDir))
        {
            foreach (var file in Directory.GetFiles(jobsDir, "*.json"))
            {
                try
                {
                    var json = File.ReadAllText(file);
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    var statusStr = root.TryGetProperty("Status", out var s) ? s.GetString() : null;
                    var isTerminal = statusStr is "Completed" or "Failed";
                    if (!isTerminal) continue;

                    var age = DateTime.UtcNow - File.GetLastWriteTimeUtc(file);
                    var threshold = statusStr == "Failed" ? KeepFailed : KeepCompleted;
                    if (age > threshold)
                    {
                        File.Delete(file);
                        deleted++;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not process job file {File} during cleanup", file);
                }
            }
        }

        // 4. Remove old delivered/failed WhatsApp queue JSON files
        var whatsappDir = Path.Combine(_paths.Queue, "whatsapp");
        if (Directory.Exists(whatsappDir))
        {
            foreach (var file in Directory.GetFiles(whatsappDir, "*.json"))
            {
                try
                {
                    var json = File.ReadAllText(file);
                    using var doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;

                    var statusStr = root.TryGetProperty("Status", out var s) ? s.GetString() : null;
                    var isTerminal = statusStr is "Delivered" or "Failed";
                    if (!isTerminal) continue;

                    var age = DateTime.UtcNow - File.GetLastWriteTimeUtc(file);
                    var threshold = statusStr == "Failed" ? KeepFailed : KeepCompleted;
                    if (age > threshold)
                    {
                        File.Delete(file);
                        deleted++;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Could not process WhatsApp queue file {File} during cleanup", file);
                }
            }
        }

        // 5. Remove old cache/completed files (PDFs already uploaded)
        deleted += WipeOldFiles(Path.Combine(_paths.Cache, "completed"), KeepCompleted);

        // 6. Remove old failed/ files
        deleted += WipeOldFiles(_paths.Failed, KeepFailed);

        if (deleted > 0)
            _logger.LogInformation("Cleanup removed {Count} file(s)/folder(s)", deleted);
    }

    private static int WipeDirectory(string path)
    {
        if (!Directory.Exists(path)) return 0;
        var count = 0;
        foreach (var file in Directory.GetFiles(path, "*", SearchOption.AllDirectories))
        {
            try { File.Delete(file); count++; } catch { /* ignore */ }
        }
        foreach (var dir in Directory.GetDirectories(path))
        {
            try { Directory.Delete(dir, recursive: true); count++; } catch { /* ignore */ }
        }
        return count;
    }

    private static int WipeOldFiles(string path, TimeSpan maxAge)
    {
        if (!Directory.Exists(path)) return 0;
        var count = 0;
        foreach (var file in Directory.GetFiles(path, "*", SearchOption.AllDirectories))
        {
            try
            {
                if (DateTime.UtcNow - File.GetLastWriteTimeUtc(file) > maxAge)
                {
                    File.Delete(file);
                    count++;
                }
            }
            catch { /* ignore */ }
        }
        return count;
    }
}

internal sealed class SecurityOptions
{
    public string AllowedOrigin { get; set; } = "*";
}

internal sealed class LoopbackAndOriginMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SecurityOptions _options;

    public LoopbackAndOriginMiddleware(RequestDelegate next, IOptions<SecurityOptions> options)
    {
        _next = next;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp is null || (!IPAddress.IsLoopback(remoteIp)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        var origin = context.Request.Headers["Origin"].ToString();

        // Validate origin when not wildcard
        if (!string.IsNullOrWhiteSpace(origin) && _options.AllowedOrigin != "*" && !string.Equals(origin, _options.AllowedOrigin, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        // Add CORS headers so the browser accepts the response
        var allowOrigin = _options.AllowedOrigin == "*"
            ? (string.IsNullOrWhiteSpace(origin) ? "*" : origin)
            : _options.AllowedOrigin;

        context.Response.Headers["Access-Control-Allow-Origin"] = allowOrigin;
        context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
        context.Response.Headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With";
        context.Response.Headers["Access-Control-Max-Age"] = "3600";

        // Handle CORS preflight
        if (context.Request.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return;
        }

        await _next(context);
    }
}

internal static class SystemInfo
{
    private const long OneMb = 1024 * 1024;
    private const long OneGb = OneMb * 1024;

    public static bool HasSufficientDiskSpace(long thresholdBytes = OneGb)
    {
        var free = GetFreeDiskSpaceBytes(AgentEnvironmentPaths.GetDiskRoot());
        return free >= thresholdBytes;
    }

    public static double GetFreeDiskSpaceMb(string? rootPath)
    {
        var free = GetFreeDiskSpaceBytes(rootPath ?? string.Empty);
        return free / (double)OneMb;
    }

    private static long GetFreeDiskSpaceBytes(string rootPath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(rootPath))
            {
                return 0;
            }

            if (Directory.Exists(rootPath))
            {
                var direct = new DriveInfo(rootPath);
                return direct.AvailableFreeSpace;
            }

            var driveRoot = Directory.GetDirectoryRoot(rootPath);
            if (!string.IsNullOrWhiteSpace(driveRoot) && Directory.Exists(driveRoot))
            {
                var byRoot = new DriveInfo(driveRoot);
                return byRoot.AvailableFreeSpace;
            }

            return 0;
        }
        catch
        {
            return 0;
        }
    }
}

internal static class AgentEnvironmentPaths
{
    public static string GetAgentBasePath()
    {
        // When running as a Windows Service the process account (LocalSystem) has a
        // different «Documents» folder than the real user.  The install script writes
        // the real user's path into the service's registry Environment block so we
        // always resolve data to the correct location.
        var envOverride = Environment.GetEnvironmentVariable("DOCUMENTAGENT_BASE_PATH");
        if (!string.IsNullOrWhiteSpace(envOverride) && Path.IsPathRooted(envOverride))
            return envOverride.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        return Path.Combine(GetDocumentsDirectory(), "DocumentAgent");
    }

    public static string GetDiskRoot()
    {
        var documentsDirectory = GetDocumentsDirectory();
        return Path.GetPathRoot(documentsDirectory) ?? documentsDirectory;
    }

    private static string GetDocumentsDirectory()
    {
        // On Windows this reliably returns e.g. C:\Users\username\Documents.
        // On macOS it can return empty string when the app isn't launched from a
        // standard user session, so we fall back to HOME-based resolution.
        var documents = NormalizeAbsolute(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        if (documents is not null)
        {
            return documents;
        }

        // Fallback: derive from UserProfile or HOME env var
        var userProfile = NormalizeAbsolute(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))
            ?? NormalizeAbsolute(Environment.GetEnvironmentVariable("HOME"));
        if (userProfile is not null)
        {
            return Path.Combine(userProfile, "Documents");
        }

        // Last resort — keep data next to the binary
        return Path.Combine(AppContext.BaseDirectory, "DocumentAgentHome");
    }

    private static string? NormalizeAbsolute(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var trimmed = path.Trim();
        if (!Path.IsPathRooted(trimmed))
        {
            return null;
        }

        return Path.GetFullPath(trimmed);
    }
}
