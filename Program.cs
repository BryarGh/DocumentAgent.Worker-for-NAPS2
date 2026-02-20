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

var builder = WebApplication.CreateBuilder(args);

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
    options.BasePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "DocumentAgent");
});

builder.Services.Configure<SecurityOptions>(options =>
{
    options.AllowedOrigin = builder.Configuration["AGENT_ALLOWED_ORIGIN"] ?? "*";
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

var app = builder.Build();

app.UseMiddleware<LoopbackAndOriginMiddleware>();

app.MapGet("/health", (AppState state) => Results.Json(new
{
    status = "ok",
    version = state.Version,
    machine_uuid = state.MachineUuid
}));

app.MapGet("/port", () => Results.Json(new { port = selectedPort }));

app.MapGet("/status", (AppState state, ScanJobQueue queue, ScannerService scannerService, AgentConfigProvider configProvider) =>
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

    var profile = new ScanProfile
    {
        ProfileName = profileName,
        ScannerName = scannerName,
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
        return Results.Json(new { error = "profile_not_found" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (!scannerService.IsDeviceAvailable(profile.ScannerName))
    {
        logger.LogWarning("Scan refused: device missing {Device}", profile.ScannerName);
        return Results.Json(new { error = "scanner_unavailable" }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (queue.TryFindByClientRequest(request.ClientRequestId, request.DocumentId!, out var existingJob))
    {
        return Results.Accepted($"/scan/{existingJob.JobId}", new { job_id = existingJob.JobId, status = existingJob.Status.ToString().ToLowerInvariant(), deduped = true });
    }

    var job = queue.Enqueue(profile, request.DocumentId!, request.ClientRequestId);
    logger.LogInformation("Scan job queued {JobId}", job.JobId);
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
            error_message = job.ErrorMessage
        });
    }

    return Results.NotFound(new { error = "job_not_found" });
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

internal sealed class ProfileRequest
{
    [JsonPropertyName("profile_name")]
    public string? ProfileName { get; init; }

    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("scanner_name")]
    public string? ScannerName { get; init; }

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

internal sealed class ScanJobProcessor : BackgroundService
{
    private readonly ScanJobQueue _queue;
    private readonly AppPaths _paths;
    private readonly ILogger<ScanJobProcessor> _logger;
    private readonly AppState _state;
    private readonly IUploadClient _uploader;
    private readonly AgentConfigProvider _config;
    private readonly TimeSpan _acquireTimeout = TimeSpan.FromMinutes(10);

    public ScanJobProcessor(ScanJobQueue queue, AppPaths paths, AppState state, AgentConfigProvider config, IUploadClient uploader, ILogger<ScanJobProcessor> logger)
    {
        _queue = queue;
        _paths = paths;
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
                job.ErrorMessage = ex.Message;
                job.ErrorCode = ex is TimeoutException
                    ? "scan_timeout"
                    : ex.Message.StartsWith("upload_", StringComparison.OrdinalIgnoreCase)
                        ? "upload_failed"
                        : job.ErrorCode ?? "scan_failed";
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
            throw new InvalidOperationException("naps2_not_configured");
        }

        var psi = new ProcessStartInfo
        {
            FileName = _config.Config.Naps2Path!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(outputPdf) ?? _paths.Scanned
        };
        psi.ArgumentList.Add("console");
        psi.ArgumentList.Add("--profile");
        psi.ArgumentList.Add(job.Profile.ProfileName);
        psi.ArgumentList.Add("--output");
        psi.ArgumentList.Add(outputPdf);

        using var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        cts.CancelAfter(_acquireTimeout);

        proc.Start();

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

        _logger.LogInformation("NAPS2 finished {JobId} exit {Exit} duration_ms {Duration}", job.JobId, exitCode, sw.ElapsedMilliseconds);

        if (exitCode != 0 || !File.Exists(outputPdf) || new FileInfo(outputPdf).Length == 0)
        {
            job.ErrorCode = "scan_failed";
            _logger.LogError("NAPS2 scan failed {JobId} exit {Exit} stderr {Stderr}", job.JobId, exitCode, stderr);
            throw new InvalidOperationException("scan_failed");
        }

        job.LocalFilePaths = new List<string> { outputPdf };
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
            Config = JsonSerializer.Deserialize<AgentConfig>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web)) ?? new AgentConfig();
            return Config;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load agent.config.json");
            Config = new AgentConfig();
            return Config;
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

    public string BasePathRoot { get; set; } = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)) ?? string.Empty;

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
    private readonly ILogger<ScannerService> _logger;
    private DateTime _lastRefresh = DateTime.MinValue;
    private readonly TimeSpan _refreshInterval = TimeSpan.FromSeconds(30);

    public ScannerService(AgentConfigProvider config, ILogger<ScannerService> logger)
    {
        _config = config;
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
            lock (_sync)
            {
                _scanners.Clear();
            }
            return;
        }

        try
        {
            var drivers = new[] { "apple", "sane", "escl" };
            var found = false;
            foreach (var driver in drivers)
            {
                var psi = new ProcessStartInfo
                {
                    FileName = _config.Config.Naps2Path!,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                psi.ArgumentList.Add("console");
                psi.ArgumentList.Add("--driver");
                psi.ArgumentList.Add(driver);
                psi.ArgumentList.Add("--listdevices");

                using var proc = new Process { StartInfo = psi };
                proc.Start();
                var stdout = proc.StandardOutput.ReadToEnd();
                var stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

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

                lock (_sync)
                {
                    _scanners.Clear();
                    for (var i = 0; i < lines.Count; i++)
                    {
                        _scanners.Add(new ScannerInfo
                        {
                            Name = lines[i],
                            Driver = driver,
                            IsDefault = i == 0,
                            LastSeenAt = DateTime.UtcNow
                        });
                    }
                }

                found = true;
                break;
            }

            if (!found)
            {
                lock (_sync)
                {
                    _scanners.Clear();
                }
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
            var basePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "DocumentAgent", "logs");
            Directory.CreateDirectory(basePath);
            var path = Path.Combine(basePath, DateTime.UtcNow.ToString("yyyy-MM-dd") + ".log");
            File.AppendAllText(path, line + Environment.NewLine);
        }
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
        if (!string.IsNullOrWhiteSpace(origin) && _options.AllowedOrigin != "*" && !string.Equals(origin, _options.AllowedOrigin, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
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
        var free = GetFreeDiskSpaceBytes(Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)) ?? string.Empty);
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
