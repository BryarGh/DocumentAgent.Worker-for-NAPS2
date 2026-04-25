using System.Diagnostics;

internal static class WindowsTrayHost
{
    public static IDisposable? TryStart(WebApplication app, AppState state, int port, string[] args)
    {
#if WINDOWS
        if (!OperatingSystem.IsWindows() || !Environment.UserInteractive)
        {
            return null;
        }

        if (Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService())
        {
            return null;
        }

        if (args.Any(arg => string.Equals(arg, "--no-tray", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        var showConsole = args.Any(arg => string.Equals(arg, "--console", StringComparison.OrdinalIgnoreCase));
        var trayHost = new WindowsTrayHostInstance(app, state, port, showConsole);
        trayHost.Start();
        return trayHost;
#else
        return null;
#endif
    }

#if WINDOWS
    private sealed class WindowsTrayHostInstance : IDisposable
    {
        private readonly WebApplication _app;
        private readonly AppState _state;
        private readonly int _port;
        private readonly bool _showConsole;
        private readonly object _sync = new();
        private Thread? _uiThread;
        private TrayApplicationContext? _context;

        public WindowsTrayHostInstance(WebApplication app, AppState state, int port, bool showConsole)
        {
            _app = app;
            _state = state;
            _port = port;
            _showConsole = showConsole;
        }

        public void Start()
        {
            if (!_showConsole)
            {
                HideConsoleWindow();
            }

            _uiThread = new Thread(RunTray)
            {
                IsBackground = true,
                Name = "DocumentAgentTray"
            };
            _uiThread.SetApartmentState(ApartmentState.STA);
            _uiThread.Start();
        }

        public void Dispose()
        {
            TrayApplicationContext? context;
            lock (_sync)
            {
                context = _context;
            }

            context?.RequestExit();
        }

        private void RunTray()
        {
            System.Windows.Forms.Application.EnableVisualStyles();
            System.Windows.Forms.Application.SetCompatibleTextRenderingDefault(false);

            var context = new TrayApplicationContext(_app, _state, _port);
            lock (_sync)
            {
                _context = context;
            }

            System.Windows.Forms.Application.Run(context);
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll")]
        private static extern nint GetConsoleWindow();

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        private static extern bool ShowWindow(nint hWnd, int nCmdShow);

        private static void HideConsoleWindow()
        {
            var handle = GetConsoleWindow();
            if (handle != 0)
            {
                const int SW_HIDE = 0;
                ShowWindow(handle, SW_HIDE);
            }
        }
    }

    private sealed class TrayApplicationContext : System.Windows.Forms.ApplicationContext
    {
        private readonly WebApplication _app;
        private readonly AppState _state;
        private readonly int _port;
        private readonly System.Windows.Forms.NotifyIcon _notifyIcon;
        private readonly System.Windows.Forms.Timer _timer;
        private readonly System.Windows.Forms.Control _invoker;
        private readonly System.Windows.Forms.ToolStripMenuItem _healthItem;
        private readonly System.Windows.Forms.ToolStripMenuItem _scannerItem;
        private readonly System.Windows.Forms.ToolStripMenuItem _queueItem;
        private string _lastHealth = string.Empty;

        public TrayApplicationContext(WebApplication app, AppState state, int port)
        {
            _app = app;
            _state = state;
            _port = port;
            _invoker = new System.Windows.Forms.Control();
            _invoker.CreateControl();

            var menu = new System.Windows.Forms.ContextMenuStrip();
            _healthItem = new System.Windows.Forms.ToolStripMenuItem("Health: checking...") { Enabled = false };
            _scannerItem = new System.Windows.Forms.ToolStripMenuItem("Scanner: checking...") { Enabled = false };
            _queueItem = new System.Windows.Forms.ToolStripMenuItem("Queue: checking...") { Enabled = false };

            menu.Items.Add(_healthItem);
            menu.Items.Add(_scannerItem);
            menu.Items.Add(_queueItem);
            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
            menu.Items.Add("Open Status", null, (_, _) => OpenStatusPage());
            menu.Items.Add("Open Logs", null, (_, _) => OpenLogsFolder());
            menu.Items.Add("Open Logs Tail", null, (_, _) => OpenLogsTail());
            menu.Items.Add("Open Config", null, (_, _) => OpenConfigFile());
            menu.Items.Add("Restart Agent", null, (_, _) => RestartAgent());
            menu.Items.Add(new System.Windows.Forms.ToolStripSeparator());
            menu.Items.Add("Exit Agent", null, (_, _) => ExitAgent());

            _notifyIcon = new System.Windows.Forms.NotifyIcon
            {
                Icon = System.Drawing.SystemIcons.Application,
                Visible = true,
                Text = BuildTrayText(),
                ContextMenuStrip = menu
            };

            _notifyIcon.DoubleClick += (_, _) => OpenStatusPage();
            _notifyIcon.BalloonTipTitle = "DocumentAgent";
            _notifyIcon.BalloonTipText = "DocumentAgent is running in the background.";
            _notifyIcon.ShowBalloonTip(3000);

            _timer = new System.Windows.Forms.Timer
            {
                Interval = 30000,
                Enabled = true
            };
            _timer.Tick += (_, _) => UpdateHealthUi(showBalloon: true);

            UpdateHealthUi(showBalloon: false);

            _app.Lifetime.ApplicationStopping.Register(RequestExit);
        }

        public void RequestExit()
        {
            if (_invoker.IsHandleCreated)
            {
                _invoker.BeginInvoke(new Action(ExitThread));
            }
            else
            {
                ExitThread();
            }
        }

        protected override void ExitThreadCore()
        {
            _timer.Stop();
            _notifyIcon.Visible = false;
            _notifyIcon.Dispose();
            _timer.Dispose();
            _invoker.Dispose();
            base.ExitThreadCore();
        }

        private string BuildTrayText()
        {
            var status = _state.ConsecutiveScanFailures > 0 ? "issues detected" : "running";
            return $"DocumentAgent: {status}";
        }

        private void UpdateHealthUi(bool showBalloon)
        {
            var scannerService = _app.Services.GetService<ScannerService>();
            var configProvider = _app.Services.GetService<AgentConfigProvider>();
            var queue = _app.Services.GetService<ScanJobQueue>();

            var naps2Ok = configProvider?.Naps2ExecutableExists ?? false;
            var scannerOk = scannerService?.HasAvailableScanner ?? false;
            var queueCount = queue?.CountQueuedUploads ?? 0;
            var failedCount = queue?.CountFailedUploads ?? 0;

            var healthText = (naps2Ok && scannerOk && _state.ConsecutiveScanFailures == 0)
                ? "healthy"
                : "degraded";

            _healthItem.Text = $"Health: {healthText}";
            _scannerItem.Text = $"Scanner: {(scannerOk ? "connected" : "not available")}";
            _queueItem.Text = $"Queue: {queueCount} queued / {failedCount} failed";
            _notifyIcon.Text = BuildTrayText();

            if (showBalloon && !string.Equals(_lastHealth, healthText, StringComparison.Ordinal))
            {
                _notifyIcon.BalloonTipTitle = "DocumentAgent Status";
                _notifyIcon.BalloonTipText = healthText == "healthy"
                    ? "Scanner and agent are healthy."
                    : "Agent is running with degraded scanner/health status.";
                _notifyIcon.ShowBalloonTip(2500);
            }

            _lastHealth = healthText;
        }

        private void OpenStatusPage()
        {
            OpenShellTarget($"http://127.0.0.1:{_port}/status");
        }

        private void OpenLogsFolder()
        {
            var logsPath = Path.Combine(AgentEnvironmentPaths.GetAgentBasePath(), "logs");
            Directory.CreateDirectory(logsPath);
            OpenShellTarget(logsPath);
        }

        private void OpenLogsTail()
        {
            var logsPath = Path.Combine(AgentEnvironmentPaths.GetAgentBasePath(), "logs");
            Directory.CreateDirectory(logsPath);

            var latestLog = new DirectoryInfo(logsPath)
                .GetFiles("*.log")
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .FirstOrDefault();

            if (latestLog is null)
            {
                OpenShellTarget(logsPath);
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = "notepad.exe",
                Arguments = $"\"{latestLog.FullName}\"",
                UseShellExecute = true
            });
        }

        private void OpenConfigFile()
        {
            var configPath = Path.Combine(AgentEnvironmentPaths.GetAgentBasePath(), "agent.config.json");
            Directory.CreateDirectory(Path.GetDirectoryName(configPath) ?? AgentEnvironmentPaths.GetAgentBasePath());
            if (!File.Exists(configPath))
            {
                File.WriteAllText(configPath, "{}\n");
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = "notepad.exe",
                Arguments = $"\"{configPath}\"",
                UseShellExecute = true
            });
        }

        private void RestartAgent()
        {
            try
            {
                var processPath = Environment.ProcessPath;
                if (!string.IsNullOrWhiteSpace(processPath))
                {
                    var exeDirectory = Path.GetDirectoryName(processPath) ?? string.Empty;
                    var hiddenLauncher = Path.Combine(exeDirectory, "DocumentAgent.Worker.HiddenLauncher.vbs");

                    if (File.Exists(hiddenLauncher))
                    {
                        var wscriptPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "wscript.exe");
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = wscriptPath,
                            Arguments = $"\"{hiddenLauncher}\"",
                            UseShellExecute = true,
                            CreateNoWindow = true
                        });
                    }
                    else
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = processPath,
                            UseShellExecute = true
                        });
                    }
                }
            }
            catch
            {
                // If restart spawn fails, still keep the current agent alive.
                return;
            }

            _app.Lifetime.StopApplication();
        }

        private void ExitAgent()
        {
            _app.Lifetime.StopApplication();
        }

        private static void OpenShellTarget(string target)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = target,
                UseShellExecute = true
            });
        }
    }
#endif
}