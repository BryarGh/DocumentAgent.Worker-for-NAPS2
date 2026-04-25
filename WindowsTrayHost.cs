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

        public TrayApplicationContext(WebApplication app, AppState state, int port)
        {
            _app = app;
            _state = state;
            _port = port;
            _invoker = new System.Windows.Forms.Control();
            _invoker.CreateControl();

            var menu = new System.Windows.Forms.ContextMenuStrip();
            menu.Items.Add("Open Status", null, (_, _) => OpenStatusPage());
            menu.Items.Add("Open Logs", null, (_, _) => OpenLogsFolder());
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
            _timer.Tick += (_, _) => _notifyIcon.Text = BuildTrayText();

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