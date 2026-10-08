using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Diagnostics;
using Microsoft.Win32;
using System.Windows.Forms;

namespace PrivateProtection.Installer
{
    static class Program
    {
        private const string AppName = "Privex Desktop Security";
        private const string AppVersion = "0.1.0";
        private const string PublisherName = "Privex Project";
        private const string ExeName = "PrivateProtection.exe";
        private const string UninstallExeName = "Uninstall.exe";

        [STAThread]
        static int Main(string[] args)
        {
            bool isSilent = false;
            bool launchAfter = false;

            foreach (var arg in args)
            {
                if (arg.Equals("/S", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("--silent", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("-s", StringComparison.OrdinalIgnoreCase))
                {
                    isSilent = true;
                }
                else if (arg.Equals("--launch", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("/L", StringComparison.OrdinalIgnoreCase))
                {
                    launchAfter = true;
                }
            }

            try
            {
                if (!isSilent)
                {
                    var result = MessageBox.Show(
                        string.Format("Welcome to the setup wizard for {0} v{1}.\n\nDo you want to install this application to your system?", AppName, AppVersion),
                        AppName + " Setup",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Information);

                    if (result != DialogResult.Yes)
                    {
                        return 2; // User cancelled
                    }
                }

                // Default install target: %LOCALAPPDATA%\Programs\Privex
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string installDir = Path.Combine(localAppData, "Programs", "Privex");

                // If running instance exists, attempt graceful termination or prompt
                Process[] existingProcesses = Process.GetProcessesByName("PrivateProtection");
                foreach (var p in existingProcesses)
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                }

                if (!Directory.Exists(installDir))
                {
                    Directory.CreateDirectory(installDir);
                }

                // Extract embedded payload.zip resource
                Assembly asm = Assembly.GetExecutingAssembly();
                string resourceName = null;
                foreach (var name in asm.GetManifestResourceNames())
                {
                    if (name.EndsWith("payload.zip", StringComparison.OrdinalIgnoreCase))
                    {
                        resourceName = name;
                        break;
                    }
                }

                if (string.IsNullOrEmpty(resourceName))
                {
                    throw new InvalidOperationException("Embedded payload.zip was not found in installer binary.");
                }

                using (Stream stream = asm.GetManifestResourceStream(resourceName))
                {
                    if (stream == null)
                    {
                        throw new InvalidOperationException("Unable to read embedded payload stream.");
                    }

                    using (ZipArchive archive = new ZipArchive(stream, ZipArchiveMode.Read))
                    {
                        foreach (ZipArchiveEntry entry in archive.Entries)
                        {
                            string targetPath = Path.Combine(installDir, entry.FullName);
                            if (string.IsNullOrEmpty(entry.Name))
                            {
                                // Directory
                                Directory.CreateDirectory(targetPath);
                            }
                            else
                            {
                                Directory.CreateDirectory(Path.GetDirectoryName(targetPath));
                                entry.ExtractToFile(targetPath, true);
                            }
                        }
                    }
                }

                // Extract embedded uninstaller if embedded, or deploy standalone uninstaller
                string uninstallerResource = null;
                foreach (var name in asm.GetManifestResourceNames())
                {
                    if (name.EndsWith("uninstaller.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        uninstallerResource = name;
                        break;
                    }
                }

                string uninstallExePath = Path.Combine(installDir, UninstallExeName);
                if (!string.IsNullOrEmpty(uninstallerResource))
                {
                    using (Stream uStream = asm.GetManifestResourceStream(uninstallerResource))
                    using (FileStream fs = new FileStream(uninstallExePath, FileMode.Create, FileAccess.Write))
                    {
                        uStream.CopyTo(fs);
                    }
                }

                // Grant AppContainer package SID read & execute access for Chromium sandboxed processes
                try
                {
                    Process aclProc = Process.Start(new ProcessStartInfo
                    {
                        FileName = "icacls.exe",
                        Arguments = string.Format("\"{0}\" /grant *S-1-15-2-1:(OI)(CI)(RX) /T /Q", installDir),
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    });
                    if (aclProc != null)
                    {
                        aclProc.WaitForExit(5000);
                    }
                }
                catch (Exception aclEx)
                {
                    Console.Error.WriteLine("Warning: ACL adjustment skipped: " + aclEx.Message);
                }

                string mainExePath = Path.Combine(installDir, ExeName);

                // Create Windows Shortcuts
                CreateShortcuts(installDir, mainExePath);

                // Register in Windows Registry (Add/Remove Programs)
                RegisterUninstall(installDir, mainExePath, uninstallExePath);

                if (!isSilent)
                {
                    var launchResult = MessageBox.Show(
                        string.Format("{0} v{1} has been successfully installed!\n\nWould you like to launch the application now?", AppName, AppVersion),
                        AppName + " Setup Complete",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Information);

                    if (launchResult == DialogResult.Yes)
                    {
                        launchAfter = true;
                    }
                }

                if (launchAfter && File.Exists(mainExePath))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = mainExePath,
                        WorkingDirectory = installDir
                    });
                }

                return 0; // Success
            }
            catch (Exception ex)
            {
                if (!isSilent)
                {
                    MessageBox.Show(
                        "An error occurred during installation:\n\n" + ex.Message,
                        AppName + " Setup Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
                Console.Error.WriteLine("INSTALLER_ERROR: " + ex);
                return 1;
            }
        }

        private static void CreateShortcuts(string installDir, string targetExePath)
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) return;

                dynamic shell = Activator.CreateInstance(shellType);

                // 1. Start Menu Shortcut
                string startMenuDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Privex");
                Directory.CreateDirectory(startMenuDir);
                string startMenuLink = Path.Combine(startMenuDir, "Privex.lnk");

                dynamic smShortcut = shell.CreateShortcut(startMenuLink);
                smShortcut.TargetPath = targetExePath;
                smShortcut.WorkingDirectory = installDir;
                smShortcut.Description = "Privex Desktop Security";
                smShortcut.Save();

                // 2. Desktop Shortcut
                string desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                string desktopLink = Path.Combine(desktopDir, "Privex.lnk");

                dynamic dtShortcut = shell.CreateShortcut(desktopLink);
                dtShortcut.TargetPath = targetExePath;
                dtShortcut.WorkingDirectory = installDir;
                dtShortcut.Description = "Privex Desktop Security";
                dtShortcut.Save();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Warning: Shortcut creation skipped: " + ex.Message);
            }
        }

        private static void RegisterUninstall(string installDir, string mainExePath, string uninstallExePath)
        {
            try
            {
                const string keyPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivateProtection";
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(keyPath))
                {
                    if (key != null)
                    {
                        key.SetValue("DisplayName", AppName);
                        key.SetValue("DisplayVersion", AppVersion);
                        key.SetValue("Publisher", PublisherName);
                        key.SetValue("InstallLocation", installDir);
                        key.SetValue("UninstallString", "\"" + uninstallExePath + "\"");
                        key.SetValue("QuietUninstallString", "\"" + uninstallExePath + "\" /S");
                        key.SetValue("DisplayIcon", "\"" + mainExePath + "\",0");
                        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);

                        long sizeBytes = 0;
                        if (Directory.Exists(installDir))
                        {
                            foreach (var file in Directory.GetFiles(installDir, "*", SearchOption.AllDirectories))
                            {
                                sizeBytes += new FileInfo(file).Length;
                            }
                        }
                        key.SetValue("EstimatedSize", (int)(sizeBytes / 1024), RegistryValueKind.DWord);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Warning: Registry uninstall registration skipped: " + ex.Message);
            }
        }
    }
}
