using System;
using System.IO;
using System.Diagnostics;
using Microsoft.Win32;
using System.Windows.Forms;

namespace PrivateProtection.Uninstaller
{
    static class Program
    {
        private const string AppName = "Privex Desktop Security";

        [STAThread]
        static int Main(string[] args)
        {
            bool isSilent = false;

            foreach (var arg in args)
            {
                if (arg.Equals("/S", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("--silent", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("-s", StringComparison.OrdinalIgnoreCase))
                {
                    isSilent = true;
                }
            }

            try
            {
                if (!isSilent)
                {
                    var result = MessageBox.Show(
                        string.Format("Are you sure you want to completely remove {0} from your computer?", AppName),
                        AppName + " Uninstall",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Question);

                    if (result != DialogResult.Yes)
                    {
                        return 2; // User cancelled
                    }
                }

                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string installDir = Path.Combine(localAppData, "Programs", "Privex");

                // 1. Terminate any running instances of PrivateProtection
                Process[] existingProcesses = Process.GetProcessesByName("PrivateProtection");
                foreach (var p in existingProcesses)
                {
                    try { p.Kill(); p.WaitForExit(3000); } catch { }
                }

                // 2. Remove Windows Registry Uninstall key
                try
                {
                    Registry.CurrentUser.DeleteSubKeyTree(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\PrivateProtection", false);
                }
                catch (Exception regEx)
                {
                    Console.Error.WriteLine("Warning: Registry cleanup failed: " + regEx.Message);
                }

                // 3. Remove Start Menu Shortcut
                try
                {
                    string startMenuDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Privex");
                    if (Directory.Exists(startMenuDir))
                    {
                        Directory.Delete(startMenuDir, true);
                    }
                }
                catch (Exception smEx)
                {
                    Console.Error.WriteLine("Warning: Start menu cleanup failed: " + smEx.Message);
                }

                // 4. Remove Desktop Shortcut
                try
                {
                    string desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                    string desktopLink = Path.Combine(desktopDir, "Privex.lnk");
                    if (File.Exists(desktopLink))
                    {
                        File.Delete(desktopLink);
                    }
                }
                catch (Exception dtEx)
                {
                    Console.Error.WriteLine("Warning: Desktop shortcut cleanup failed: " + dtEx.Message);
                }

                // 5. Delete install directory via background cmd delayed deletion
                if (Directory.Exists(installDir))
                {
                    string cmdArgs = string.Format("/C timeout /t 2 /nobreak > nul & rmdir /S /Q \"{0}\"", installDir);
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = "cmd.exe",
                        Arguments = cmdArgs,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden,
                        UseShellExecute = true
                    });
                }

                if (!isSilent)
                {
                    MessageBox.Show(
                        string.Format("{0} was successfully uninstalled from your computer.", AppName),
                        AppName + " Uninstall Complete",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }

                return 0; // Success
            }
            catch (Exception ex)
            {
                if (!isSilent)
                {
                    MessageBox.Show(
                        "An error occurred during uninstallation:\n\n" + ex.Message,
                        AppName + " Uninstall Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                }
                Console.Error.WriteLine("UNINSTALL_ERROR: " + ex);
                return 1;
            }
        }
    }
}
