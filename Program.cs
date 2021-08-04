using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace DiscordVirusScanner
{
    class Program
    {
        public struct discordVersion
        {
            public discordVersion(string name, string exeFileName)
            {
                this.Name = name;
                this.ExeFileName = exeFileName;
                this.ExePath = "";
                this.versionNumber = "";
            }
            public string Name;
            public string ExeFileName;
            public string ExePath;

            public string versionNumber;
        };
        private static readonly string[] _expectedDomains =
        {
            "localhost",
            "sentry.io",
            "1.2.3.4",
            "if(url.indexof('http')!="
        };
        public static discordVersion[] DiscordVersions =
        {
            new discordVersion("DiscordPTB", "DiscordPTB.exe"),
            new discordVersion("Discord", "Discord.exe")
        };
        
        static void SetupDiscordVersions()
        {
            Console.WriteLine("Setting up discord versions!");
            var localAppDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"/../local/";

            var folderPaths = Directory.GetDirectories(localAppDataPath, "Discord*", SearchOption.TopDirectoryOnly);

            var cnt = 0;
            foreach (var discordVersion in DiscordVersions)
            {
                Console.WriteLine("Checking for " + discordVersion.Name);

                foreach (var folderPath in folderPaths)
                {
                    DirectoryInfo curDir = new DirectoryInfo(folderPath);
                    if (curDir.Name.ToLower() != discordVersion.Name.ToLower())
                    {
                        continue;
                    }
                    // Now find the discord version
                    Regex reg = new Regex("app-");
                    string[] folders = Directory.GetDirectories(folderPath, "*", SearchOption.TopDirectoryOnly);
                    foreach (var folder in folders)
                    {
                        if (reg.IsMatch(folder))
                        {
                            var size = folder.Split("app-").Length;
                            DiscordVersions[cnt].versionNumber = folder.Split("app-")[size - 1];
                            Console.WriteLine("Found " + discordVersion.Name + " version: " + DiscordVersions[cnt].versionNumber);
                            var finalPath = folder + @"/" + discordVersion.ExeFileName;
                            Console.WriteLine("FinalPath: " + finalPath);
                            DiscordVersions[cnt].ExePath = finalPath;
                            break;
                        }
                    }
                }

                cnt = cnt + 1;
            }

        }
        static bool ProcessVersions()
        {
            foreach (var discordVersion in DiscordVersions)
            {
                if (!ProcessDiscordDir(discordVersion))
                {
                    Console.WriteLine("Potential virus found in " + discordVersion.Name + " checking!");
                    Console.WriteLine("Version info.");
                    Console.WriteLine("Discord Name: " + discordVersion.Name);
                    Console.WriteLine("Discord Version: " + discordVersion.versionNumber);
                    Console.WriteLine("Discord ExeFileName: " + discordVersion.ExeFileName);
                    Console.WriteLine("Discord ExePath: " + discordVersion.ExePath);
                    return false;
                }
            }

            return true;
        }
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            SetupDiscordVersions();
            
            
            if (!ProcessVersions())
            {
                Console.WriteLine("Stopped!");
                return;
            }
            
            Console.WriteLine("----------------------------------");
            Console.WriteLine("Safely starting all DiscordVersions!");

            foreach (var discordVersion in DiscordVersions)
            {
                Console.WriteLine("Trying to start " + discordVersion.Name + ".");
                if (File.Exists(discordVersion.ExePath))
                {
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = discordVersion.ExePath,
                            Arguments = "",
                            UseShellExecute = false,
                            RedirectStandardOutput = false,
                            CreateNoWindow = false,
                        }
                    };
                    process.Start();
                    Console.WriteLine("Success.");
                }
                else
                {
                    Console.WriteLine("Broken install.");
                }

            } 
            Environment.Exit(0);
        }


        
        static void CloseRunningProcessByName(string processName)
        {
            Console.WriteLine("Checking if " + processName + " is running.");
            var processes = Process.GetProcesses();
            foreach (var p in processes)
            {
                var tmp = p.ProcessName.ToLower();
                if (tmp == processName || tmp == processName + ".exe")
                {
                    Console.WriteLine("Found " + processName);
                    Console.WriteLine("Killing " + p.ProcessName);
                    p.Kill(true);
                    Console.WriteLine("Killed " + p.ProcessName);
                    return;
                }
            }
        }
        static bool CheckUrls(string currentLine)
        {
            if (currentLine.Contains("http://") || currentLine.Contains("https://"))
            {
                if (currentLine.Contains('"' + "http://") ||
                    currentLine.Contains('"' + "https://") ||
                    currentLine.Contains("'http://") ||
                    currentLine.Contains("'https://")
                )
                {
                    bool safe = false;
                    foreach (var expectedDomain in _expectedDomains)
                    {
                        if (currentLine.Contains(expectedDomain))
                        {
                            safe = true;
                            break;
                        }
                    }

                    if (!safe)
                    {
                        Console.WriteLine("Used URL: " + currentLine);
                        return false;
                    }
                }
            }
            return true;
        }
        static bool ProcessDiscordDir(discordVersion discordVersion_T)
        {
            CloseRunningProcessByName(discordVersion_T.ExeFileName);
            Console.WriteLine("----------------------------------");
            Console.WriteLine("Scanning " + discordVersion_T.Name + " files...");

            FileInfo discordPTBExeInfo = new FileInfo(discordVersion_T.ExePath);
            
            var discordDirectory = discordPTBExeInfo.Directory;
            string[] jsFiles = Directory.GetFiles(discordDirectory.FullName, "*.js", SearchOption.AllDirectories);

            foreach (var fsFile in jsFiles)
            {
                FileInfo fileInfo = new FileInfo(fsFile);
                string[] arrLines = File.ReadAllLines(fileInfo.FullName);
                for(var i = 0; i < arrLines.Length; i++)
                {
                    string currentLine = arrLines[i];

                    // Skip useless lines!
                    if(currentLine == "" || currentLine.StartsWith("//")) continue;
                    
                    // Process the line so its easier to handle
                    currentLine = currentLine.ToLower().Replace(" ", "");
                    
                    // If the line contains a url scan it.
                    if (!CheckUrls(currentLine))
                    {
                        // Failed check
                        Console.WriteLine("Failed URL Check");
                        return false;
                    }
                    
                    // Check for discord webhooks commonly used by token grabbers.
                    if (currentLine.ToLower().Contains("webhook"))
                    {
                        Console.WriteLine("Infected file detected (" + fileInfo.Name + "), code : ");
                        Console.WriteLine(currentLine);
                        return false;
                    }
                }
            }

            return true;
        }
    }
}