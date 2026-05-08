using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Shelly.Keys.Gpg;
using Shelly.Keys.Gpgme;
using Shelly.Keys.Gpgme.Interop;
using Spectre.Console;
using Spectre.Console.Cli;
using static System.IO.UnixFileMode;

namespace Shelly.Keys.Commands.Initialize;

[SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
public class InitializeCommand : AsyncCommand<Settings>
{
    private const string GpgConf = """
                                   no-greeting
                                   no-permission-warning
                                   keyserver-options timeout=10
                                   keyserver-options import-clean
                                   keyserver-options no-self-sigs-only
                                   """;

    private const uint GPGME_CREATE_NOPASSWD = 128;
    private const uint GPGME_CREATE_NOEXPIRE = 256;

    private const UnixFileMode FilePermissions = UserRead | UserWrite | GroupRead | OtherRead;

    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings)
    {
        RootElevator.EnsureRootExectuion();

        AnsiConsole.MarkupLine("[bold green]Initializing keyring[/]");
        AnsiConsole.MarkupLine("[bold green]This may take a while[/]");
        AnsiConsole.MarkupLine("[bold green]Please be patient[/]");

        //Creation with mode 0700
        Directory.CreateDirectory(settings.Directory, FilePermissions | UserExecute);


        AnsiConsole.MarkupLine("[bold green]Setting up and Verifying gpg configuration[/]");

        var gpgConfiguration = new FileInfo(Path.Combine(settings.Directory, "gpg.conf"));
        if (!gpgConfiguration.Exists)
        {
            await gpgConfiguration.Create().DisposeAsync();
        }

        if (gpgConfiguration.UnixFileMode != FilePermissions)
        {
            gpgConfiguration.UnixFileMode = FilePermissions;
            gpgConfiguration.Refresh();
        }

        // Check if empty
        long size;
        await using (var read = gpgConfiguration.OpenRead())
            size = read.Length;

        if (size == 0)
        {
            await File.WriteAllTextAsync(gpgConfiguration.FullName, GpgConf);
            File.SetUnixFileMode(gpgConfiguration.FullName, FilePermissions);
        }

        AnsiConsole.MarkupLine("[bold green]GPG configuration set up[/]");
        AnsiConsole.MarkupLine("[bold green]Starting Gpgme keyring setup[/]");

        var gpgAgentConf = new FileInfo(Path.Combine(settings.Directory, "gpg-agent.conf"));
        if (!gpgAgentConf.Exists)
        {
            var fileStream = gpgAgentConf.CreateText();
            await fileStream.WriteLineAsync("disable-scdaemon");
            fileStream.Close();
            File.SetUnixFileMode(gpgAgentConf.FullName, FilePermissions);
        }

        using var ctx = new GpgmeContext();
        if (ctx.Handle.IsInvalid)
        {
            throw new InvalidOperationException("gpgme_new returned an invalid handle");
        }

        ctx.SetEngineInfo(
            GpgmeNative.gpgme_protocol_t.GPGME_PROTOCOL_OpenPGP,
            fileName: null,
            homeDir: settings.Directory);
        AnsiConsole.MarkupLine("[bold green]Gpgme engine set up![/]");
        var engineErr = GpgmeImports.gpgme_engine_check_version(GpgmeNative.gpgme_protocol_t.GPGME_PROTOCOL_OpenPGP);
        GpgmeHelpers.ThrowIfErrorString(engineErr);

        var startError = GpgmeImports.gpgme_op_keylist_start(ctx.Handle, IntPtr.Zero, 0);
        GpgmeHelpers.ThrowIfErrorString(startError);
        var endErr = GpgmeImports.gpgme_op_keylist_end(ctx.Handle);
        GpgmeHelpers.ThrowIfErrorString(endErr);

        AnsiConsole.MarkupLine("[bold green]Gpgme keyring setup complete[/]");

        AnsiConsole.MarkupLine("[bold green]Generating local signing key[/]");

        string fpr;
        bool hasKey = false;
        if (!GpgmeContext.HasSecretKey(ctx))
        {
            var err = GpgmeImports.gpgme_op_createkey(ctx.Handle, "Pacman Keyring Master Key <pacman@localhost>",
                "rsa4096",
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                GPGME_CREATE_NOPASSWD | GPGME_CREATE_NOEXPIRE);
            if (err != 0) throw new InvalidOperationException($"createkey: 0x{err:X8}");
            GpgmeHelpers.ThrowIfErrorString(err);
            var resultPtr = GpgmeImports.gpgme_op_genkey_result(ctx.Handle);
            var result = Marshal.PtrToStructure<GpgmeNative.GpgmeGenkeyResult>(resultPtr);
            fpr = Marshal.PtrToStringUTF8(result.fpr)
                  ?? throw new InvalidOperationException("genkey result has no fingerprint");
        }
        else
        {
            AnsiConsole.MarkupLine("[bold green]Skipping keyring already has a master key[/]");
            fpr = await GpgHelpers.GetMasterFingerprintAsync(settings.Directory);
            hasKey = true;
        }

        List<string> argList = [];
        if (hasKey)
        {
            
        }
        var psi = new ProcessStartInfo("gpg")
        {
            
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            RedirectStandardInput = true,
        };
        if (!hasKey)
        {
            psi.ArgumentList.Add("--homedir");
            psi.ArgumentList.Add(settings.Directory);
            psi.ArgumentList.Add("--no-permission-warning");
            psi.ArgumentList.Add("--batch");
            psi.ArgumentList.Add("--update-trustdb");
        }
        else
        {
            psi.ArgumentList.Add("--homedir");
            psi.ArgumentList.Add(settings.Directory);
            psi.ArgumentList.Add("--no-permission-warning");
            psi.ArgumentList.Add("--batch");
            psi.ArgumentList.Add("--check-trustdb");
        }
        using var p = Process.Start(psi);
        var outputError = p!.StandardError.ReadToEndAsync();
        var output = p!.StandardOutput.ReadToEndAsync();
        if (!hasKey)
        {
            await p.StandardInput.WriteLineAsync($"{fpr}:6:");
        }
        p.StandardInput.Close();
        await p!.WaitForExitAsync();
        var stdout = await output;
        var stderr = await outputError;
        AnsiConsole.MarkupLine($"[bold green]{Markup.Escape(stdout.Trim())}[/]");
        AnsiConsole.MarkupLine($"[bold green]{Markup.Escape(stderr.Trim())}[/]");
        var exitCode = p.ExitCode;
        if (exitCode != 0)
        {
            AnsiConsole.MarkupLine(
                $"[bold red] Failed to execute gpg trust db update with exitcode {exitCode} [/]");
            return exitCode;
        }
        AnsiConsole.MarkupLine("[bold green]Trust db updated[/]");
        return 0;

    }
    
    
}