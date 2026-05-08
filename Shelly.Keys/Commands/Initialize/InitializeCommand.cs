using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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
        ctx.SetEngineInfo(
            GpgmeNative.gpgme_protocol_t.GPGME_PROTOCOL_OpenPGP,
            fileName: null,
            homeDir: settings.Directory);
        var engineErr = GpgmeImports.gpgme_engine_check_version(GpgmeNative.gpgme_protocol_t.GPGME_PROTOCOL_OpenPGP);
        GpgmeHelpers.ThrowIfError(engineErr);

        GpgmeImports.gpgme_op_keylist_start(ctx.Handle, null, 0);
        GpgmeImports.gpgme_op_keylist_end(ctx.Handle);
        AnsiConsole.MarkupLine("[bold green]Gpgme keyring setup complete[/]");

        AnsiConsole.MarkupLine("[bold green]Generating local signing key[/]");

        if (!GpgmeContext.HasSecretKey(ctx))
        {
            var err = GpgmeImports.gpgme_op_createkey(ctx.Handle, "Pacman Keyring Master Key <pacman@localhost>",
                "rsa4096",
                0,
                0,
                IntPtr.Zero,
                GPGME_CREATE_NOPASSWD | GPGME_CREATE_NOEXPIRE);
            GpgmeHelpers.ThrowIfError(err);
        }
        else
        {
            AnsiConsole.MarkupLine("[bold green]Skipping keyring already has a master key[/]");
        }

        var psi = new ProcessStartInfo("gpg")
        {
            ArgumentList =
                { "--homedir", settings.Directory, "--no-permission-warning", "--batch", "--update-trustdb" },
            UseShellExecute = false,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        using var p = Process.Start(psi);
        await p!.WaitForExitAsync();
        AnsiConsole.MarkupLine($"[bold green]{p.StandardError.ReadToEnd()}");
        var exitCode = p.ExitCode;
        if (exitCode != 0)
        {
            AnsiConsole.MarkupLine(
                $"[bold red] Failed to execute gpg trust db update with exitcode {exitCode} [/]");
            return exitCode;
        }


        return 0;
    }
}