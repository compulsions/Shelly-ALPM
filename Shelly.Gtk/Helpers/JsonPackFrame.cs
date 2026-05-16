using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Shelly.Gtk.Helpers;

/// <summary>
/// JSON wire-frame matching the Shelly-CLI writer side. Decodes <c>[MEMPACK]…[/MEMPACK]</c>
/// envelopes whose payload is base64-encoded UTF-8 JSON, deserialized via the
/// <see cref="ShellyGtkJsonContext"/> source-generated context (AOT-safe).
/// </summary>
public static class JsonPackFrame
{
    public const string Prefix = "[JSON]";
    public const string Suffix = "[/JSON]";

    public static bool TryDecode<T>(string output, out T? value)
    {
        value = default;
        if (string.IsNullOrWhiteSpace(output)) return false;

        var pref = output.IndexOf(Prefix, StringComparison.Ordinal);
        if (pref < 0) return false;
        var suff = output.IndexOf(Suffix, pref + Prefix.Length, StringComparison.Ordinal);
        if (suff < 0) return false;
        var payload = output.AsSpan(pref + Prefix.Length, suff - (pref + Prefix.Length));

        try
        {
            var bytes = Convert.FromBase64String(payload.ToString());
            var json = Encoding.UTF8.GetString(bytes);
            var typeInfo = (JsonTypeInfo<T>)ShellyGtkJsonContext.Default.GetTypeInfo(typeof(T))!;
            value = JsonSerializer.Deserialize(json, typeInfo);
            return value is not null;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[MemPackFrame] decode failed: {ex.Message} (len={payload.Length})");
            return false;
        }
    }
}
