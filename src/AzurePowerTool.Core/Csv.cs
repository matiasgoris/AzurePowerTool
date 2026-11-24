using System.Text;

namespace AzurePowerTool.Core;

public static class Csv
{
    /// <summary>Semicolon-separated (opens correctly in Excel with Dutch/Belgian regional settings), UTF-8 with BOM.</summary>
    public static string Build(IEnumerable<string> headers, IEnumerable<IEnumerable<string?>> rows, char separator = ';')
    {
        var sb = new StringBuilder("﻿");
        sb.AppendLine(string.Join(separator, headers.Select(h => Escape(h, separator))));
        foreach (var row in rows)
        {
            sb.AppendLine(string.Join(separator, row.Select(v => Escape(v, separator))));
        }
        return sb.ToString();
    }

    private static string Escape(string? value, char separator)
    {
        value ??= "";
        return value.IndexOfAny([separator, '"', '\n', '\r']) >= 0
            ? $"\"{value.Replace("\"", "\"\"")}\""
            : value;
    }
}
