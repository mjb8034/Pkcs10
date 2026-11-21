using System.Buffers;
using System.Text;

namespace Pkcs10.Security.Cryptography.Pem;

public sealed record PemBlock(
    string Label,
    ReadOnlyMemory<byte> Data,
    long BeginLine,
    long EndLine);

public static class PemParser
{
    private const string BeginPrefix = "-----BEGIN ";
    private const string EndPrefix = "-----END ";
    private const string BoundarySuffix = "-----";

    public const int DefaultMaximumBlockCharacters = 16 * 1024 * 1024;

    public const int DefaultMaximumLabelLength = 128;

    private sealed class ParserState
    {
        public string? Label;
        public StringBuilder? Base64;

        public long LineNumber;
        public long BeginLine;
    }

    public static bool IsPem(
        Stream stream,
        int maximumProbeLength = 64 * 1024)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (!stream.CanRead)
        {
            throw new ArgumentException(
                "The stream must be readable.",
                nameof(stream));
        }

        if (!stream.CanSeek)
        {
            throw new NotSupportedException(
                "PEM probing requires a seekable stream.");
        }

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumProbeLength);

        ReadOnlySpan<byte> marker = "-----BEGIN "u8;

        long position = stream.Position;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(4096);

        try
        {
            int matched = 0;
            int remaining = maximumProbeLength;

            while (remaining > 0)
            {
                int requested = Math.Min(buffer.Length, remaining);

                int count = stream.Read(buffer, 0, requested);

                if (count == 0)
                    return false;

                remaining -= count;

                for (int i = 0; i < count; i++)
                {
                    byte b = buffer[i];

                    if (b == marker[matched])
                    {
                        matched++;

                        if (matched == marker.Length)
                            return true;
                    }
                    else
                    {
                        /*
                         * Account for a possible new match beginning
                         * with the current byte.
                         */
                        matched = b == marker[0] ? 1 : 0;
                    }
                }
            }

            return false;
        }
        finally
        {
            Array.Clear(
                buffer,
                0,
                buffer.Length);

            ArrayPool<byte>.Shared.Return(buffer);

            stream.Position = position;
        }
    }

    /*
     * Synchronous Stream entry point.
     *
     * The stream is disposed unless leaveOpen is true.
     */
    public static IReadOnlyList<PemBlock> Parse(
        Stream stream,
        Encoding? encoding = null,
        bool leaveOpen = false,
        int maximumBlockCharacters = DefaultMaximumBlockCharacters,
        int maximumLabelLength = DefaultMaximumLabelLength)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (!stream.CanRead)
        {
            throw new ArgumentException(
                "The stream must be readable.",
                nameof(stream));
        }

        ValidateLimits(maximumBlockCharacters, maximumLabelLength);

        encoding ??= Encoding.UTF8;

        using var reader = new StreamReader(
            stream,
            encoding,
            detectEncodingFromByteOrderMarks: true,
            bufferSize: 4096,
            leaveOpen: leaveOpen);

        return Parse(
            reader,
            maximumBlockCharacters,
            maximumLabelLength);
    }

    /*
     * Synchronous TextReader entry point.
     *
     * The caller retains ownership of the TextReader.
     */
    public static IReadOnlyList<PemBlock> Parse(
        TextReader reader,
        int maximumBlockCharacters = DefaultMaximumBlockCharacters,
        int maximumLabelLength = DefaultMaximumLabelLength)
    {
        ArgumentNullException.ThrowIfNull(reader);

        ValidateLimits(maximumBlockCharacters, maximumLabelLength);

        var blocks = new List<PemBlock>();
        var state = new ParserState();

        string? line;

        while ((line = reader.ReadLine()) is not null)
        {
            ProcessLine(
                line,
                state,
                blocks,
                maximumBlockCharacters,
                maximumLabelLength);
        }

        Complete(state);

        return blocks;
    }

    /*
     * Asynchronous Stream entry point.
     *
     * The stream is disposed unless leaveOpen is true.
     */
    public static async Task<IReadOnlyList<PemBlock>> ParseAsync(
        Stream stream,
        Encoding? encoding = null,
        bool leaveOpen = false,
        int maximumBlockCharacters =
            DefaultMaximumBlockCharacters,
        int maximumLabelLength =
            DefaultMaximumLabelLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        if (!stream.CanRead)
        {
            throw new ArgumentException(
                "The stream must be readable.",
                nameof(stream));
        }

        ValidateLimits(
            maximumBlockCharacters,
            maximumLabelLength);

        encoding ??= Encoding.UTF8;

        using var reader = new StreamReader(
            stream,
            encoding,
            detectEncodingFromByteOrderMarks: true,
            bufferSize: 4096,
            leaveOpen: leaveOpen);

        return await ParseAsync(
                reader,
                maximumBlockCharacters,
                maximumLabelLength,
                cancellationToken)
            .ConfigureAwait(false);
    }

    /*
     * Asynchronous TextReader entry point.
     *
     * The caller retains ownership of the TextReader.
     */
    public static async Task<IReadOnlyList<PemBlock>> ParseAsync(
        TextReader reader,
        int maximumBlockCharacters =
            DefaultMaximumBlockCharacters,
        int maximumLabelLength =
            DefaultMaximumLabelLength,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);

        ValidateLimits(
            maximumBlockCharacters,
            maximumLabelLength);

        var blocks = new List<PemBlock>();
        var state = new ParserState();

        while (true)
        {
            string? line = await reader
                .ReadLineAsync(cancellationToken)
                .ConfigureAwait(false);

            if (line is null)
                break;

            ProcessLine(
                line,
                state,
                blocks,
                maximumBlockCharacters,
                maximumLabelLength);
        }

        Complete(state);

        return blocks;
    }

    /*
     * Shared parser state machine.
     *
     * Ordinary text outside PEM blocks is ignored. This includes
     * OpenSSL bag attributes, subject and issuer descriptions,
     * comments, and other surrounding text.
     *
     * Once a BEGIN boundary is encountered, input is validated
     * strictly until the corresponding END boundary.
     */
    private static void ProcessLine(
        string line,
        ParserState state,
        List<PemBlock> blocks,
        int maximumBlockCharacters,
        int maximumLabelLength)
    {
        state.LineNumber++;

        ReadOnlySpan<char> trimmed = line.AsSpan().Trim();

        /*
         * BEGIN boundary.
         */
        if (TryReadBoundary(
                trimmed,
                BeginPrefix,
                maximumLabelLength,
                out string beginLabel,
                out string? beginError))
        {
            if (state.Label is not null)
            {
                throw new FormatException(
                    $"PEM block '{state.Label}' beginning at " +
                    $"line {state.BeginLine} was not closed before " +
                    $"another BEGIN boundary at line " +
                    $"{state.LineNumber}.");
            }

            state.Label = beginLabel;
            state.BeginLine = state.LineNumber;
            state.Base64 = new StringBuilder();

            return;
        }

        /*
         * The line started like a BEGIN boundary but was malformed.
         */
        if (beginError is not null)
        {
            throw new FormatException(
                $"Invalid PEM at line {state.LineNumber}: " +
                beginError);
        }

        /*
         * END boundary.
         */
        if (TryReadBoundary(
                trimmed,
                EndPrefix,
                maximumLabelLength,
                out string endLabel,
                out string? endError))
        {
            if (state.Label is null)
            {
                throw new FormatException(
                    $"END boundary for '{endLabel}' at line " +
                    $"{state.LineNumber} has no corresponding " +
                    "BEGIN boundary.");
            }

            if (!string.Equals(
                    state.Label,
                    endLabel,
                    StringComparison.Ordinal))
            {
                throw new FormatException(
                    $"END label '{endLabel}' at line " +
                    $"{state.LineNumber} does not match BEGIN " +
                    $"label '{state.Label}' at line " +
                    $"{state.BeginLine}.");
            }

            blocks.Add(
                DecodeBlock(
                    state.Label,
                    state.Base64!,
                    state.BeginLine,
                    state.LineNumber));

            Reset(state);

            return;
        }

        /*
         * The line started like an END boundary but was malformed.
         */
        if (endError is not null)
        {
            throw new FormatException(
                $"Invalid PEM at line {state.LineNumber}: " +
                endError);
        }

        /*
         * Ignore ordinary text outside PEM blocks.
         *
         * This intentionally permits input such as:
         *
         *     Bag Attributes
         *         friendlyName: Example
         *     Key Attributes: <No Attributes>
         *     -----BEGIN PRIVATE KEY-----
         *     ...
         *     -----END PRIVATE KEY-----
         */
        if (state.Label is null)
            return;

        /*
         * Empty lines within the body contribute no Base64 data.
         */
        if (trimmed.IsEmpty)
            return;

        /*
         * Prevent unbounded accumulation.
         *
         * The subtraction form avoids an integer overflow that could
         * occur if the two lengths were added first.
         */
        if (trimmed.Length > maximumBlockCharacters ||
            state.Base64!.Length >
                maximumBlockCharacters - trimmed.Length)
        {
            throw new FormatException(
                $"PEM block '{state.Label}' beginning at line " +
                $"{state.BeginLine} exceeds the " +
                $"{maximumBlockCharacters}-character limit.");
        }

        state.Base64.Append(trimmed);
    }

    /*
     * Attempts to interpret a line as a BEGIN or END boundary.
     *
     * Returns:
     *
     *     true
     *         The line is a valid boundary having the requested prefix.
     *
     *     false with error == null
     *         The line does not begin with the requested prefix.
     *
     *     false with error != null
     *         The line begins like the requested boundary but is malformed.
     */
    private static bool TryReadBoundary(
        ReadOnlySpan<char> line,
        string prefix,
        int maximumLabelLength,
        out string label,
        out string? error)
    {
        label = string.Empty;
        error = null;

        ReadOnlySpan<char> prefixSpan =
            prefix.AsSpan();

        if (!line.StartsWith(
                prefixSpan,
                StringComparison.Ordinal))
        {
            return false;
        }

        if (!line.EndsWith(
                BoundarySuffix.AsSpan(),
                StringComparison.Ordinal))
        {
            error =
                $"Malformed PEM boundary: missing trailing " +
                $"'{BoundarySuffix}'.";

            return false;
        }

        int labelLength =
            line.Length -
            prefixSpan.Length -
            BoundarySuffix.Length;

        if (labelLength <= 0)
        {
            error = "Malformed PEM boundary: the label is empty.";

            return false;
        }

        if (labelLength > maximumLabelLength)
        {
            error = $"PEM label exceeds the {maximumLabelLength}-character limit.";

            return false;
        }

        ReadOnlySpan<char> labelSpan =
            line.Slice(
                prefixSpan.Length,
                labelLength);

        if (!IsValidLabel(labelSpan))
        {
            error = "Malformed PEM boundary: the label contains invalid characters.";

            return false;
        }

        label = labelSpan.ToString();

        return true;
    }

    /*
     * Validates labels used by common cryptographic PEM objects.
     *
     * Examples include:
     *
     *     CERTIFICATE
     *     CERTIFICATE REQUEST
     *     NEW CERTIFICATE REQUEST
     *     PUBLIC KEY
     *     PRIVATE KEY
     *     ENCRYPTED PRIVATE KEY
     *     RSA PUBLIC KEY
     *     RSA PRIVATE KEY
     *     EC PRIVATE KEY
     */
    private static bool IsValidLabel(ReadOnlySpan<char> label)
    {
        if (label.IsEmpty ||
            label[0] is ' ' or '-' ||
            label[^1] is ' ' or '-')
        {
            return false;
        }

        char previous = default; // '\0'

        foreach (char ch in label)
        {
            bool valid =
                ch is >= 'A' and <= 'Z' ||
                ch is >= '0' and <= '9' ||
                ch is ' ' or '-';

            if (!valid)
                return false;

            if ((ch == ' ' && previous == ' ') ||
                (ch == '-' && previous == '-'))
            {
                return false;
            }

            previous = ch;
        }

        return true;
    }

    /*
     * Decodes one complete PEM payload.
     */
    private static PemBlock DecodeBlock(
        string label,
        StringBuilder base64,
        long beginLine,
        long endLine)
    {
        if (base64.Length == 0)
        {
            throw new FormatException(
                $"PEM block '{label}' beginning at line " +
                $"{beginLine} contains no Base64 data.");
        }

        int maximumDecodedLength;

        try
        {
            maximumDecodedLength = checked(((base64.Length + 3) / 4) * 3);
        }
        catch (OverflowException ex)
        {
            throw new FormatException(
                $"PEM block '{label}' beginning at line " +
                $"{beginLine} is too large to decode.",
                ex);
        }

        char[] encodedBuffer = ArrayPool<char>.Shared.Rent(base64.Length);

        byte[] decodedBuffer = ArrayPool<byte>.Shared.Rent(maximumDecodedLength);

        try
        {
            base64.CopyTo(
                sourceIndex: 0,
                destination: encodedBuffer,
                destinationIndex: 0,
                count: base64.Length);

            if (!Convert.TryFromBase64Chars(
                    encodedBuffer.AsSpan(
                        0,
                        base64.Length),
                    decodedBuffer,
                    out int bytesWritten))
            {
                throw new FormatException(
                    $"PEM block '{label}' beginning at line " +
                    $"{beginLine} contains invalid Base64 data.");
            }

            byte[] data = decodedBuffer.AsSpan(0, bytesWritten).ToArray();

            return new PemBlock(
                label,
                data,
                beginLine,
                endLine);
        }
        finally
        {
            /*
             * These buffers may contain private-key material.
             *
             * Clear the complete rented arrays before returning
             * them to the shared pools.
             */
            Array.Clear(encodedBuffer, 0, encodedBuffer.Length);

            Array.Clear(decodedBuffer, 0, decodedBuffer.Length);

            ArrayPool<char>.Shared.Return(encodedBuffer);

            ArrayPool<byte>.Shared.Return(decodedBuffer);
        }
    }

    /*
     * Validates parser state at end of input.
     */
    private static void Complete(ParserState state)
    {
        if (state.Label is not null)
        {
            throw new FormatException(
                $"PEM block '{state.Label}' beginning at line " +
                $"{state.BeginLine} is incomplete because the " +
                "input ended before its END boundary.");
        }
    }

    private static void Reset(ParserState state)
    {
        state.Label = null;
        state.Base64 = null;
        state.BeginLine = 0;
    }

    private static void ValidateLimits(int maximumBlockCharacters, int maximumLabelLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumBlockCharacters);

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maximumLabelLength);
    }
}