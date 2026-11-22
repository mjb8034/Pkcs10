using System.Buffers;
using System.Text;

namespace Pkcs10.Security.Cryptography.Pem;

/// <summary>
/// Represents a decoded Privacy-Enhanced Mail (PEM) block.
/// </summary>
/// <param name="Label">
/// The label from the PEM BEGIN and END boundaries, such as
/// <c>CERTIFICATE</c>, <c>CERTIFICATE REQUEST</c>, or
/// <c>PRIVATE KEY</c>.
/// </param>
/// <param name="Data">
/// The binary data obtained by Base64-decoding the contents of the PEM block.
/// </param>
/// <param name="BeginLine">
/// The one-based line number containing the BEGIN boundary.
/// </param>
/// <param name="EndLine">
/// The one-based line number containing the matching END boundary.
/// </param>
public sealed record PemBlock(
    string Label,
    ReadOnlyMemory<byte> Data,
    long BeginLine,
    long EndLine);

/// <summary>
/// Provides methods for detecting and parsing Privacy-Enhanced Mail (PEM)
/// encoded data from streams and text readers.
/// </summary>
/// <remarks>
/// <para>
/// The parser recognizes PEM blocks delimited by matching
/// <c>-----BEGIN label-----</c> and <c>-----END label-----</c>
/// boundaries and returns the Base64-decoded contents as
/// <see cref="PemBlock"/> instances.
/// </para>
/// <para>
/// Text outside PEM blocks is ignored. This permits PEM objects to be read
/// from files that contain surrounding descriptive text, such as OpenSSL
/// bag attributes, subject or issuer descriptions, comments, or other
/// non-PEM content.
/// </para>
/// <para>
/// After a BEGIN boundary is encountered, the corresponding PEM block is
/// validated until its matching END boundary is encountered. Malformed
/// boundaries, mismatched labels, nested BEGIN boundaries, invalid Base64
/// data, oversized blocks, and unterminated blocks cause a
/// <see cref="FormatException"/>.
/// </para>
/// <para>
/// Multiple PEM blocks may be present in the same input.
/// </para>
/// </remarks>
public static class PemParser
{
    private const string BeginPrefix = "-----BEGIN ";
    private const string EndPrefix = "-----END ";
    private const string BoundarySuffix = "-----";

    /// <summary>
    /// Specifies the default maximum number of Base64 characters permitted
    /// in a single PEM block.
    /// </summary>
    /// <value>
    /// 16,777,216 characters (16 Mi characters).
    /// </value>
    /// <remarks>
    /// The limit prevents unbounded accumulation of PEM payload data while
    /// parsing. A different limit may be supplied to the parsing methods.
    /// </remarks>
    public const int DefaultMaximumBlockCharacters = 16 * 1024 * 1024;

    /// <summary>
    /// Specifies the default maximum number of characters permitted in a
    /// PEM label.
    /// </summary>
    /// <value>128 characters.</value>
    public const int DefaultMaximumLabelLength = 128;

    private sealed class ParserState
    {
        public string? Label;
        public StringBuilder? Base64;

        public long LineNumber;
        public long BeginLine;
    }

    /// <summary>
    /// Determines whether a readable, seekable stream contains a PEM BEGIN
    /// marker within a bounded number of bytes from the stream's current
    /// position.
    /// </summary>
    /// <param name="stream">
    /// The stream to examine.
    /// </param>
    /// <param name="maximumProbeLength">
    /// The maximum number of bytes to examine. The default is 65,536 bytes.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the byte sequence
    /// <c>-----BEGIN </c> is found within the examined portion of the
    /// stream; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method is a lightweight probe. Finding the BEGIN marker does
    /// not guarantee that the stream contains a complete or valid PEM
    /// block. Use <see cref="Parse(Stream, Encoding?, bool, int, int)"/>
    /// to validate and decode the PEM data.
    /// </para>
    /// <para>
    /// The stream position is restored to its original value before this
    /// method returns, including when an exception occurs.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="stream"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="stream"/> is not readable.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// <paramref name="stream"/> does not support seeking.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maximumProbeLength"/> is less than or equal to zero.
    /// </exception>
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

    /// <summary>
    /// Parses all PEM blocks from a readable stream.
    /// </summary>
    /// <param name="stream">
    /// The stream containing PEM-encoded text.
    /// </param>
    /// <param name="encoding">
    /// The text encoding used to read the stream. If
    /// <see langword="null"/>, UTF-8 is used. Byte-order marks are detected
    /// by the underlying <see cref="StreamReader"/>.
    /// </param>
    /// <param name="leaveOpen">
    /// <see langword="true"/> to leave <paramref name="stream"/> open after
    /// parsing; <see langword="false"/> to dispose it.
    /// </param>
    /// <param name="maximumBlockCharacters">
    /// The maximum number of Base64 characters permitted in a single PEM
    /// block.
    /// </param>
    /// <param name="maximumLabelLength">
    /// The maximum number of characters permitted in a PEM label.
    /// </param>
    /// <returns>
    /// A read-only list containing the decoded PEM blocks in the order in
    /// which they occur in the input. The list is empty when no PEM blocks
    /// are present.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="stream"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="stream"/> is not readable.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maximumBlockCharacters"/> or
    /// <paramref name="maximumLabelLength"/> is less than or equal to zero.
    /// </exception>
    /// <exception cref="FormatException">
    /// The input contains a malformed PEM boundary, mismatched BEGIN and
    /// END labels, a nested BEGIN boundary, an empty or oversized PEM
    /// payload, invalid Base64 data, or a PEM block without a matching END
    /// boundary.
    /// </exception>
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

    /// <summary>
    /// Parses all PEM blocks from a text reader.
    /// </summary>
    /// <param name="reader">
    /// The text reader containing PEM-encoded text.
    /// </param>
    /// <param name="maximumBlockCharacters">
    /// The maximum number of Base64 characters permitted in a single PEM
    /// block.
    /// </param>
    /// <param name="maximumLabelLength">
    /// The maximum number of characters permitted in a PEM label.
    /// </param>
    /// <returns>
    /// A read-only list containing the decoded PEM blocks in input order.
    /// The list is empty when no PEM blocks are present.
    /// </returns>
    /// <remarks>
    /// This method does not dispose <paramref name="reader"/>. The caller
    /// retains ownership of the reader.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="reader"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maximumBlockCharacters"/> or
    /// <paramref name="maximumLabelLength"/> is less than or equal to zero.
    /// </exception>
    /// <exception cref="FormatException">
    /// The input contains a malformed PEM boundary, mismatched BEGIN and
    /// END labels, a nested BEGIN boundary, an empty or oversized PEM
    /// payload, invalid Base64 data, or a PEM block without a matching END
    /// boundary.
    /// </exception>
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

    /// <summary>
    /// Asynchronously parses all PEM blocks from a readable stream.
    /// </summary>
    /// <param name="stream">
    /// The stream containing PEM-encoded text.
    /// </param>
    /// <param name="encoding">
    /// The text encoding used to read the stream. If
    /// <see langword="null"/>, UTF-8 is used. Byte-order marks are detected
    /// by the underlying <see cref="StreamReader"/>.
    /// </param>
    /// <param name="leaveOpen">
    /// <see langword="true"/> to leave <paramref name="stream"/> open after
    /// parsing; <see langword="false"/> to dispose it.
    /// </param>
    /// <param name="maximumBlockCharacters">
    /// The maximum number of Base64 characters permitted in a single PEM
    /// block.
    /// </param>
    /// <param name="maximumLabelLength">
    /// The maximum number of characters permitted in a PEM label.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// A task whose result is a read-only list containing the decoded PEM
    /// blocks in input order. The list is empty when no PEM blocks are
    /// present.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="stream"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="stream"/> is not readable.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maximumBlockCharacters"/> or
    /// <paramref name="maximumLabelLength"/> is less than or equal to zero.
    /// </exception>
    /// <exception cref="FormatException">
    /// The input contains invalid PEM data.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// The operation is canceled through
    /// <paramref name="cancellationToken"/>.
    /// </exception>
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

    /// <summary>
    /// Asynchronously parses all PEM blocks from a text reader.
    /// </summary>
    /// <param name="reader">
    /// The text reader containing PEM-encoded text.
    /// </param>
    /// <param name="maximumBlockCharacters">
    /// The maximum number of Base64 characters permitted in a single PEM
    /// block.
    /// </param>
    /// <param name="maximumLabelLength">
    /// The maximum number of characters permitted in a PEM label.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// A task whose result is a read-only list containing the decoded PEM
    /// blocks in input order. The list is empty when no PEM blocks are
    /// present.
    /// </returns>
    /// <remarks>
    /// This method does not dispose <paramref name="reader"/>. The caller
    /// retains ownership of the reader.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="reader"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="maximumBlockCharacters"/> or
    /// <paramref name="maximumLabelLength"/> is less than or equal to zero.
    /// </exception>
    /// <exception cref="FormatException">
    /// The input contains invalid PEM data.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// The operation is canceled through
    /// <paramref name="cancellationToken"/>.
    /// </exception>
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

            if (!String.Equals(
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
        label = String.Empty;
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