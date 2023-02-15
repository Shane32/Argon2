using System.Diagnostics;
using System.Text;

namespace Shane32.Argon2;

/// <summary>
/// Provides a set of functions for hashing passwords using the Argon2 algorithm into a composite string
/// containing the hash parameters, salt and hash.
/// </summary>
public static class Argon2Library
{
    /// <summary>
    /// Returns a set of Argon2 parameters which are appropriate for the given time and parallelism requirements.
    /// The expected amount of time to execute this method is approximately double <paramref name="minTime"/>.
    /// </summary>
    /// <param name="parallelism">The number of lanes to use while processing the hash.</param>
    /// <param name="hashLengthBits">The length of the hash, in bits.</param>
    /// <param name="minTime">The minimum of time required to encode or validate the hash.</param>
    public static async Task<Argon2Parameters> SelectParametersAsync(int parallelism, int hashLengthBits, TimeSpan minTime)
    {
        if (minTime < TimeSpan.Zero)
            throw new ArgumentException("Minimum time cannot be negative.", nameof(minTime));

        int i = 0;
        while (true) {
            var timer = Stopwatch.StartNew();
            var parameters = new Argon2Parameters(parallelism, 1 << i, 1 << (i + 12), hashLengthBits);
            await HashAsync(parameters, "hello_testing");
            if (timer.Elapsed > minTime)
                return parameters;
            timer.Restart();
            parameters = new Argon2Parameters(parallelism, 1 << (i + 1), 1 << (i + 12), hashLengthBits);
            await HashAsync(parameters, "hello_testing");
            if (timer.Elapsed > minTime)
                return parameters;
            i++;
        }
    }

    /// <summary>
    /// Hashes a password using the Argon2 algorithm with the given parameters.
    /// The returned hash starts with <c>$a2id$</c> and includes the parameters and salt used to create it.
    /// </summary>
    public static async Task<string> HashAsync(Argon2Parameters parameters, string password)
    {
        var iterationsPow = (int)Math.Log(parameters.Iterations, 2);
        var memorySizePow = (int)Math.Log(parameters.MemorySizeKb, 2);

        var salt = new byte[parameters.HashLengthBits >> 3];
        using (var crypto = System.Security.Cryptography.RandomNumberGenerator.Create())
            crypto.GetBytes(salt);
        var saltStr = Convert.ToBase64String(salt);
        var dataBytes = Encoding.Unicode.GetBytes(password);
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(dataBytes);
        argon2.DegreeOfParallelism = parameters.Parallelism;
        argon2.Salt = salt;
        argon2.Iterations = parameters.Iterations;
        argon2.MemorySize = parameters.MemorySizeKb;
        var hash = await argon2.GetBytesAsync(parameters.HashLengthBits >> 3);
        var hashStr = Convert.ToBase64String(hash);
        return $"$a2id${parameters.Parallelism}${iterationsPow}${memorySizePow}${saltStr}${hashStr}";
    }

    /// <summary>
    /// Validates a password against a hash encoded using the Argon2 algorithm.
    /// Returns <see langword="true"/> if the password matches the hash.
    /// An exception is thrown if the hash is not in the correct format.
    /// </summary>
    /// <param name="hash">The encoded hash, as returned by <see cref="HashAsync(Argon2Parameters, string)"/>.</param>
    /// <param name="password">The password to validate.</param>
    /// <exception cref="FormatException"></exception>
    public static async Task<bool> VerifyAsync(string hash, string password)
    {
        var parts = hash.Split('$');
        if (parts.Length != 7)
            throw new FormatException("Hash is not in the correct format");
        if (parts[0] != "")
            throw new FormatException("Hash is not in the correct format");
        if (parts[1] != "a2id")
            throw new FormatException("Hash is not in the correct format");
        if (!int.TryParse(parts[2], out var parallelism))
            throw new FormatException("Hash is not in the correct format");
        if (!int.TryParse(parts[3], out var iterationsPow))
            throw new FormatException("Hash is not in the correct format");
        if (!int.TryParse(parts[4], out var memorySizePow))
            throw new FormatException("Hash is not in the correct format");

        var salt = Convert.FromBase64String(parts[5]);
        var hashBytes = Convert.FromBase64String(parts[6]);
        var dataBytes = Encoding.Unicode.GetBytes(password);
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(dataBytes);
        argon2.DegreeOfParallelism = parallelism;
        argon2.Salt = salt;
        argon2.Iterations = 1 << iterationsPow;
        argon2.MemorySize = 1 << memorySizePow;
        var computedHash = await argon2.GetBytesAsync(hashBytes.Length);
        return hashBytes.SequenceEqual(computedHash);
    }

    /// <summary>
    /// Returns <see langword="true"/> if the given hash was encoded using the Argon2 algorithm
    /// by checking if the hash prefix is <c>$a2id$</c>.
    /// </summary>
    public static bool IsArgon2Hash(string hash)
        => hash.StartsWith("$a2id$", StringComparison.Ordinal);
}
