using System.Diagnostics;
using System.Text;

namespace Shane32.Argon2;

/// <summary>
/// Provides a set of functions for hashing passwords using the Argon2 algorithm into a composite string
/// containing the hash parameters, salt and hash.
/// </summary>
public static class Argon2Library
{
    /// <inheritdoc cref="SelectParametersAsync(int, TimeSpan, int, int, byte[])"/>
    public static Task<Argon2Parameters> SelectParametersAsync(int parallelism, TimeSpan minTime, int hashLengthBits)
        => SelectParametersAsync(parallelism, minTime, hashLengthBits, hashLengthBits);

    /// <summary>
    /// Returns a set of Argon2 parameters which are appropriate for the given time and parallelism requirements.
    /// The expected amount of time to execute this method is approximately double <paramref name="minTime"/>.
    /// </summary>
    /// <param name="parallelism">The number of lanes to use while processing the hash.</param>
    /// <param name="minTime">The minimum of time required to encode or validate the hash.</param>
    /// <param name="hashLengthBits">The length of the hash, in bits.</param>
    /// <param name="saltLengthBits">The length of the salt, in bits.</param>
    /// <param name="knownSecret">An optional secret to be used which creating the hash.</param>
    public static async Task<Argon2Parameters> SelectParametersAsync(int parallelism, TimeSpan minTime, int hashLengthBits, int saltLengthBits, byte[]? knownSecret = null)
    {
        if (minTime < TimeSpan.Zero)
            throw new ArgumentException("Minimum time cannot be negative.", nameof(minTime));

        int i = 0;
        while (true) {
            var timer = Stopwatch.StartNew();
            var parameters = new Argon2Parameters(parallelism, 1 << i, 1 << (i + 12), hashLengthBits, saltLengthBits, knownSecret);
            await HashAsync("hello_testing", parameters);
            if (timer.Elapsed > minTime)
                return parameters;
            timer.Restart();
            parameters = new Argon2Parameters(parallelism, 1 << (i + 1), 1 << (i + 12), hashLengthBits, saltLengthBits, knownSecret);
            await HashAsync("hello_testing", parameters);
            if (timer.Elapsed > minTime)
                return parameters;
            i++;
        }
    }

    /// <summary>
    /// Hashes a password using the Argon2 algorithm with the given parameters.
    /// The returned hash starts with <c>$a2id$</c> and includes the parameters and salt used to create it.
    /// </summary>
    public static async Task<string> HashAsync(string password, Argon2Parameters parameters)
    {
        if (password == null)
            throw new ArgumentNullException(nameof(password));
        if (parameters == null)
            throw new ArgumentNullException(nameof(parameters));

        var iterationsPow = (int)Math.Log(parameters.Iterations, 2);
        var memorySizePow = (int)Math.Log(parameters.MemorySizeKb, 2);

        var salt = new byte[parameters.SaltLengthBits >> 3];
        using (var crypto = System.Security.Cryptography.RandomNumberGenerator.Create())
            crypto.GetBytes(salt);
        var saltStr = Convert.ToBase64String(salt);
        var dataBytes = Encoding.Unicode.GetBytes(password);
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(dataBytes);
        argon2.DegreeOfParallelism = parameters.Parallelism;
        argon2.Salt = salt;
        argon2.Iterations = parameters.Iterations;
        argon2.MemorySize = parameters.MemorySizeKb;
        argon2.KnownSecret = parameters.KnownSecret;
        var hash = await argon2.GetBytesAsync(parameters.HashLengthBits >> 3);
        var hashStr = Convert.ToBase64String(hash);
        return $"$a2id${parameters.Parallelism}${iterationsPow}${memorySizePow}${saltStr}${hashStr}";
    }

    /// <summary>
    /// Validates a password against a hash encoded using the Argon2 algorithm.
    /// Returns <see langword="true"/> if the password matches the hash.
    /// An exception is thrown if the hash is not in the correct format.
    /// </summary>
    /// <param name="hash">The encoded hash, as returned by <see cref="HashAsync(string, Argon2Parameters)"/>.</param>
    /// <param name="password">The password to validate.</param>
    /// <param name="knownSecret">An optional secret to use when calculating the hash.</param>
    /// <exception cref="FormatException"></exception>
    public static async Task<bool> VerifyAsync(string password, string hash, byte[]? knownSecret = null)
    {
        if (password == null)
            throw new ArgumentNullException(nameof(password));
        if (hash == null)
            throw new ArgumentNullException(nameof(hash));

        var (parallelism, iterationsPow, memorySizePow, salt, hashBytes) = Parse(hash, "Hash");
        if (hashBytes == null)
            throw new FormatException("String is not in the correct format");
        var dataBytes = Encoding.Unicode.GetBytes(password);
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(dataBytes);
        argon2.DegreeOfParallelism = parallelism;
        argon2.Salt = salt;
        argon2.Iterations = 1 << iterationsPow;
        argon2.MemorySize = 1 << memorySizePow;
        argon2.KnownSecret = knownSecret;
        var computedHash = await argon2.GetBytesAsync(hashBytes.Length);
        return hashBytes.SequenceEqual(computedHash);
    }

    /// <summary>
    /// Validates a password against a hash encoded using the Argon2 algorithm.
    /// Returns <see langword="true"/> if the password matches the hash.
    /// An exception is thrown if the hash is not in the correct format.
    /// </summary>
    /// <param name="hash">The encoded hash, as returned by <see cref="HashAsync(string, string, int, byte[])"/>.</param>
    /// <param name="password">The password to validate.</param>
    /// <param name="salt">The encoded salt, as returned by <see cref="CreateArgonSalt(Argon2Parameters)"/>.</param>
    /// <param name="knownSecret">An optional secret to use when calculating the hash.</param>
    /// <exception cref="FormatException"></exception>
    public static Task<bool> VerifyAsync(string password, string hash, string salt, byte[]? knownSecret = null)
        => VerifyAsync(password, salt + hash, knownSecret);

    /// <summary>
    /// Returns <see langword="true"/> if the given hash was encoded using the Argon2 algorithm
    /// by checking if the hash prefix is <c>$a2id$</c>.
    /// </summary>
    public static bool IsArgon2Hash(string hash)
        => hash.StartsWith("$a2id$", StringComparison.Ordinal);

    /// <summary>
    /// Returns <see langword="true"/> if the given salt was created for use with the Argon2 algorithm
    /// by checking if the salt starts with <c>$a2id$</c>.
    /// </summary>
    public static bool IsArgon2Salt(string salt)
        => salt.StartsWith("$a2id$", StringComparison.Ordinal);

    /// <summary>
    /// Encodes the given parameters and a salt into a string.
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    public static string CreateArgonSalt(Argon2Parameters parameters)
    {
        if (parameters == null)
            throw new ArgumentNullException(nameof(parameters));

        var iterationsPow = (int)Math.Log(parameters.Iterations, 2);
        var memorySizePow = (int)Math.Log(parameters.MemorySizeKb, 2);

        var salt = new byte[parameters.SaltLengthBits >> 3];
        using (var crypto = System.Security.Cryptography.RandomNumberGenerator.Create())
            crypto.GetBytes(salt);
        var saltStr = Convert.ToBase64String(salt);
        return $"$a2id${parameters.Parallelism}${iterationsPow}${memorySizePow}${saltStr}$";
    }

    /// <summary>
    /// Given a set of parameters and salt encoded within <paramref name="argonSalt"/> and a password,
    /// returns the hash encoded using the Argon2 algorithm.
    /// </summary>
    public static async Task<string> HashAsync(string password, string argonSalt, int hashLengthBits, byte[]? knownSecret = null)
    {
        if (password == null)
            throw new ArgumentNullException(nameof(password));
        if (argonSalt == null)
            throw new ArgumentNullException(nameof(argonSalt));

        if (hashLengthBits % 8 != 0)
            throw new ArgumentOutOfRangeException(nameof(hashLengthBits), "Hash length must be a multiple of 8 bits");
        var (parallelism, iterationsPow, memorySizePow, salt, hash) = Parse(argonSalt, "Salt");
        if (hash != null)
            throw new FormatException("Salt is not in the correct format");
        var dataBytes = Encoding.Unicode.GetBytes(password);
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(dataBytes);
        argon2.DegreeOfParallelism = parallelism;
        argon2.Salt = salt;
        argon2.Iterations = 1 << iterationsPow;
        argon2.MemorySize = 1 << memorySizePow;
        argon2.KnownSecret = knownSecret;
        var computedHash = await argon2.GetBytesAsync(hashLengthBits >> 3);
        return Convert.ToBase64String(computedHash);
    }

    private static (int parallelism, int iterationsPow, int memorySizePow, byte[] salt, byte[]? hash) Parse(string salt, string desc)
    {
        var parts = salt.Split('$');
        if (parts.Length != 7)
            throw new FormatException(desc + " is not in the correct format");
        if (parts[0] != "")
            throw new FormatException(desc + " is not in the correct format");
        if (parts[1] != "a2id")
            throw new FormatException(desc + " is not in the correct format");
        if (!int.TryParse(parts[2], out var parallelism))
            throw new FormatException(desc + " is not in the correct format");
        if (!int.TryParse(parts[3], out var iterationsPow))
            throw new FormatException(desc + " is not in the correct format");
        if (!int.TryParse(parts[4], out var memorySizePow))
            throw new FormatException(desc + " is not in the correct format");

        var saltBytes = Convert.FromBase64String(parts[5]);
        var hashBytes = parts[6].Length == 0 ? null : Convert.FromBase64String(parts[6]);
        return (parallelism, iterationsPow, memorySizePow, saltBytes, hashBytes);
    }
}
