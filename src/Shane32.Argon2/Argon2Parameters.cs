namespace Shane32.Argon2;

/// <summary>
/// A set of parameters for the Argon2 algorithm.
/// </summary>
public class Argon2Parameters
{
    /// <summary>
    /// Initializes a new instance.
    /// </summary>
    public Argon2Parameters(int parallelism, int iterations, int memorySizeKb, int hashLengthBits, int saltLengthBits, byte[]? knownSecret = null)
    {
        if (hashLengthBits % 8 != 0)
            throw new ArgumentOutOfRangeException(nameof(hashLengthBits), "Hash length must be a multiple of 8 bits");
        if (saltLengthBits % 8 != 0)
            throw new ArgumentOutOfRangeException(nameof(saltLengthBits), "Salt length must be a multiple of 8 bits");
        if (parallelism < 1)
            throw new ArgumentOutOfRangeException(nameof(parallelism), "Parallelism must be at least 1");
        if (iterations < 1)
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be 1 or larger");
        var iterationsPow = Math.Log(iterations, 2);
        if (iterationsPow % 1 != 0)
            throw new ArgumentOutOfRangeException(nameof(iterations), "Iterations must be a power of 2");
        if (memorySizeKb < 1)
            throw new ArgumentOutOfRangeException(nameof(memorySizeKb), "Memory size must be 1 or larger");
        var memorySizePow = Math.Log(memorySizeKb, 2);
        if (memorySizePow % 1 != 0)
            throw new ArgumentOutOfRangeException(nameof(memorySizeKb), "Memory size must be a power of 2");

        Parallelism = parallelism;
        Iterations = iterations;
        MemorySizeKb = memorySizeKb;
        HashLengthBits = hashLengthBits;
        SaltLengthBits = saltLengthBits;
        KnownSecret = knownSecret;
    }

    /// <inheritdoc cref="Konscious.Security.Cryptography.Argon2.DegreeOfParallelism"/>
    public int Parallelism { get; }

    /// <inheritdoc cref="Konscious.Security.Cryptography.Argon2.Iterations"/>
    public int Iterations { get; }

    /// <inheritdoc cref="Konscious.Security.Cryptography.Argon2.MemorySize"/>
    public int MemorySizeKb { get; }

    /// <summary>
    /// The length of the salt, in bits.
    /// </summary>
    public int SaltLengthBits { get; }

    /// <summary>
    /// The length of the hash, in bits.
    /// </summary>
    public int HashLengthBits { get; }

    /// <inheritdoc cref="Konscious.Security.Cryptography.Argon2.KnownSecret"/>
    public byte[]? KnownSecret { get; }
}
