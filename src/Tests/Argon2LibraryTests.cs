using Shane32.Argon2;

namespace Tests;

public class Argon2LibraryTests
{
    [Fact]
    public async Task FullTest()
    {
        // Select a set of parameters to use that require at least 0.2 seconds of hashing time
        var parallelism = 2;
        var hashLengthBits = 256;
        var minTime = TimeSpan.FromSeconds(0.2);
        var parameters = await Argon2Library.SelectParametersAsync(parallelism, hashLengthBits, minTime);

        // Create a hash with custom parameters
        var hash = await Argon2Library.HashAsync(parameters, "password");
        Assert.StartsWith("$a2id$", hash, StringComparison.Ordinal);
        Assert.True(Argon2Library.IsArgon2Hash(hash));
        Assert.False(Argon2Library.IsArgon2Hash("invalid hash"));

        // Verify a hash
        Assert.True(await Argon2Library.VerifyAsync(hash, "password"));

        // Verify an invalid hash
        Assert.False(await Argon2Library.VerifyAsync(hash, "password2"));

        // Verify that an invalid format throws
        await Assert.ThrowsAsync<FormatException>(() => Argon2Library.VerifyAsync("invalid hash", "password"));
    }
}
