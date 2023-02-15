# Shane32.Argon2

[![NuGet](https://img.shields.io/nuget/v/Shane32.Argon2.svg)](https://www.nuget.org/packages/Shane32.Argon2)
[![Coverage Status](https://coveralls.io/repos/github/Shane32/Argon2/badge.svg?branch=master)](https://coveralls.io/github/Shane32/Argon2?branch=master)

Provides a set of functions for hashing passwords using the Argon2 algorithm into a composite string
containing the hash parameters, salt and hash.

## Usage

The algorithm typically creates a single string containing both the hash parameters,
salt and the hash itself.

```csharp
using Shane32.Argon2;

// Select a set of parameters to use that require at least 0.2 seconds of hashing time
var parameters = await Argon2Library.SelectParametersAsync(
    parallelism: 2,
    minTime: TimeSpan.FromSeconds(0.2),
    hashLengthBits: 256,
    saltLengthBits: 128);

// Create a hash with generated parameters
var hash = await Argon2Library.HashAsync("password", parameters);

// Create a hash with custom parameters
var hash2 = await Argon2Library.HashAsync(
    "foobar",
    new Argon2Parameters(
        parallelism: 4,
        iterations: 16,
        memorySizeKb: 4096,
        hashLengthBits: 64));

// Verify a hash
var ok = await Argon2Library.VerifyAsync("password", hash);
```

You can also generate a string containing the parameters and salt separately
from the hash:

```csharp
// Create a salt
var salt = Argon2Library.CreateArgonSalt(parameters);

// Create a hash
var hash = await Argon2Library.HashAsync("password", salt, 256);

// Verify a hash
var ok = await Argon2Library.VerifyAsync("password", hash, salt);
```

It is also possible to create the hash with a known secret by passing
a byte array to the above functions.  The hash does not contain the secret
and will require the secret to verify the hash against a password.

## Format

The hash string is composed of multiple parts, separated by `$`, as shown below:

```
$a2id${parallelism}${iterations}${memorySize}${salt}${hash}
```

| Parameter | Description |
|-|-|
| `parallelism` | The number of lanes to use while processing the hash |
| `iterations` | The base-2 logarithm of the number of iterations to apply to the password hash |
| `memorySize` | The base-2 logarithm of amount of memory to use while processing the hash, in kilobytes |
| `salt` | The salt used to generate the hash, base-64 encoded |
| `hash` | The hash of the password, base-64 encoded |

Example:

```
$a2id$4$4$12$08ivHvoRWVg=$Upe6Dg66bMM=
```

The above hash string was generated using the following parameters:

| Parameter        | Value           |
|------------------|-----------------|
| `parallelism`    | 4 lanes         |
| `iterations`     | 16 iterations   |
| `memorySizeKb`   | 4,096 kilobytes |
| `hashLengthBits` | 64 bits         |
| `password`       | `foobar`        |

When the salt is stored separately from the hash, the salt string is the same
as the hash described above, excluding the hash:

| Salt | Hash |
|------|------|
| `$a2id$4$4$12$08ivHvoRWVg=$` | `Upe6Dg66bMM=` |

## Notes

- This uses the [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography)
underlying library to create the Argon2 hash. The library is a C# implementation of Argon2 and
may be subject to side-channel attacks.

- The Argon2id variant is used when creating hashes.

- The salt generation function uses the default .NET cryptographic random number generator
and currently generates a salt of the same length as the desired hash length.

- The password fed to the Argon2id implementation is the UTF-16 little-endian encoding of the password string.

## Recommended parameters

Current recommendations for Argon2 parameters vary widly based on the source
and use case; some say:

| Parameter        | Recommendation |
|------------------|----------------|
| `parallelism`    | Number of CPU cores on the server |
| `iterations`     | 2-4 depending on the server hardware |
| `memorySizeKb`   | 65,536 KB or as much as the server can comfortably handle |
| `hashLengthBits` | 256 bits |
| Salt length      | 128 bits |
| Hashing time     | 0.5 seconds |

The algorithm within `SelectParametersAsync` starts with the following parameters
and then alternately doubles the iterations and memory size until the desired
minimum hashing time is reached:

| Parameter        | Value           |
|------------------|-----------------|
| `iterations`     | 1 iteration     |
| `memorySizeKb`   | 4,096 kilobytes |

On the hardware used for testing, the following parameters were generated with a
minimum hashing time of 0.5 seconds and a `parallelism` value of 2:

| Parameter        | Value            |
|------------------|------------------|
| `iterations`     | 16 iterations    |
| `memorySizeKb`   | 65,536 kilobytes |

The `SelectParametersAsync` algorithm was designed with a certain use case
in mind and may not fit your needs.  It is also important to note that if the
`SelectParametersAsync` algorithm is run concurrently with other tasks on the
same machine, the generated parameters may be lower than typical.

## Possible future features

- Support for Argon2, Argon2i, and Argon2d formats (would use unique prefix for each format)
- Support for verifying BCrypt passwords
- Integration of the underlying library to avoid the dependency
- Use of another underlying library that is not subject to side-channel attacks
- Execution of hash verification functions on a thread with a lower priority, and
  execution of parameter selection functions on a thread with a higher priority
- Wrapper to provide resistance to denial-of-service attacks

## Credits

Glory to Jehovah, Lord of Lords and King of Kings, creator of Heaven and Earth,
who through his Son Jesus Christ, has reedemed me to become a child of God. -Shane32
