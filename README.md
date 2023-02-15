# Shane32.Argon2

[![NuGet](https://img.shields.io/nuget/v/Shane32.Argon2.svg)](https://www.nuget.org/packages/Shane32.Argon2)
[![Coverage Status](https://coveralls.io/repos/github/Shane32/Argon2/badge.svg?branch=master)](https://coveralls.io/github/Shane32/Argon2?branch=master)

Provides a set of functions for hashing passwords using the Argon2 algorithm into a composite string
containing the hash parameters, salt and hash.

## Usage

```csharp
using Shane32.Argon2;

// Select a set of parameters to use that require at least 0.2 seconds of hashing time
var parallelism = 2;
var hashLengthBits = 256;
var minTime = TimeSpan.FromSeconds(0.2);
var parameters = await Argon2Library.SelectParametersAsync(parallelism, hashLengthBits, minTime);

// Create a hash with generated parameters
var hash = await Argon2Library.HashAsync(parameters, "password");

// Create a hash with custom parameters
var hash2 = await Argon2Library.HashAsync(
    new Argon2Parameters(
        parallelism: 4,
        iterations: 16,
        memorySizeKb: 4096,
        hashLengthBits: 64),
    "foobar");

// Verify a hash
var ok = await Argon2Library.VerifyAsync(hash, "password");
```

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

The length of the salt is determined by the desired hash length.

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

## Dependencies

This uses the [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography)
underlying library to create the Argon2 hash.

## Notes

The [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography)
library is a C# implementation of Argon2 and may be subject to side-channel attacks.

The Argon2id variant is used when creating hashes.

The salt generation function uses the default .NET cryptographic random number generator.

## Credits

Glory to Jehovah, Lord of Lords and King of Kings, creator of Heaven and Earth,
who through his Son Jesus Christ, has reedemed me to become a child of God. -Shane32
