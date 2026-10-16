# ets5sign

A tiny, dependency-free C library and CLI for computing the `.ets5hash`
companion file KNX ETS5 keeps next to each file in a ProjectStore directory.

ETS5's ProjectStore holds the live, uncompressed working copy of a project
(as opposed to the exported `.knxproj` zip archive). Every file in it is
paired with a `<name>.ets5hash` file. If you edit a ProjectStore file by
hand, ETS5 refuses to open the project again with "corrupt data integrity"
until that hash is recomputed. This tool recomputes it.

This is a file-integrity check, not a license check. It has nothing to do
with, and provides no way to bypass, the KNX Association license dongle.

## The algorithm

Reverse engineered from `Knx.Ets.ObjectModel.dll`'s
`HashedFileStream.Check` and `FileProjectStore.set_ProjectGuid`, and
confirmed by round-tripping an edited file through a real ETS5 instance:

```text
mask = (sum(project_guid bytes, .NET Guid.ToByteArray order)
        + sum(utf8 bytes of project_id string)) mod 65536

digest = SHA1(file_bytes)                 # 20 bytes
digest[i] = (digest[i] + 41) mod 256      # for all i
digest[i] ^= (mask >> 8) & 0xFF           # if i is even
digest[i] ^= mask & 0xFF                  # if i is odd

.ets5hash file content = base64(digest)
```

`project_guid` and `project_id` are `ProjInfo/@Guid` and `Proj/@Id` from the
project's own plaintext `P` file in the ProjectStore directory — nothing
outside the project itself is needed.

## Building

```sh
make        # builds libets5sign.a and the ets5sign binary
make check  # runs the built-in self-test
```

No runtime dependencies: SHA-1 is a small embedded public-domain
implementation (`src/sha1.c`), and everything else is the C standard
library plus POSIX directory APIs. The resulting binary is a few tens of
kilobytes, statically linkable, and has no OpenSSL/libcrypto dependency.

## CLI usage

Two independent ways to supply the project identity:

**Point at a ProjectStore directory** (reads `Id`/`Guid` from `<dir>/P`):

```sh
ets5sign check /path/to/ProjectStore/P-03C4
ets5sign write /path/to/ProjectStore/P-03C4
```

With no file arguments, every file that already has a sibling
`.ets5hash` is processed. You can also name specific files:

```sh
ets5sign write /path/to/ProjectStore/P-03C4 P-03C4-0_A-2
```

**Supply the GUID and project id directly** (no ProjectStore directory
required — useful for scripting, tests, or files that live elsewhere):

```sh
ets5sign hash  --guid 851555f1-28bb-44de-9ea8-baac8bcd413d --id P-03C4 somefile
ets5sign check --guid 851555f1-28bb-44de-9ea8-baac8bcd413d --id P-03C4 somefile
ets5sign write --guid 851555f1-28bb-44de-9ea8-baac8bcd413d --id P-03C4 somefile
ets5sign mask  --guid 851555f1-28bb-44de-9ea8-baac8bcd413d --id P-03C4
```

Close ETS5 before editing ProjectStore files on disk. The project's
`<id>.store` file is a separate, unrelated integrity check and is left
alone by this tool.

## Library usage

```c
#include "ets5sign.h"

uint16_t mask;
ets5_mask("851555f1-28bb-44de-9ea8-baac8bcd413d", "P-03C4", &mask);

char b64[ETS5SIGN_B64_LEN];
ets5_hash_b64(file_bytes, file_len, mask, b64);
```

See `include/ets5sign.h` for the full API.

## Status

Verified against every hashed file (`P`, `B`, `I`, and area files) in a
real ETS5 5.7.7 ProjectStore, and against ETS5 itself: a file edited and
re-signed with this tool was opened successfully by the real application.
