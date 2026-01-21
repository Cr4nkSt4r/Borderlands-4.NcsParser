# Borderlands 4 NcsParser

Cross-platform NCS (Nexus Config Store) decoder/encoder library with a small CLI wrapper.

## Overview

- [Notes](#notes)
- [What are NCS files?](#what-are-ncs-files)
- [Features](#features)
- [Requirements](#requirements)
- [Build](#build)
- [Clang-format integration](#clang-format-integration)
- [CLI usage](#cli-usage)
- [Library usage](#library-usage)
- [Honorable mentions](#honorable-mentions)
- [License](#license)

## Notes

I wasn't able to properly refactor the code before release, there just wasn't any time to do so, and I've had 0 experience with Unreal Engine in general, please bear with me.  
Big shoutout to @apple1417 & @apocalyptech for helping me out on any Unreal specifics and SunBeam for making my journey start smooth.  
There is still some testing and debugging code like `egbx_type`, `parse_oodle_compressor` and `mask` related things which are currently used even in Release builds, but that's subject to change.  
The same is true for the [LICENSE](LICENSE.md), it's subject to change.  

## What are NCS files?

NCS files are compressed containers for Nexus Config Store tables. Each file holds:

- A compressed payload containing one or more tables.
- A table header section with string tables and type-code metadata.
- A bit-packed data section with records, tags, and entry payloads.

### How are they read?

1) Decompresses the payload.
2) Parses header strings and type-code tables.
3) Reads a bitstream of records and tags to reconstruct table data.

### This library + wrapper tries to mirror that flow

- It decodes `.ncs` into `.json` by reading the same header + bitstream structures.
- It encodes `.json` back into `.ncs` using the same ordering and metadata rules.
- A metadata file is used to preserve any information that we currently can't generate.

## Features

- Decode `.ncs` to `.json`
- Encode `.json` back to `.ncs` (requires metadata)
- Optional `.decomp` output (which are just oodle decompressed `.ncs` files)

## Requirements

- CMake 3.20+
- C++20 compiler (MSVC, clang, or GCC)
- Oodle binary for `.ncs` de/compression
- Optional: clang-format for auto-formatting

### Oodle binaries (required for compressed `.ncs`)

By default the loader searches next to the executable:

- Windows: `oo2core_9_win64.dll`
- Linux x64: `liboo2corelinux64.so.9`
- Linux arm64: `liboo2corelinuxarm64.so.9`

You can override the path with `--oodle <path>`.

## Build

### Linux

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j <parallel_jobs>
```

### Windows (MSVC)

```bat
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release -j <parallel_jobs>
```

Outputs:

- Library: `build/Release/ncs.lib` (Windows) or `build/libncs.a` (Linux)
- CLI: `build/Release/ncs_parser.exe` (Windows) or `build/ncs_parser` (Linux)

## Clang-format integration

CMake runs clang-format on build if available.

- Enable/disable: `-DUSE_CLANG_FORMAT=ON|OFF` (default ON)
- Set path via env var:
  - `CLANG_FORMAT_PATH=/path/to/clang-format`

In VS Code (CMake Tools), set it in `cmake.configureEnvironment`:

```json
{
  "cmake.configureEnvironment": {
    "CLANG_FORMAT_PATH": "/path/to/clang-format"
  }
}
```

## CLI usage

```clean
Usage: ncs_parser <file-or-dir> [--minimal] [--deps] [--strings] [--decomp] [--full] [--oodle <path>] [--debug]
```

- First argument must be a file or directory.
- `--minimal` strips metadata from JSON output and skips the table metadata `.json` generation.
- `--deps` keeps `__dep_entries` in `.json`.
- `--strings` keeps header/value strings in metadata `.json`.
- `--decomp` writes `.decomp` payloads.
- `--full` includes `--deps --strings --decomp`.
- `--debug` enables extra logging.

### Output layout (binary-relative)

```clean
output/
  json/
    <name>.json            (only when decoding)
    <name>_metadata.json   (unless --minimal)
  ncs/
    <name>.ncs             (only when encoding)
  decomp/
    <name>.decomp          (only with --decomp/--full)
```

### Examples

Decode a single file:

```bash
./ncs_parser /path/to/Nexus-Data-foo.ncs
```

Decode a folder with metadata strings and decomp:

```bash
./ncs_parser /path/to/ncs_dumps --strings --decomp
```

Encode a folder with with a custom oodle path:

```bash
./ncs_parser /path/to/json_folder --oodle /path/to/oo2core
```

## Library usage

Link against `ncs` and include `src/ncs_parser.h`:

```cpp
#include "ncs_parser.h"

int main() {
  NcsParser parser;
  ParserDecodeOptions opt;
  auto result = parser.DecodeNcsFile("file.ncs", opt);
  // result.tables + result.metadata
}
```

### Using the library in other projects

1) Build `ncs` as a static library (see Build section).
2) Add required headers
3) Link against the library and any platform libs:
   - Linux: `dl`
   - Windows: no extra libs needed beyond the defaults
4) Ensure the Oodle binary is available at runtime (next to your binary) or pass an explicit path in the options.

Minimal example:

```cpp
NcsParser parser;
ParserDecodeOptions decode_opt;
decode_opt.oodle_path = "/path/to/oo2core";
auto decoded = parser.DecodeNcsFile("input.ncs", decode_opt);

ParserEncodeOptions encode_opt;
encode_opt.oodle_path = "/path/to/oo2core";
auto rebuilt = parser.EncodeJsonToNcs(decoded.tables, decoded.metadata, encode_opt);
```

## Honorable mentions

@apple1417 & @apocalyptech  For their general Unreal Engine help!  
SunBeam                     For a smooth start into the project!

## License

See [LICENSE.md](LICENSE.md).
