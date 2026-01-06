/**
 * Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser
 */
#include "common.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <json.hpp>

namespace fs = std::filesystem;

static void print_usage() {
  BL4_LOG_INFO("Usage:\n  NcsParser <file-or-dir> [--decomp] [--database] [--metadata] [--full] [--oodle <path>]");
  BL4_LOG_INFO(
    "Options:\n"
    "  -h,--help\n"
    "  --decomp      Generates <table>.decomp file/s\n"
    "  --database    Generates an experimental database.json file\n"
    "  --metadata    Read/write <table>_metadata.json\n"
    "  --full        Generates all from above\n"
    "  --oodle       Set alternate oodle path\n");
  BL4_LOG_INFO("Copyright (c) 2026 Cr4nkSt4r - https://github.com/Cr4nkSt4r/Borderlands-4.NcsParser");
}

int main(int argc, char **argv) {
  const fs::path exe_dir = bl4::fs_utils::executable_dir();
  const fs::path out_root =
    exe_dir.empty() ? (fs::path() / "output") : (exe_dir / "output");
  const fs::path out_json_dir = out_root / "json";
  const fs::path out_decomp_dir = out_root / "decomp";
  const fs::path out_ncs_dir = out_root / "ncs";
  const fs::path out_database_path = out_root / "database.json";

  bl4::fs_utils::ensure_dir(out_root);
  const auto disp = [&exe_dir](const fs::path &p) -> std::string { return bl4::fs_utils::display_path(p, exe_dir); };

  if (argc < 2) {
    print_usage();
    return 2;
  }
  if (argc == 2) {
    const std::string arg1 = argv[1];
    if (arg1 == "-h" || arg1 == "--help") {
      print_usage();
      return 0;
    }
  }

  const std::string input_path = argv[1];
  bool want_decomp = false;
  bool want_database = false;
  bool want_metadata = false;
  std::optional<fs::path> oodle_override;

  for (int i = 2; i < argc; i++) {
    const std::string arg = argv[i];
    if (arg == "--decomp") {
      want_decomp = true;
    } else if (arg == "--database") {
      want_database = true;
    } else if (arg == "--metadata") {
      want_metadata = true;
    } else if (arg == "--oodle") {
      if (i + 1 >= argc) {
        BL4_LOG_ERROR("Missing path after %s", arg.c_str());
        return 2;
      }
      oodle_override = fs::path(argv[++i]);
    } else if (arg == "--full") {
      want_decomp = true;
      want_database = true;
      want_metadata = true;
    } else if (arg == "-h" || arg == "--help") {
      print_usage();
      return 0;
    } else {
      BL4_LOG_ERROR("Unknown argument: %s", arg.c_str());
      print_usage();
      return 2;
    }
  }

  const fs::path in = fs::path(input_path);
  if (!fs::exists(in)) {
    BL4_LOG_ERROR("Path does not exist: %s", input_path.c_str());
    return 2;
  }


  return 0;
}
