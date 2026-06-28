#!/usr/bin/env bb

(require '[babashka.fs :as fs]
         '[babashka.process :refer [shell]]
         '[clojure.string :as str])

(def root (str (fs/canonicalize (fs/path (fs/parent *file*) ".."))))
(def target (or (System/getenv "TARGET") "aarch64-unknown-linux-musl"))
(def target-dir (or (System/getenv "CARGO_TARGET_DIR") "/tmp/aiueos-linux-target"))
(def cc-wrapper (or (System/getenv "AIUEOS_ZIG_CC") "/tmp/aiueos-zigcc-aarch64-linux-musl"))
(def ar-wrapper (or (System/getenv "AIUEOS_ZIG_AR") "/tmp/aiueos-zigar-aarch64-linux-musl"))
(def wrapper-version "native-wrapper-v1")
(def wrapper-source "/tmp/aiueos-zig-wrapper.c")
(def wrapper-marker (str (fs/path target-dir ".aiueos-zig-wrapper-version")))

(when-not (fs/which "zig")
  (binding [*out* *err*]
    (println "missing zig; install it first (for example: brew install zig)"))
  (System/exit 1))

(shell {:out :string} "rustup" "target" "add" target)

(spit wrapper-source
      "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n\nstatic int ends_with(const char *s, const char *suffix) {\n  size_t n = strlen(s), m = strlen(suffix);\n  return n >= m && strcmp(s + n - m, suffix) == 0;\n}\n\nstatic int skip_cc_arg(const char *s) {\n  if (strcmp(s, \"--target=aarch64-unknown-linux-musl\") == 0) return 1;\n  if (strcmp(s, \"--target=aarch64_unknown_linux_musl\") == 0) return 1;\n  if (strstr(s, \"/self-contained/crt\") && ends_with(s, \".o\")) return 1;\n  return 0;\n}\n\nint main(int argc, char **argv) {\n  int ar_mode = strstr(argv[0], \"zigar\") != NULL;\n  char **out = calloc((size_t)argc + 5, sizeof(char *));\n  if (!out) return 127;\n  int j = 0;\n  out[j++] = \"zig\";\n  if (ar_mode) {\n    out[j++] = \"ar\";\n    for (int i = 1; i < argc; i++) out[j++] = argv[i];\n  } else {\n    out[j++] = \"cc\";\n    out[j++] = \"-target\";\n    out[j++] = \"aarch64-linux-musl\";\n    for (int i = 1; i < argc; i++) if (!skip_cc_arg(argv[i])) out[j++] = argv[i];\n  }\n  out[j] = NULL;\n  execvp(\"zig\", out);\n  perror(\"zig\");\n  return 127;\n}\n")

(shell "cc" wrapper-source "-o" cc-wrapper)
(fs/copy cc-wrapper ar-wrapper {:replace-existing true})
(fs/set-posix-file-permissions cc-wrapper "rwxr-xr-x")
(fs/set-posix-file-permissions ar-wrapper "rwxr-xr-x")

(def existing-wrapper-version
  (when (fs/exists? wrapper-marker)
    (str/trim (slurp wrapper-marker))))

(when-not (= wrapper-version existing-wrapper-version)
  (let [build-dir (fs/path target-dir target "release" "build")]
    (when (fs/exists? build-dir)
      (doseq [p (concat (fs/glob build-dir "zstd-sys-*")
                        (fs/glob build-dir "wasmtime-*"))]
        (fs/delete-tree p)))
    (fs/create-dirs target-dir)
    (spit wrapper-marker wrapper-version)))

(shell {:dir root
        :extra-env {"RUSTC_WRAPPER" ""
                    "CARGO_TARGET_DIR" target-dir
                    "CC_aarch64_unknown_linux_musl" cc-wrapper
                    "AR_aarch64_unknown_linux_musl" ar-wrapper
                    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER" cc-wrapper}}
       "cargo" "build" "--release" "--target" target "--no-default-features" "--features" "wasm-runtime")

(def bin (str (fs/path target-dir target "release" "aiueos")))
(shell "file" bin)
(println bin)
