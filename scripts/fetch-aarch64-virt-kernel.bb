#!/usr/bin/env bb

(require '[babashka.fs :as fs]
         '[babashka.process :refer [shell]])

(def out (or (first *command-line-args*) "/tmp/aiueos-kernel/vmlinuz-virt"))
(def url
  (or (System/getenv "AIUEOS_AARCH64_KERNEL_URL")
      "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/netboot/vmlinuz-virt"))

(fs/create-dirs (fs/parent out))
(shell "curl" "-L" "--fail" "--show-error" "--output" out url)
(shell "file" out)
(println out)
