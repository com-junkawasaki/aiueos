#!/usr/bin/env bb

(require '[babashka.fs :as fs]
         '[babashka.process :refer [process shell]]
         '[clojure.string :as str])

(def root (str (fs/canonicalize (fs/path (fs/parent *file*) ".."))))
(defn env-or [k default] (or (System/getenv k) default))
(defn host-target []
  (let [out (:out @(process ["rustc" "-vV"] {:out :string}))]
    (some->> (str/split-lines out)
             (some #(second (re-find #"^host: (.+)$" %))))))

(def host (host-target))
(def host-target-dir (env-or "AIUEOS_HOST_TARGET_DIR" "/tmp/aiueos-datomic-target"))
(def linux-bin (env-or "AIUEOS_LINUX_BIN" "/tmp/aiueos-linux-target/aarch64-unknown-linux-musl/release/aiueos"))
(def kernel (env-or "AIUEOS_KERNEL" "/tmp/aiueos-kernel/vmlinuz-virt"))
(def system (env-or "AIUEOS_SYSTEM" "examples/robot/robot.aiueos.edn"))
(def initramfs (env-or "AIUEOS_INITRAMFS" "examples/robot/.aiueos/image/aiueos-robot.initramfs.cpio.gz"))
(def console (env-or "AIUEOS_CONSOLE" "pl011"))
(def console-socket (env-or "AIUEOS_CONSOLE_SOCKET" "examples/robot/.aiueos/image/aiueos-console.sock"))

(when-not (and linux-bin (fs/executable? linux-bin))
  (shell {:dir root} "bb" "scripts/build-linux-aarch64.bb"))

(when-not (and kernel (fs/regular-file? kernel))
  (shell {:dir root} "bb" "scripts/fetch-aarch64-virt-kernel.bb" kernel))

(shell {:dir root
        :extra-env {"CARGO_TARGET_DIR" host-target-dir}}
       "cargo" "run" "--target" host "--features" "kototama" "--"
       "image" "build" system "--aiueos-bin" linux-bin)

(let [vm-args (cond-> ["cargo" "run" "--target" host "--features" "kototama" "--"
                       "vm" "boot" system "--kernel" kernel "--initramfs" initramfs]
                (not= console "pl011")
                (into ["--console" console "--console-socket" console-socket]))]
  (apply shell
         {:dir root
          :extra-env {"CARGO_TARGET_DIR" host-target-dir}}
         vm-args))
