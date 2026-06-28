#!/usr/bin/env bb

(require '[babashka.fs :as fs]
         '[babashka.process :refer [process shell]]
         '[clojure.java.io :as io]
         '[clojure.string :as str])

(def root (str (fs/canonicalize (fs/path (fs/parent *file*) ".."))))
(defn env-or [k default] (or (System/getenv k) default))
(defn host-target []
  (let [out (:out @(process ["rustc" "-vV"] {:out :string}))]
    (some->> (str/split-lines out)
             (some #(second (re-find #"^host: (.+)$" %))))))

(def host (host-target))
(def timeout-ms (Long/parseLong (env-or "AIUEOS_SMOKE_TIMEOUT_MS" "60000")))
(def host-target-dir (env-or "AIUEOS_HOST_TARGET_DIR" "/tmp/aiueos-datomic-target"))
(def linux-bin (env-or "AIUEOS_LINUX_BIN" "/tmp/aiueos-linux-target/aarch64-unknown-linux-musl/release/aiueos"))
(def kernel (env-or "AIUEOS_KERNEL" "/tmp/aiueos-kernel/vmlinuz-virt"))
(def system (env-or "AIUEOS_SYSTEM" "examples/robot/robot.aiueos.edn"))
(def initramfs (env-or "AIUEOS_INITRAMFS" "examples/robot/.aiueos/image/aiueos-robot.initramfs.cpio.gz"))
(def console (env-or "AIUEOS_CONSOLE" "pl011"))
(def console-socket (env-or "AIUEOS_CONSOLE_SOCKET" "examples/robot/.aiueos/image/aiueos-console.sock"))
(def success-line "aiueos init — system is up; pid 1 idle")

(defn cleanup! [proc]
  (try
    (when proc
      (.destroy (:proc proc)))
    (catch Throwable _))
  ;; The child process tree is cargo -> aiueos vm boot -> qemu. Stop only the
  ;; processes tied to this exact kernel/initramfs boot.
  (doseq [pattern [(str "qemu-system-aarch64.*" (java.util.regex.Pattern/quote kernel)
                        ".*" (java.util.regex.Pattern/quote initramfs))
                   (str "aiueos vm boot.*" (java.util.regex.Pattern/quote system)
                        ".*" (java.util.regex.Pattern/quote kernel))]]
    (try
      (shell {:continue true :out :string :err :string} "pkill" "-f" pattern)
      (catch Throwable _))))

(when-not (and linux-bin (fs/executable? linux-bin))
  (shell {:dir root} "bb" "scripts/build-linux-aarch64.bb"))

(when-not (and kernel (fs/regular-file? kernel))
  (shell {:dir root} "bb" "scripts/fetch-aarch64-virt-kernel.bb" kernel))

(shell {:dir root
        :extra-env {"CARGO_TARGET_DIR" host-target-dir}}
       "cargo" "run" "--target" host "--features" "kototama" "--"
       "image" "build" system "--aiueos-bin" linux-bin)

(let [done (promise)
      vm-args (cond-> ["cargo" "run" "--target" host "--features" "kototama" "--"
                       "vm" "boot" system "--kernel" kernel "--initramfs" initramfs]
                (not= console "pl011")
                (into ["--console" console "--console-socket" console-socket]))
      proc (process vm-args
                    {:dir root
                     :extra-env {"CARGO_TARGET_DIR" host-target-dir}
                     :out :pipe
                     :err :redirect})]
  (future
    (try
      (with-open [r (io/reader (:out proc))]
        (doseq [line (line-seq r)]
          (println line)
          (when (str/includes? line success-line)
            (deliver done :ok))))
      (catch Throwable e
        (deliver done e))))
  (let [result (deref done timeout-ms :timeout)]
    (cleanup! proc)
    (cond
      (= result :ok)
      (do
        (println "aiueos smoke boot: ok")
        (System/exit 0))

      (= result :timeout)
      (do
        (binding [*out* *err*]
          (println "aiueos smoke boot: timed out waiting for PID 1 idle"))
        (System/exit 1))

      :else
      (do
        (binding [*out* *err*]
          (println "aiueos smoke boot failed:" (.getMessage result)))
        (System/exit 1)))))
