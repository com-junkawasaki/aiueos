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
(def block (env-or "AIUEOS_BLOCK" "examples/robot/.aiueos/image/aiueos-robot.raw"))
(def block-size (Long/parseLong (env-or "AIUEOS_BLOCK_SIZE" "8388608")))
(def success-line "aiueos init — system is up; pid 1 idle")

(defn ensure-block! [path size]
  (when-not (zero? (mod size 512))
    (throw (ex-info "AIUEOS_BLOCK_SIZE must be a multiple of 512 bytes" {:size size})))
  (let [file (io/file root path)]
    (when-let [parent (.getParentFile file)]
      (.mkdirs parent))
    (when-not (.exists file)
      (with-open [raf (java.io.RandomAccessFile. file "rw")]
        (.setLength raf size)))))

(defn cleanup! [proc]
  (try
    (when proc
      (.destroy (:proc proc)))
    (catch Throwable _))
  ;; The child process tree is cargo -> aiueos vm boot -> qemu. Stop only the
  ;; processes tied to this exact kernel/initramfs/block boot.
  (doseq [pattern [(str "qemu-system-aarch64.*" (java.util.regex.Pattern/quote kernel)
                        ".*" (java.util.regex.Pattern/quote initramfs)
                        ".*" (java.util.regex.Pattern/quote block))
                   (str "aiueos vm boot.*" (java.util.regex.Pattern/quote system)
                        ".*" (java.util.regex.Pattern/quote kernel)
                        ".*--block.*" (java.util.regex.Pattern/quote block))]]
    (try
      (shell {:continue true :out :string :err :string} "pkill" "-f" pattern)
      (catch Throwable _))))

(when-not (and linux-bin (fs/executable? linux-bin))
  (shell {:dir root} "bb" "scripts/build-linux-aarch64.bb"))

(when-not (and kernel (fs/regular-file? kernel))
  (shell {:dir root} "bb" "scripts/fetch-aarch64-virt-kernel.bb" kernel))

(ensure-block! block block-size)

(shell {:dir root
        :extra-env {"CARGO_TARGET_DIR" host-target-dir}}
       "cargo" "run" "--target" host "--features" "kototama" "--"
       "image" "build" system "--aiueos-bin" linux-bin)

(let [done (promise)
      proc (process ["cargo" "run" "--target" host "--features" "kototama" "--"
                     "vm" "boot" system
                     "--kernel" kernel
                     "--initramfs" initramfs
                     "--block" block]
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
        (println "aiueos virtio-blk smoke boot: ok")
        (System/exit 0))

      (= result :timeout)
      (do
        (binding [*out* *err*]
          (println "aiueos virtio-blk smoke boot: timed out waiting for PID 1 idle"))
        (System/exit 1))

      :else
      (do
        (binding [*out* *err*]
          (println "aiueos virtio-blk smoke boot failed:" (.getMessage result)))
        (System/exit 1)))))
