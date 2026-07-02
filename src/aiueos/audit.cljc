(ns aiueos.audit
  "The append-only audit log, ported from the retired `aiueos/src/audit.rs`
  Rust module to CLJC per ADR-2607022200.

  Every capability decision (grant/deny) and every component lifecycle event
  (compile/run/reject) is appended as one EDN map per line, so the log is
  itself \"kotoba\" -- queryable with the same reader as everything else.

  The five audit events are plain keywords matching
  `aiueos.contract/audit-events` (`:grant :deny :compile :run :reject`)
  exactly, so there is no separate enum to port -- callers just use the
  keywords directly, the way the rest of this repo keeps `:aiueos/*` data
  the shared vocabulary between CLJC and host adapters.

  `audit-entry` is pure EDN construction: no I/O, no ambient wall-clock
  dependence, portable to any host (JVM, JS, kotoba-Wasm). File I/O
  (`log-path`, `append!`, `read-log`) is inherently a JVM/host adapter
  concern -- not portable to CLJS/kotoba-Wasm -- so it is `#?(:clj ...)`
  gated, following the `aiueos.contract/load-component-boundary` pattern."
  (:require [clojure.string :as str]
            #?(:clj [clojure.edn :as edn])
            #?(:clj [clojure.java.io :as io])))

(def default-log-dir-name
  "Default audit log directory name under a project/component root, mirroring
  the retired Rust `AuditLog::under`."
  ".aiueos")

(def default-log-file-name
  "Default audit log file name inside `default-log-dir-name`."
  "audit.edn")

(defn now-secs
  "Current epoch second, used to fill in `audit-entry`'s timestamp when the
  caller doesn't supply one explicitly. JVM: `System/currentTimeMillis`
  divided down to seconds (matches the retired Rust `now_secs`, which clamped
  clock errors to 0 -- `System/currentTimeMillis` cannot fail that way, so no
  clamping is needed here). CLJS: `js/Date` for host-neutral portability."
  []
  #?(:clj (quot (System/currentTimeMillis) 1000)
     :cljs (quot (.getTime (js/Date.)) 1000)))

(defn audit-entry
  "Build one append-only audit log entry as a plain EDN map:

  `{:aiueos/ts <epoch-seconds> :aiueos/event event :aiueos/component component :aiueos/detail detail}`

  Pure and host-neutral -- no I/O, no wall-clock dependence in the 4-arity
  form, so it is directly testable and portable to any host. Every entry this
  produces must validate against `aiueos.contract/validate-audit-event`.

  - `component` -- a keyword or non-empty string component id.
  - `event` -- one of `:grant :deny :compile :run :reject`
    (`aiueos.contract/audit-events`).
  - `detail` -- a free-text string.
  - `ts` -- (4-arity only) an explicit non-negative-integer epoch second;
    omit it (3-arity) to fill in the current time via `now-secs`."
  ([component event detail]
   (audit-entry component event detail (now-secs)))
  ([component event detail ts]
   {:aiueos/ts ts
    :aiueos/event event
    :aiueos/component component
    :aiueos/detail detail}))

#?(:clj
   (defn log-path
     "Default audit log location under `dir`: `<dir>/.aiueos/audit.edn`,
     creating the `.aiueos` directory if needed. Mirrors the retired Rust
     `AuditLog::under`. Returns a `java.io.File`."
     [dir]
     (let [log-dir (io/file dir default-log-dir-name)]
       (.mkdirs log-dir)
       (io/file log-dir default-log-file-name))))

#?(:clj
   (defn append!
     "Append one audit `entry` (as produced by `audit-entry`) to the log file
     at `path` as one EDN-encoded line, newline-terminated. Opens `path` in
     create+append mode, creating parent directories if needed."
     [path entry]
     (let [f (io/file path)]
       (when-let [parent (.getParentFile f)]
         (.mkdirs parent))
       (with-open [w (io/writer f :append true)]
         (.write w (pr-str entry))
         (.write w "\n")))
     nil))

#?(:clj
   (defn read-log
     "Read the raw log at `path` back as a vector of parsed EDN maps, one per
     non-blank line, in file order. A missing file reads as `[]`. Blank lines
     are skipped."
     [path]
     (let [f (io/file path)]
       (if-not (.exists f)
         []
         (with-open [r (io/reader f)]
           (vec
            (for [line (line-seq r)
                  :when (not (str/blank? line))]
              (edn/read-string line))))))))
