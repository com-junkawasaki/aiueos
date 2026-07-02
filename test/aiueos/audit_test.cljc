(ns aiueos.audit-test
  (:require [aiueos.audit :as audit]
            [aiueos.contract :as contract]
            [clojure.test :refer [deftest is testing]]
            #?(:clj [clojure.java.io :as io])))

(deftest audit-entry-shape
  (testing "4-arity is pure and builds the expected EDN map"
    (is (= {:aiueos/ts 1782748800
            :aiueos/event :grant
            :aiueos/component :service/log
            :aiueos/detail "capabilities #{:log/write}"}
           (audit/audit-entry :service/log :grant "capabilities #{:log/write}" 1782748800))))
  (testing "3-arity fills in a current, non-negative timestamp"
    (let [entry (audit/audit-entry :service/log :grant "granted")]
      (is (int? (:aiueos/ts entry)))
      (is (not (neg? (:aiueos/ts entry))))
      (is (= :grant (:aiueos/event entry)))
      (is (= :service/log (:aiueos/component entry)))
      (is (= "granted" (:aiueos/detail entry))))))

(deftest audit-entry-validates-for-every-event-kind
  (doseq [event #{:grant :deny :compile :run :reject}]
    (let [entry (audit/audit-entry :app/notes event (str "event " event) 0)]
      (is (true? (:valid? (contract/validate-audit-event entry)))
          (str "expected " entry " to validate, errors: "
               (:errors (contract/validate-audit-event entry)))))))

#?(:clj
   (defn- temp-dir []
     (str (java.nio.file.Files/createTempDirectory
           "aiueos-audit-test"
           (make-array java.nio.file.attribute.FileAttribute 0)))))

#?(:clj
   (deftest log-path-under-creates-dot-aiueos-dir
     (let [dir (temp-dir)
           path (audit/log-path dir)]
       (is (.exists (io/file dir audit/default-log-dir-name)))
       (is (= audit/default-log-file-name (.getName path)))
       (is (= audit/default-log-dir-name (.getName (.getParentFile path)))))))

#?(:clj
   (deftest append-and-read-log-round-trip
     (let [dir (temp-dir)
           path (audit/log-path dir)
           e1 (audit/audit-entry :service/log :compile "compiled" 100)
           e2 (audit/audit-entry :service/log :run "started" 101)
           e3 (audit/audit-entry :app/notes :grant "granted #{:log/write}" 102)]
       (audit/append! path e1)
       (audit/append! path e2)
       (audit/append! path e3)
       (is (= [e1 e2 e3] (audit/read-log path))))))

#?(:clj
   (deftest read-log-missing-file-returns-empty-vector
     (let [dir (temp-dir)
           path (io/file dir "does-not-exist.edn")]
       (is (= [] (audit/read-log path))))))

#?(:clj
   (deftest read-log-skips-blank-lines
     (let [dir (temp-dir)
           path (audit/log-path dir)
           e1 (audit/audit-entry :service/log :deny "denied" 200)
           e2 (audit/audit-entry :service/log :reject "rejected" 201)]
       (spit path (str (pr-str e1) "\n\n   \n" (pr-str e2) "\n"))
       (is (= [e1 e2] (audit/read-log path))))))
