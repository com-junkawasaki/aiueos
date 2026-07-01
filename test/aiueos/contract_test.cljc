(ns aiueos.contract-test
  (:require [aiueos.contract :as contract]
            [clojure.test :refer [deftest is run-tests testing]]))

(def minimal-manifest
  {:aiueos/component :service/log
   :aiueos/kind :service
   :aiueos/trust :verified
   :aiueos/source "log-service.clj"
   :aiueos/entry "init"
   :aiueos/args []
   :aiueos/exports #{:log/write}
   :aiueos/effects #{:storage}
   :aiueos/limits {:memory-pages 8 :fuel 1000000}})

(deftest manifest-contract
  (testing "validates the minimal component manifest shape"
    (is (contract/manifest? minimal-manifest))
    (is (= {:valid? true :errors []}
           (contract/validate-manifest minimal-manifest))))
  (testing "rejects missing, unknown, and malformed authority fields"
    (let [result (contract/validate-manifest
                  {:aiueos/component :service/log
                   :aiueos/kind :unknown
                   :aiueos/effcts #{:network}
                   :aiueos/args [:not-an-int]})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/kind] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/effcts] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/args] (:path %)) (:errors result))))))

(deftest policy-decision-contract
  (testing "validates grant decisions"
    (is (contract/policy-decision?
         {:aiueos/decision :grant
          :aiueos/component :service/log
          :aiueos/capabilities #{:log/write}})))
  (testing "validates deny decisions with violation shape"
    (is (contract/policy-decision?
         {:aiueos/decision :deny
          :aiueos/component :agent/generated
          :aiueos/violations
          [{:aiueos/kind :forbidden-effect
            :aiueos/message "effect network is forbidden"}]})))
  (testing "rejects incomplete decisions"
    (let [result (contract/validate-policy-decision
                  {:aiueos/decision :grant
                   :aiueos/component :service/log})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/capabilities] (:path %)) (:errors result))))))

(deftest policy-contract
  (testing "validates signer lifecycle policy"
    (is (contract/policy?
         {:aiueos/signers {:alice "ed25519-pubkey" :bob "old-pubkey"}
          :aiueos/signer-status {:alice :active :bob :revoked}
          :aiueos/require-signed true})))
  (testing "accepts flat signer registries for backward compatibility"
    (is (contract/policy?
         {:aiueos/signers {:alice "ed25519-pubkey"}})))
  (testing "rejects malformed signer lifecycle policy"
    (let [result (contract/validate-policy
                  {:aiueos/signers {:alice "ed25519-pubkey"}
                   :aiueos/signer-status {:bob :revoked
                                           :mallory :unknown}
                   :aiueos/require-signed :yes})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/signer-status] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/require-signed] (:path %)) (:errors result)))))
  (testing "rejects lifecycle entries for unknown signers"
    (let [result (contract/validate-policy
                  {:aiueos/signers {:alice "ed25519-pubkey"}
                   :aiueos/signer-status {:bob :revoked}})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/signer-status :bob] (:path %)) (:errors result))))))

(deftest audit-event-contract
  (testing "validates audit events emitted by authority or host adapters"
    (is (contract/audit-event?
         {:aiueos/ts 1782748800
          :aiueos/event :grant
          :aiueos/component :service/log
          :aiueos/detail "capabilities #{:log/write}"})))
  (testing "rejects malformed events"
    (let [result (contract/validate-audit-event
                  {:aiueos/ts -1
                   :aiueos/event :unknown
                   :aiueos/component ""})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos/ts] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/event] (:path %)) (:errors result)))
      (is (some #(= [:aiueos/detail] (:path %)) (:errors result))))))

(deftest host-adapter-contract
  (testing "validates native host adapters as explicit contract consumers"
    (is (contract/host-adapter?
         {:aiueos.adapter/id :adapter/wasm-executor
          :aiueos.adapter/kind :wasm-executor
          :aiueos.adapter/consumes #{:aiueos/manifest :aiueos/policy-decision}
          :aiueos.adapter/provides #{:aiueos/run-result :aiueos/audit-event}
          :aiueos.adapter/repository "kotoba-lang/aiueos-wasm-adapter"
          :aiueos.adapter/status :planned
          :aiueos.adapter/native? true})))
  (testing "rejects incomplete or implicit adapter declarations"
    (let [result (contract/validate-host-adapter
                  {:aiueos.adapter/id "native"
                   :aiueos.adapter/kind :rust
                   :aiueos.adapter/provides []})]
      (is (false? (:valid? result)))
      (is (some #(= [:aiueos.adapter/id] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.adapter/kind] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.adapter/consumes] (:path %)) (:errors result)))
      (is (some #(= [:aiueos.adapter/provides] (:path %)) (:errors result))))))

(defn -main [& _]
  (let [{:keys [fail error]} (run-tests 'aiueos.contract-test)
        failures (+ (or fail 0) (or error 0))]
    (when (pos? failures)
      #?(:clj (System/exit 1)
         :cljs (throw (ex-info "aiueos contract tests failed"
                               {:fail fail :error error}))))))
