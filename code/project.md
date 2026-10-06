# V2V identity-keyed evidence detector — project reference

This is the design reference for the ns-3 artifact accompanying the paper
*Risk Assessment Model for V2V Cyber Threats*. It describes the v4 evaluation
contract introduced after an IEEE-style artifact audit.

The central correction is conceptual: the runtime mechanism is an
**identity-keyed sequential plausibility/evidence detector**. Its output is a
decision score. It is not a calibrated Bayesian posterior, and it does not
compute operational risk from STRIDE or DREAD.

## 1. Research question and scope

Every honest vehicle assesses the BSM streams it receives. The detector asks
whether the claims in a stream are physically or temporally implausible. State
is keyed by `(receiver, claimed identity)`. The receiver also sees the UDP
source address; v5 uses it only for the separate contested-identity signal,
not as oracle physical-source truth.

> **The contested-identity signal is an evaluation-only identifiability bound,
> not a deployable mitigation.** It keys on the receiver-observable UDP source
> address, which in this simulation is static, unique per node and
> unspoofable. A real adversary spoofs L2/L3 as readily as the
> application-layer identity, so these numbers upper-bound what
> source-address disambiguation could achieve rather than describing a defence
> that can be fielded. The signal is also structurally incapable of firing for
> attacks that do not impersonate (falsification, flooding, constant offset,
> reversed heading), so its aggregate rate over a mixed run is bounded above by
> the impersonating share and is not comparable to the stream-detection rate.
> Any deployable version needs source authentication or trusted
> physical-layer attribution, neither of which is modelled here.

That choice creates the artifact's main research question:

> When a malicious message is transmitted under an honest vehicle's identity,
> can an identity-keyed detector distinguish the physical source from the identity
> owner?

Within this model the answer is generally no. An alert can indicate that a
claimed-ID stream is inconsistent, but the detector lacks authenticated source
information needed to attribute the inconsistency to the physical transmitter.
The experiment measures that non-identifiability rather than hiding the
affected pairs from the confusion matrix.

## 2. Threat model

- **Adversary:** an insider with a functioning 802.11p interface.
- **Identity:** a plaintext `claimedId` field; it can be forged.
- **Credentials:** IEEE 1609.2 signing and certificate validation are not
  simulated. The detector is not presented as a PKI replacement.
- **Capabilities:** attackers can forge identity, position, velocity, sequence
  number, and asserted timestamp; replay received BSMs; and exceed the nominal
  beacon rate.
- **Physical limits:** no PHY jamming, RF fingerprinting, trusted ranging, or
  authenticated channel binding is modeled.
- **Coordination:** collusion and full Sybil behavior are not evaluated.
- **Placement:** each honest vehicle decides independently. There is no RSU,
  consensus layer, reputation exchange, or central authority.

`oracle_*` fields exist only in the evaluation harness. The deployable detector
must never read them.

## 3. Simulation architecture

```text
physical vehicle
    └─ emits BSM over 802.11p
          ├─ untrusted claimed identity, time, position, and velocity
          ├─ receiver-observable network source
          └─ evaluation-only role/onset/message-truth record
                 ↓
honest receiver
    ├─ updates claimed-ID-keyed plausibility state
    ├─ accumulates bounded evidence score
    ├─ emits an identity-contested signal for multiple observable sources
    │    (EVALUATION-ONLY: the source address is unspoofable here)
    ├─ records first threshold crossing and final score
    └─ emits one pair record at finalization
                 ↓
evaluation harness
    ├─ per-message malicious-stream labels
    ├─ identity-owner labels
    ├─ clean-pair labels
    ├─ victim pair and unique-victim accounting
    ├─ zero-reception malicious opportunity accounting
    └─ exact TX-registry latency and PDR bookkeeping
```

The security assessment runs during `Simulator::Run()`. Final statistics are
computed only after pair states have been finalized.

## 4. Message and oracle data

The simulated BSM contains the fields needed by the receiver:

```cpp
struct Bsm {
    uint32_t claimedId;
    uint32_t seq;
    double   txTime;       // sender-asserted; may include clock offset
    double   x, y;         // asserted position
    double   vx, vy;       // asserted velocity
    uint32_t oracleId;     // fields below are evaluation only
    uint32_t oracleSeq;
    double   oracleTxTime;
    double   oracleX, oracleY;
    double   oracleVx, oracleVy;
    uint32_t oracleAssignedRole;
    uint32_t oracleVictimId;
    uint8_t  oracleSourceIsAttacker;
    uint8_t  oracleAttackActive;
    uint8_t  oracleMessageIsMalicious;
};
```

The struct is copied into the packet payload rather than encoded as SAE J2735
or ETSI CAM. This is a simulation simplification.

For evaluation, each true transmission is also registered under the physical
source and sequence. The registry stores the simulator's true transmission
time and the exact set of honest receivers inside `commRange` at that instant.
This fixes two earlier errors:

- application latency is `true reception time − true transmission time`, not a
  clipped difference from the sender-asserted clock; and
- a packet contributes to the PDR numerator only when that receiver appeared
  in the corresponding in-range denominator set.

The detector never reads this registry.

## 5. Attacker roles

Assigned attackers behave honestly at the nominal rate until `attackStart`.
After onset the available pure roles are:

| CLI name | Behavior | Expected blind spot or evidence |
|---|---|---|
| `spoof` | transmit under an honest victim's identity | identity collision / victim attribution |
| `falsify` | repeatedly randomize the asserted position | kinematic and map evidence |
| `replay` | rebroadcast captured messages | sequence, time, and multi-source collision evidence |
| `dos` | transmit at 10× nominal rate | rate evidence |
| `constoffset` | maintain a fixed position offset | internally consistent trajectory; expected blind spot |
| `revheading` | negate the asserted velocity vector | heading evidence |
| `slydos` | transmit below the rate threshold | expected threshold blind spot |
| `mixed` | balanced naive-role mixture | combined condition |
| `mixedhard` | balanced seven-role mixture | publication stress condition |
| `none` | no assigned attackers | clean validation condition |

Attacker identities are selected independently of node ID, lane, and travel
direction. Mixed roles are assigned from a balanced role list and shuffled,
instead of deriving both role and mobility from `node_id % k`. The primary
density study uses 70 vehicles so the tested attacker fractions yield
seven-role multiples.

## 6. Plausibility checks

Seven binary checks produce positive evidence:

| Check | Condition |
|---|---|
| position jump | implied speed exceeds the physical ceiling plus sensor uncertainty |
| speed mismatch | asserted speed disagrees with displacement-derived speed |
| staleness | reception time minus asserted transmission time exceeds the freshness bound |
| replay | duplicate sequence or non-monotonic asserted time |
| rate | claimed-ID message count exceeds the one-second rate limit |
| map bounds | asserted position lies outside the modeled road |
| heading | asserted velocity points opposite to observed displacement |

Kinematic comparisons use a reference sample at least `MIN_REF_DT = 0.5 s`
old. Differencing two noisy 10 Hz positions would otherwise amplify GNSS noise
into a large implied-speed error.

`gpsSigma` and `detectorGpsSigma` are intentionally separate:

- `gpsSigma` is the actual standard deviation used to generate noisy
  observations;
- `detectorGpsSigma` is the uncertainty assumed by the check thresholds.

The separation permits misspecification tests such as actual/assumed
`(4 m, 2 m)` and `(2 m, 4 m)`. A sweep that changes both together is not a
misspecification experiment.

## 7. Sequential evidence score

Let `L` be bounded accumulated log-evidence, `L0` the configured reference
offset, `Δt` elapsed wall-clock time, and `H` the evidence half-life. On each
received message:

```text
r ← exp(−ln(2) × Δt / H)
L ← r × clamp(L) + (1 − r) × L0
L ← clamp(L + Σ fired_k log(d_k / f_k), −8, +8)
score ← logistic(L)
```

Only fired checks contribute in the primary configuration. The optional
null-evidence behavior is retained only as a structural ablation; the checks
are heterogeneous attack indicators, so silence of an unrelated check is not
generally evidence of innocence.

The logistic transform bounds the reported score but does **not** make it a
posterior probability. The `d_k` and `f_k` terms are evidence weights under a
working conditional-independence approximation. Position jump and speed
mismatch visibly violate that approximation because both use the same
displacement.

Two score models are exposed:

- `reference`: documented, hand-set weights used as a reproducible reference;
- `simfit`: weights fitted on traces from this same simulator.

`simfit` is circular with respect to this simulation and is therefore a
sensitivity arm, not a calibrated model. Neither score may be described as a
calibrated probability without external calibration and held-out evaluation.

The threshold is selected on validation seeds only. A preregistered 0.001 grid
is evaluated using the same half-open upward-crossing intervals as runtime.
Macro F1 is maximized subject to a predeclared clean-FPR constraint. For the
full run, the constraint uses an exact one-sided 95% bound on whether a benign
seed has any clean false positive. It is frozen before the test plan exists.

## 8. Runtime risk claims removed

The detector does not assign STRIDE categories at runtime and does not multiply
its score by a DREAD impact value. The separate threat/risk tables in the
project may still be discussed as elicited threat-analysis data, provided that
they are not presented as detector measurements.

This separation avoids three unsupported inferences:

1. a bounded decision score is not automatically a probability;
2. a subjective DREAD score is not an empirical event likelihood; and
3. multiplying the two does not create a validated operational risk estimate.

## 9. Evaluation units and labels

The primary sample is one `(receiver, claimed identity)` pair after warm-up.
Messages within a pair are repeated observations, not independent samples.
Receivers within one seed share the same attacker population and channel
realization; consequently the **seed/run is the independent unit for confidence
intervals**.

The v4 labels are:

- `assigned_attacker_use`: at least one message came from a node assigned an
  attacker role, regardless of onset or content;
- `attack_active_use`: at least one post-onset assigned-attacker message arrived;
- `malicious_use`: at least one received message was actually malicious;
- `owner_is_attacker`: the claimed identity is assigned to an attacker;
- `owner_seen`: the identity's legitimate source was observed in the pair;
- `source_count`: number of distinct physical sources that used the claimed
  identity;
- `impersonated`: a malicious message used an honest claimed identity.

These yield three non-interchangeable evaluations:

### 9.1 Malicious-stream detection

Truth is `malicious_use`. For a positive pair, prediction and score evaluation
start at the first malicious observation: `stream_alert` requires a new crossing
at or after that onset, and `stream_peak_score` is the post-onset peak. For a
negative pair, the full-window `ever_alert` and peak are used. The conditional
window prevents a benign false crossing before an impersonation begins from
being credited as attack detection. It still measures stream inconsistency; it
does not assert who sent the traffic.

### 9.2 Owner attribution

Truth is `owner_is_attacker`. An alert on a victim identity is a false
attribution here even if the stream genuinely contained malicious messages.
Such pairs must not be silently excluded.

### 9.3 Clean-pair false alarms

The clean subset contains honest identities with no malicious use. This reports
ordinary detector false alarms without erasing the separate operational cost
of impersonation.

For all confusion matrices:

```text
TPR = TP / (TP + FN)
FPR = FP / (FP + TN)
precision = TP / (TP + FP)
F1 = 2TP / (2TP + FP + FN)
```

Undefined denominators remain undefined. They are never replaced by zero.

For owner attribution and victim exposure, the primary decision is
`ever_alert`. For malicious-stream detection, the primary decision is the
conditional rule in §9.1. `final_alert` and `final_score` are secondary
outcomes. Stream time-to-detection is measured from `first_malicious_seen_s` to a
new post-onset crossing. A crossing that predates malicious onset is retained as
`preexisting_alert` but is not credited as attack detection. Undetected
positive streams are right-censored and must be included via restricted mean
detection time or another censoring-aware summary.

Detector confusion is conditional on at least one valid reception. System-level
coverage is reported separately through `malicious_expected_pairs`,
`malicious_expected_pairs_observed`, `malicious_observed_pairs_any_range`, and
`malicious_zero_reception_pairs`. Integration tests enforce
`expected_observed + zero_reception = expected`.

## 10. Impersonation reporting

The pair output supports two exposure counts:

- **victim pairs:** receiver–honest-identity pairs with malicious use;
- **unique victim identities:** distinct honest claimed identities exposed
  anywhere in a run.

For example, one victim identity observed by 30 receivers is 30 victim pairs
but one unique victim. Calling both “vehicles” is incorrect.

The same distinction applies to alerted victims. A detector may alert many
receiver-local copies of a small set of victim identities.

## 11. Structural comparison and oracle diagnostic

`baselines.py` replays nine explicitly named rule structures over identical v6
traces:

1. range;
2. sudden appearance;
3. majority of plausibility checks;
4. sequential evidence score;
5. receiver-observable identity contesting;
6. instantaneous weighted sum;
7. naive Bayes;
8. EWMA fired-check count; and
9. supervised logistic regression over seven cumulative check-fire rates.

Every setting is fitted on all 439 validation traces. Each rule freezes its own
native-scale threshold under the same exact one-sided 95% benign-seed upper
bound (at most 1%) used by the primary selector; all 299 benign validation
seeds are eligible. Logistic feature order, scaling, coefficients and threshold
are serialized. Held-out replay loads that artifact and performs no refitting.

They are not labeled ART, SAW, eMDM, Bayes, or any other published method,
because these local rules do not implement the full methods described in those
papers.

Each rule is evaluated with claimed-ID keys and, separately, with true-source
oracle keys. The oracle arm measures the effect of perfect source
disambiguation. It is **not deployable** under the stated threat model and must
not be presented as a competing detector.

Identity contesting is not oracle keyed: it uses the UDP source address visible
to the receiver and emits a temporal alert when a claimed identity first
appears from more than one such source. It is a mitigation prototype, not a
cryptographic binding; source spoofing and legitimate pseudonym changes remain
open limitations.

## 12. Command-line reference

The executable's `--csvHeader=true` output is authoritative for the summary
schema. Principal controls are:

| Flag | Meaning |
|---|---|
| `--nVehicles` | fleet size |
| `--attackerFraction` | assigned-attacker fraction in `[0,1]` |
| `--attack` | one of the roles or mixtures in §5 |
| `--simTime` | simulation duration |
| `--interval` | honest BSM interval |
| `--prior` | reference offset parameter for the score |
| `--threshold` | bounded decision-score threshold |
| `--decayHalfLife` | elapsed-time evidence half-life in seconds; `-1` disables forgetting |
| `--warmup` | startup period excluded from evaluation |
| `--attackStart` | genuine attack onset; require `warmup < attackStart < simTime` |
| `--commRange` | true-position range used for the PDR opportunity set |
| `--detector` | detector on/off timing arm |
| `--nullEvidence` | non-firing-check ablation |
| `--scoreModel` | `reference` or `simfit` |
| `--gpsSigma` | actual generated GNSS noise |
| `--detectorGpsSigma` | detector-assumed GNSS noise |
| `--spdSigma` | generated speed noise |
| `--clockSigma` | per-vehicle asserted-clock offset |
| `--bsmBytes` | packet size |
| `--pairOutput` | per-pair CSV path |
| `--trace` | per-reception v4 trace path |
| `--run` | ns-3 RNG run identifier |
| `--csvHeader` | print the current summary schema and exit |

Numeric inputs must be finite and within their declared ranges. Unknown attack
or score-model values terminate the run with an error.

## 13. Per-pair schema

The auditable pair file contains:

```text
receiver_id,claimed_id,source_count,source_ids,source_roles,
observable_source_count,observable_source_ipv4s,identity_contested,
contested_stream_alert,assigned_attacker_use,attack_active_use,malicious_use,
malicious_messages,owner_is_attacker,clean_pair,impersonated,
peak_score,stream_peak_score,final_score,final_alert,ever_alert,stream_alert,
preexisting_alert,post_onset_crossing_intervals,
first_seen_s,first_cross_s,time_to_detect_s,last_seen_s,observed_duration_s,
censor_time_s,censored,first_malicious_seen_s,first_stream_cross_s,
stream_time_to_detect_s,stream_observed_duration_s,stream_censor_time_s,
stream_censored,messages
```

`source_ids` and all oracle-derived labels are evaluation-only. An empty first
crossing or TTD for an undetected positive is censoring, not zero delay.

## 14. Per-reception trace schema

The v4 trace contains:

```text
receiver_id,rx_time,receiver_true_x,receiver_true_y,observable_source_ipv4,
claimed_id,claimed_seq,claimed_tx_time,claimed_x,claimed_y,claimed_vx,claimed_vy,
oracle_source_id,oracle_tx_seq,oracle_tx_time,
oracle_true_x,oracle_true_y,oracle_true_vx,oracle_true_vy,
oracle_source_is_attacker,oracle_assigned_role,oracle_attack_active,
oracle_message_is_malicious,oracle_victim_id,oracle_owner_is_attacker,
oracle_expected_receiver
```

Receiver true position is included so offline range rules do not substitute a
stale self-report. The `oracle_*` prefix marks fields forbidden to the runtime
detector. `oracle_tx_time` is the simulator truth; `claimed_tx_time` is an
untrusted protocol field.

## 15. Experiment protocol

The publication-core design uses 70 vehicles for the balanced mixed-role
condition and disjoint validation/test seeds. The planned grid is:

| Purpose | Arms × seeds | Runs |
|---|---:|---:|
| validation: benign | 1 × 299 | 299 |
| validation: seven pure attacks | 7 × 20 | 140 |
| test: seven pure attacks at 30% | 7 × 30 | 210 |
| balanced `mixedhard` density study | 4 × 30 | 120 |
| fusion/score sensitivity arms | 3 × 30 | 90 |
| actual/assumed GNSS misspecification | 3 × 30 | 90 |
| fleet scaling at 35 and 105 vehicles | 2 × 30 | 60 |
| held-out benign test | 1 × 50 | 50 |
| serial detector on/off timing pairs | 2 × 30 | 60 |
| **total** |  | **1119** |

The runner writes each run to a separate file, then validates and merges in a
deterministic order. A manifest records at least the git commit, binary hash,
ns-3 version, compiler, host, complete command, base seed, run ID, and output
hash. Shared concurrent appends are not used.

Aggregation must reject:

- an unexpected schema version;
- duplicate full configuration/run keys;
- missing planned arms or seeds;
- non-finite required configuration fields;
- malformed or mixed-schema rows; and
- validation/test seed overlap.

Intervals are clustered by seed. Comparisons using the same seed are paired.
Zero-event rates use a one-sided upper confidence bound rather than the
unsupported statement that the true rate is exactly zero.

## 16. Simulation context

| Component | Value |
|---|---|
| Simulator | ns-3.40 |
| PHY/MAC | `AdhocWifiMac`, `WIFI_STANDARD_80211p`, 10 MHz |
| Rate | `OfdmRate6MbpsBW10MHz` |
| Propagation | log-distance loss plus Nakagami fading |
| Transmit power | 20 dBm |
| Mobility | constant velocity on a bounded four-lane road |
| Road | 5000 m, bidirectional |
| Speed | approximately 20–33 m/s |
| Application | UDP BSM broadcast, nominally 10 Hz |
| Publication-core fleet | 70 vehicles |
| Seed policy | fixed ns-3 base seed, disjoint run IDs by split |

The mobility initialization keeps vehicles on the modeled road for the full
run. Lane and direction are not allowed to determine attacker status.

## 17. Known limitations

1. **Claimed-ID/source non-identifiability.** Without authenticated binding or
   trusted physical-source information, an identity-keyed state machine cannot
   reliably blame the transmitter during identity collision.
2. **No external benchmark.** VeReMi/VeReMi Extension has not been run.
3. **No superiority claim.** The structural rules are not full published
   baselines.
4. **No calibrated probability.** `reference` is hand-set; `simfit` is fitted
   and evaluated within the same simulator.
5. **Correlated checks.** Conditional independence is a working simplification.
6. **Known blind spots.** Fixed-offset trajectories and below-threshold
   flooding can be internally consistent with the local rules.
7. **No Sybil/collusion evaluation.** Multiple identities per physical source
   and coordinated attackers require a separate design.
8. **Simplified networking and mobility.** Results are scenario-specific.
9. **Host timing only.** Detector microseconds measure this host, not an OBU.
10. **No causal network-performance effect.** The detector is passive; the
    on/off arm verifies implementation and measures compute overhead.
11. **Observable-source mitigation assumptions.** Identity contesting assumes
    the network source cannot be cheaply forged and does not yet model benign
    pseudonym changes.

## 18. Current status

The v4 code and analysis workflow replace earlier measurements whose latency,
PDR, role allocation, pair labels, and uncertainty handling were not adequate
for publication. Until the clean v4 grid passes schema validation and
regenerates the tables, no historical headline value should be carried into
the manuscript.
