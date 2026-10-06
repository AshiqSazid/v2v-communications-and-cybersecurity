/* =====================================================================
 * v2v_cybersecurity_v2.cc
 *
 * Identity-keyed sequential plausibility detection for V2V communication.
 *
 * This replaces the earlier two-node point-to-point UdpEcho program.
 * What changed, and why it matters for the paper:
 *
 *   OLD                                   NEW
 *   ------------------------------------------------------------------
 *   PointToPointHelper (wired)            IEEE 802.11p AdhocWifiMac, 10 MHz,
 *                                         LogDistance + Nakagami fading
 *   no mobility                           highway mobility, 2 directions
 *   UdpEcho unicast                       periodic BSM broadcast @ 10 Hz
 *   suspiciousTraffic = false (constant)  7 plausibility checks over the
 *                                         received BSM stream
 *   if/else lookup table                   bounded sequential evidence score
 *   no attackers                          spoofing / position falsification
 *                                         / replay / DoS flooding
 *   verdict printed before Run()          verdict evolves per received
 *                                         message during the run
 *   no metrics                            TP/FP/TN/FN, TPR, FPR, precision,
 *                                         F1, ROC/AUC, PDR, latency,
 *                                         detector CPU overhead
 *
 * Build (verified on ns-3.40):
 *   cp v2v_cybersecurity_v2.cc <ns-3-root>/scratch/
 *   ./ns3 build v2v_cybersecurity_v2
 *
 *   Requires modules: wifi, internet, mobility, applications.
 *   The configured AdhocWifiMac operates outside a BSS; no association or
 *   vehicular control-plane protocol is modelled.
 *
 * Example:
 *   ./ns3 run "v2v_cybersecurity_v2 --nVehicles=50 --attackerFraction=0.3
 *              --attack=mixed --run=1"
 *
 * IMPORTANT FOR HONEST REPORTING: the output is a bounded SEQUENTIAL
 * LOG-EVIDENCE SCORE mapped through a logistic to [0,1]. That mapped value is
 * NOT a posterior probability -- the checks are correlated, non-firing checks
 * contribute nothing by default, and the weights are assumptions rather than
 * estimates. Do not write P(compromised | evidence) for it anywhere.
 * "reference" weights are assumptions; "simfit" weights were fitted on this
 * simulator and are diagnostic only. Neither supports a calibration or
 * external-generalisation claim.
 * ===================================================================== */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <deque>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("V2VCybersecurityV2");

/* =====================================================================
 * 1. Basic Safety Message
 * ===================================================================== */

#pragma pack(push, 1)
struct Bsm
{
    uint32_t claimedId;   // identity asserted by the sender (forgeable)
    uint32_t seq;         // sequence number
    double   txTime;      // sender-asserted generation time
    double   x, y;        // asserted position
    double   vx, vy;      // asserted velocity
    uint32_t oracleId;    // GROUND TRUTH -- evaluation harness only.
    uint32_t oracleSeq;   // true source's over-the-air transmission sequence
    double   oracleTxTime;
    double   oracleX, oracleY;
    double   oracleVx, oracleVy;
    uint32_t oracleAssignedRole;
    uint32_t oracleVictimId;
    uint8_t  oracleSourceIsAttacker;
    uint8_t  oracleAttackActive;
    uint8_t  oracleMessageIsMalicious;
                          // The detector MUST NOT read oracle-prefixed fields.
};
#pragma pack(pop)

enum Role
{
    HONEST = 0,
    SPOOFER,     // Spoofing            -> claims a victim's identity
    FALSIFIER,   // Tampering           -> asserts implausible positions
    REPLAYER,    // Repudiation/Replay  -> rebroadcasts captured BSMs
    FLOODER,     // Denial of Service   -> transmits at 10x nominal rate

    // --- competent variants -------------------------------------------
    // The four roles above are the easy cases: each violates a plausibility
    // check on every single message. Reporting TPR against only those
    // overstates the detector. The three below are drawn from the VeReMi
    // NextGen taxonomy and are specifically constructed to survive the
    // checks that catch their naive counterparts.
    CONST_OFFSET,  // Tampering -> FIXED position offset. In STEADY STATE the
                   // trajectory is internally consistent, implied speed is
                   // plausible, and the position checks are blind to it.
                   // NOTE: when the offset switches on mid-stream, that single
                   // step is itself an impossible displacement and is detected
                   // once, at the discontinuity. Run --attackStart=0 to
                   // measure steady-state detectability without that artifact;
                   // the paired difference isolates the onset contribution.
    REV_HEADING,   // Tampering -> velocity vector negated. |v| is unchanged,
                   // so a magnitude-only speed check cannot see it.
    SLY_FLOODER    // DoS -> 1.6x nominal rate, under RATE_LIMIT = 20/s.
};

static const char* RoleName(Role role)
{
    switch (role)
    {
    case HONEST:       return "honest";
    case SPOOFER:      return "spoof";
    case FALSIFIER:    return "falsify";
    case REPLAYER:     return "replay";
    case FLOODER:      return "dos";
    case CONST_OFFSET: return "constoffset";
    case REV_HEADING:  return "revheading";
    case SLY_FLOODER:  return "slydos";
    default:           return "unknown";
    }
}

/* =====================================================================
 * 2. Plausibility checks -> sequential log evidence
 *
 *    Check weights use the log-ratio parameterisation:
 *      fired      : log(d_k / f_k)
 *      not fired  : 0            (default)
 *                   log((1-d_k)/(1-f_k))   with --nullEvidence=true
 *
 *    WHY NON-FIRING IS NOT SCORED BY DEFAULT
 *    ---------------------------------------
 *    Scoring it resembles naive Bayes, but here it is not calibrated. Each
 *    d_k is a reference trigger rate marginalised over a heterogeneous
 *    attacker population, but any single attacker follows one strategy. A
 *    position falsifier never floods, so CHK_RATE staying silent is not evidence of
 *    benignity -- it is evidence the attacker is not a flooder. Charging the
 *    full log((1-d)/(1-f)) penalty for it treats "wrong attack type" as
 *    "innocent".
 *
 *    Positive-evidence-only fusion plus the decay factor gives the intended
 *    behaviour: silence lets the score relax toward its initial value, and only
 *    observed implausibility accumulates. Keep --nullEvidence as the ablation
 *    -- the contrast is worth a paragraph and a figure in the paper.
 * ===================================================================== */

enum Check
{
    CHK_POSITION_JUMP = 0,   // implied speed between BSMs exceeds physics
    CHK_SPEED_MISMATCH,      // asserted speed inconsistent with displacement
    CHK_STALENESS,           // message age at reception too large
    CHK_REPLAY,              // duplicate sequence / non-monotonic timestamp
    CHK_RATE,                // message rate far above the nominal 10 Hz
    CHK_MAP_BOUNDS,          // asserted position outside the road network
    CHK_HEADING,             // asserted velocity direction contradicts the
                             // direction actually travelled between beacons
    CHK_COUNT
};

/* =====================================================================
 * STRIDE classification and DREAD impact
 *
 * The evidence layer answers a LIKELIHOOD question: how much evidence is
 * there that this stream is misbehaving. It does not answer an IMPACT
 * question: how bad would that be. Ordering alerts needs both, so
 *
 *     Q(identity) = S(evidence) x Impact(STRIDE class)
 *
 * Q IS AN ORDINAL RISK-PRIORITY INDEX, NOT AN EXPECTED LOSS. S is a bounded
 * decision score rather than a calibrated probability, and the impact terms
 * are expert-derived ordinal weights, so the product supports ranking two
 * alerts against each other and nothing stronger. It is deliberately kept out
 * of the detection path: the TRUSTED/COMPROMISED label is decided by S alone
 * against the validation-frozen threshold tau.
 *
 * Each check is mapped to the STRIDE category its violation evidences, and
 * each category carries a DREAD impact normalised to (0,1]. STRIDE is a
 * threat-modelling taxonomy, not a detector: it LABELS the consequence class
 * of evidence the checks already produced, and never identifies an attack by
 * itself. Because one plausibility violation can be consistent with several
 * classes, attribution that is not separable is reported as ambiguous.
 *
 * PROVENANCE, which is not uniform across the six classes. Four values are
 * DERIVED from a 60-scenario integrated risk dataset (15 VeReMi NextGen
 * attack types x 4 operational contexts) as the per-class mean of DREAD
 * components built by documented rules over observed CVSS exploitability,
 * exposure and composite impact -- see data/stride_dread_table.csv and
 * data/enrich_dataset.py, both regenerable and validated against the source
 * document's own risk formulas. Information Disclosure and Elevation of
 * Privilege have NO scenarios in that dataset; those two remain elicited and
 * are marked as such below.
 *
 * These are expert-derived consequence weights, not measurements. They order
 * threats by severity; their absolute magnitudes carry no calibration claim.
 * Q is therefore reported ALONGSIDE the evidence score, never in place of it,
 * and no detection result in this work depends on the impact term.
 * ===================================================================== */
enum Stride
{
    S_SPOOFING = 0,
    S_TAMPERING,
    S_REPUDIATION,
    S_INFO_DISCLOSURE,
    S_DOS,
    S_ELEVATION,
    S_COUNT,
    S_NONE = S_COUNT     // no check fired: no threat identified
};

[[maybe_unused]] static const char* StrideName(int s)
{
    switch (s)
    {
    case S_SPOOFING:        return "spoofing";
    case S_TAMPERING:       return "tampering";
    case S_REPUDIATION:     return "repudiation";
    case S_INFO_DISCLOSURE: return "info_disclosure";
    case S_DOS:             return "denial_of_service";
    case S_ELEVATION:       return "elevation_of_privilege";
    default:                return "none";
    }
}

// The five DREAD components per class, on the 0-10 scale used by the source
// dataset, and the normalisation I_c = (D+R+E+A+Ds) / (5 * 10).
// These are the numbers the paper must print: publishing only the normalised
// result hides the rubric that produced it. Regenerate with
// data/enrich_dataset.py; the table is mirrored in data/stride_dread_table.csv
// and the two are checked against each other by test/test_analysis.py.
//
// n = number of scenarios in the 60-scenario source dataset (15 VeReMi
// NextGen attack types x 4 operational contexts) contributing to the mean.
// Two classes have no scenarios and remain elicited by the authors; they are
// marked, and no pair in any reported run is assigned either class.
struct DreadComponents
{
    double damage, reproducibility, exploitability, affected, discoverability;
    int    scenarios;      // n; 0 => elicited, not derived
    double normalised;     // (sum) / 50
};

static const DreadComponents g_dread[S_COUNT] = {
    /* Spoofing        */ {8.0, 6.5, 10.0, 10.0, 2.0, 16, 0.73},
    /* Tampering       */ {7.75, 6.5, 6.375, 9.125, 4.125, 32, 0.6775},
    /* Repudiation     */ {7.75, 6.5, 2.5, 9.5, 2.0, 8, 0.565},
    /* InfoDisclosure  */ {8.0, 6.0, 2.0, 8.0, 2.0, 0, 0.52},  // ELICITED
    /* DenialOfService */ {7.5, 6.5, 6.0, 9.0, 8.0, 4, 0.74},
    /* Elevation       */ {8.0, 6.0, 2.0, 9.0, 2.0, 0, 0.54}}; // ELICITED

static const double g_strideImpact[S_COUNT] = {
    g_dread[S_SPOOFING].normalised,        g_dread[S_TAMPERING].normalised,
    g_dread[S_REPUDIATION].normalised,     g_dread[S_INFO_DISCLOSURE].normalised,
    g_dread[S_DOS].normalised,             g_dread[S_ELEVATION].normalised};

// Two STRIDE classes whose best evidence contributions differ by less than
// this (in log-evidence units) are not separable by the observation, and the
// attribution is reported as ambiguous instead of being forced to one label.
static const double STRIDE_AMBIGUITY = 0.5;

// Priority bands for the index Q. These are OPERATIONAL POLICY, not validated
// safety boundaries and not calibrated to expected harm: they name the
// response a deployment chooses to attach to a rank. Every classification
// result in this work uses the detection threshold tau instead, selected on a
// disjoint validation partition. Conclusions are also reported on the
// continuous Q so nothing depends on where these cuts fall.
static const double PRIORITY_LOW_MAX = 0.30;   // -> accept
static const double PRIORITY_MED_MAX = 0.60;   // -> accept with monitoring

[[maybe_unused]] static const char* PriorityBand(double q)
{
    if (q <= PRIORITY_LOW_MAX) return "low";
    if (q <= PRIORITY_MED_MAX) return "medium";
    return "high";
}

struct CheckModel
{
    double d;          // P(check fires | compromised), assumed
    double f;          // P(check fires | honest), assumed
    Stride category;   // STRIDE class this check's violation evidences
};

// SIMFIT was estimated from traced receptions from this same simulator. The
// reference trigger rates can differ substantially because they are modelling
// assumptions rather than measurements from an independent labelled corpus.
// CIRCULARITY WARNING: SIMFIT is an in-simulator sensitivity arm, not an
// independently calibrated model.
static const CheckModel g_checkSimfit[CHK_COUNT] = {
    /* POSITION_JUMP  */ {0.0160, 0.0003, S_SPOOFING},
    /* SPEED_MISMATCH */ {0.0165, 0.0004, S_TAMPERING},
    /* STALENESS      */ {0.0612, 0.00005, S_REPUDIATION},
    /* REPLAY         */ {0.0399, 0.0040, S_REPUDIATION},
    /* RATE           */ {0.5500, 0.0023, S_DOS},
    /* MAP_BOUNDS     */ {0.0011, 0.00005, S_SPOOFING},
    /* HEADING        */ {0.0260, 0.0002, S_TAMPERING}};

static const CheckModel g_checkReference[CHK_COUNT] = {
    /* POSITION_JUMP  */ {0.85, 0.02, S_SPOOFING},
    /* SPEED_MISMATCH */ {0.70, 0.05, S_TAMPERING},
    /* STALENESS      */ {0.40, 0.03, S_REPUDIATION},
    /* REPLAY         */ {0.90, 0.01, S_REPUDIATION},
    /* RATE           */ {0.95, 0.01, S_DOS},
    /* MAP_BOUNDS     */ {0.60, 0.005, S_SPOOFING},
    /* HEADING        */ {0.75, 0.04, S_TAMPERING}};

static const CheckModel* g_check = g_checkReference;

struct StrideAttribution
{
    int category = S_NONE;
    double evidence = 0.0;
    double runnerUpEvidence = 0.0;
    bool ambiguous = false;
};

/* Attribute one observation from the checks that fired on that observation.
 * Evidence is first collapsed by STRIDE class, so two correlated checks mapped
 * to Tampering cannot occupy both first and second place.  The result is a
 * label for prioritisation only; it is never read by the detector decision. */
static StrideAttribution AttributeStrideFrame(const bool fired[CHK_COUNT])
{
    double byClass[S_COUNT] = {};
    for (int k = 0; k < CHK_COUNT; ++k)
    {
        if (!fired[k])
        {
            continue;
        }
        const CheckModel& check = g_check[k];
        byClass[check.category] =
            std::max(byClass[check.category], std::log(check.d / check.f));
    }

    StrideAttribution result;
    for (int category = 0; category < S_COUNT; ++category)
    {
        const double evidence = byClass[category];
        if (evidence > result.evidence)
        {
            result.runnerUpEvidence = result.evidence;
            result.evidence = evidence;
            result.category = category;
        }
        else if (evidence > result.runnerUpEvidence)
        {
            result.runnerUpEvidence = evidence;
        }
    }
    result.ambiguous =
        result.category != S_NONE && result.runnerUpEvidence > 0.0 &&
        (result.evidence - result.runnerUpEvidence) < STRIDE_AMBIGUITY;
    return result;
}

static double PriorityIndex(double peakScore, int strideClass)
{
    if (strideClass < 0 || strideClass >= S_COUNT ||
        !std::isfinite(peakScore) || peakScore <= 0.0)
    {
        return 0.0;
    }
    return std::min(1.0, peakScore) * g_strideImpact[strideClass];
}

// Physical plausibility constants (highway scenario).
static const double VMAX          = 60.0;   // m/s, absolute speed ceiling
static const double SPEED_TOL     = 15.0;   // m/s, asserted vs implied
static const double MAX_AGE       = 0.50;   // s, message freshness bound
static const double MAX_FUTURE    = 0.10;   // s, tolerated positive clock offset
static const double RATE_WINDOW   = 1.0;    // s
static const double RATE_LIMIT    = 20.0;   // msgs/s from one identity
static const double ROAD_LEN      = 5000.0; // m
static const double ROAD_WIDTH    = 30.0;   // m
static const double LOG_EVIDENCE_CLAMP = 8.0; // bounded evidence accumulation
static const double MIN_REF_DT    = 0.5;    // s, kinematic comparison baseline
static const double HEADING_COS_MIN = 0.0;  // cos < 0 => asserted heading is
                                            // more than 90 deg from travel

/* =====================================================================
 * 3. Evaluation harness (never read by the detector)
 * ===================================================================== */

struct PairRecord
{
    uint32_t receiverId;
    uint32_t claimedId;
    std::set<uint32_t> sourceIds;
    std::set<uint32_t> sourceRoles;
    std::set<uint32_t> observableSourceIps;
    std::set<uint32_t> victimIds;
    bool     ownerSeen;
    bool     assignedAttackerUse; // assigned role, irrespective of onset/content
    bool     attackActiveUse;  // an assigned attacker's post-onset message arrived
    bool     hostileUse;       // at least one oracle-message-malicious reception
    uint64_t maliciousMsgs;
    bool     everContested;
    bool     contestedStreamAlert;
    bool     preexistingContested;
    double   firstContested;
    double   firstStreamContested;
    bool     ownerIsAttacker;  // identity owner, not stream, is hostile
    double   peakScore;
    double   streamPeakScore;  // post-onset peak for positives; full peak for negatives
    double   finalScore;
    bool     finalAlert;
    bool     everAlert;
    bool     streamAlert;       // new crossing at/after first hostile use
    bool     preexistingAlert;  // first crossing preceded hostile use
    double   firstSeen;
    double   firstCross;
    double   firstHostileSeen;
    double   firstStreamCross;
    double   lastSeen;
    double   timeToDetect; // seconds from first sighting to first crossing; <0 = never
    double   streamTimeToDetect; // first above-threshold observation after onset
    std::vector<std::pair<double, double>> postOnsetCrossingIntervals;
    uint64_t msgs;

    /* --- PRIMARY endpoint (schema v5) --------------------------------
     * Everything above this line is a secondary diagnostic. The fields
     * below define the reported confusion matrices and AUC.
     *
     * The v4 contract applied a NEW-CROSSING rule to positives over a
     * post-onset window and an ANY-CROSSING rule to negatives over a
     * post-warm-up window. Two rules and two exposure windows do not
     * form one classifier's confusion matrix, and the AUC (which ranked
     * peaks) did not correspond to that operating point.
     *
     * v5 uses one statistic thresholded identically for both classes
     * over one calendar window W, so the reported (FPR, TPR) point lies
     * on the reported ROC curve by construction.
     * ----------------------------------------------------------------- */
    bool     eligible;          // received >= 1 message inside W
    uint64_t windowMsgs;        // receptions inside W
    double   windowExposure;    // seconds between first and last reception in W
    double   windowPeakScore;   // max score over W -- the decision statistic
    double   windowFirstExceed; // first time in W with score > threshold
    bool     windowAlert;       // windowPeakScore > threshold

    /* --- MITIGATION: track-keyed decision ----------------------------
     * Same evidence, same checks, same window -- keyed by kinematic track
     * instead of claimed identity. The victim-harm comparison uses
     * ownerTrackAlert: any track carrying the owner's genuine messages still
     * counts even if a bad association mixed forged messages into it.  The
     * pure-honest metric remains as a separate association diagnostic. */
    uint32_t trackCount;         // distinct trajectories under this identity
    double   maxTrackPeak;       // highest peak over any track
    double   honestTrackPeak;    // highest peak over tracks carrying NO
                                 // malicious message (harness-labelled)
    double   ownerTrackPeak;     // highest peak over tracks that carried the
                                 // claimed owner's genuine messages in W;
                                 // mixed tracks remain included
    bool     trackAlert;         // any track exceeded the threshold
    bool     honestTrackAlert;   // an all-honest track exceeded it
    bool     ownerTrackAlert;    // an owner-carrying track exceeded it
    uint64_t trackCapacityDrops; // W messages omitted after TRACK_MAX filled

    /* --- TRACK QUALITY (harness-only; association never reads these) -----
     * The mitigation depends on association being right, so association is
     * measured rather than assumed. Definitions match the tracking
     * literature's usual sense:
     *   purity      messages from a track's dominant true source / its total,
     *               averaged over tracks weighted by message count. 1.0 means
     *               no track ever mixed two transmitters.
     *   merges      tracks that carried messages from >1 true source.
     *   fragments   extra tracks beyond one per true source seen under this
     *               identity: a single transmitter split across k tracks
     *               contributes k-1.
     *   idSwitches  consecutive messages within a track whose true source
     *               changed. */
    double   trackPurity;
    uint32_t trackMerges;
    uint32_t trackFragments;
    uint64_t trackIdSwitches;

    /* Perfect-association upper bound: evidence keyed on the harness's true
     * source ID. Not deployable -- it reads the oracle -- but it bounds what
     * any better tracker could contribute, so the gap between this and the
     * real association arm IS the cost of imperfect association. */
    double   oracleTrackHonestPeak;
    bool     oracleTrackHonestAlert;

    /* --- STRIDE / DREAD prioritisation layer ----------------------------
     * Q = S x Impact(STRIDE class), an ORDINAL RISK-PRIORITY INDEX used to
     * rank alerts. It is not an expected-loss estimate: S is not calibrated
     * and the impact weights are expert-derived. Q never feeds detection --
     * trustCompromised is the score-vs-tau decision -- so no detection result
     * in this work depends on the impact weights. */
    int      strideClass;        // dominant threat class, S_NONE if none
    bool     strideAmbiguous;    // runner-up class within STRIDE_AMBIGUITY
    double   strideMargin;       // evidence gap between top two classes
    double   strideImpact;       // normalised DREAD impact of that class
    double   peakPriority;       // S_peak x impact(class observed at S_peak)
    bool     trustCompromised;   // == windowAlert; one decision variable
};
static std::vector<PairRecord> g_pairs;

using TxKey = std::pair<uint32_t, uint32_t>; // (true source, true TX sequence)
struct TxTruth
{
    double trueTxTime = 0.0;
    std::set<uint32_t> expectedReceivers;
    std::set<uint32_t> countedReceivers;
};
static std::map<TxKey, TxTruth> g_txTruth;
static std::set<uint32_t>       g_attackerIds;
static uint32_t                 g_nVehicles = 0;

static bool IsAttackerId(uint32_t id)
{
    return g_attackerIds.count(id) != 0;
}

static uint64_t            g_sent = 0;
static uint64_t            g_received = 0;
static uint64_t            g_invalidBsm = 0;
static double              g_latencySum = 0.0;
static uint64_t            g_latencyN = 0;
static uint64_t            g_detectorCalls = 0;
static double              g_detectorNanos = 0.0;
// Per-call samples so the reported cost can be a distribution rather than a
// mean. Real-time suitability is a tail property, not an average one.
static std::vector<int64_t> g_detectorSamples;
// Peak live detector payload per receiver. Bytes are a documented field-size
// estimate, not RSS: allocator metadata, STL capacity and evaluation-only
// harness state are deliberately excluded and must not be described as a
// measured memory footprint.
static uint64_t            g_peakKeys = 0;
static uint64_t            g_peakTracks = 0;
static uint64_t            g_peakStateBytes = 0;

// PDR accounting. The denominator counts only receivers that were physically
// within COMM_RANGE at transmission time -- dividing by (nVehicles-1) over a
// 5 km road measures road length, not channel quality.
static double              g_commRange = 300.0;   // m, --commRange
static uint64_t            g_expected = 0;
static uint64_t            g_pdrRx = 0;
static double              g_warmup = 5.0;        // s, --warmup: discard transient
static double              g_attackStart = 10.0;  // s, --attackStart
static double              g_onsetBlank = 0.0;    // s, --onsetBlank
// Start of the evaluation window W. Set once in main() from
// max(g_warmup, g_attackStart + g_onsetBlank). Every pair of every class is
// judged over [g_evalStart, end], which is what makes the confusion matrix
// belong to a single classifier.
static double              g_evalStart = 10.0;

static uint64_t            g_assignedAttackerRx = 0;
static uint64_t            g_attackActiveRx = 0;
static uint64_t            g_maliciousRx = 0;
using EvaluationPairKey = std::pair<uint32_t, uint32_t>; // receiver, claimed ID
static std::set<EvaluationPairKey> g_expectedMaliciousPairs;
static std::set<EvaluationPairKey> g_observedMaliciousPairs;

// Actual sensor noise and the detector's independently declared assumption.
static double              g_gpsSigma = 2.0;      // m,   --gpsSigma

// Localisation-error SHAPE, not magnitude. The misspecification arms vary how
// large the error is; this varies what kind of error it is, which is the
// assumption the noise-aware checks actually rest on. gaussian is the default
// and consumes exactly one Gauss() per axis, identical to the original code, so
// every result generated before this option existed reproduces bit-for-bit.
enum NoiseShape { NOISE_GAUSSIAN = 0, NOISE_STUDENT_T, NOISE_BIASED, NOISE_CORRELATED };
static NoiseShape          g_noiseShape = NOISE_GAUSSIAN;   // --noiseShape
static double              g_noiseRho   = 0.9;              // --noiseRho, AR(1)
static double              g_noiseBias  = 3.0;              // --noiseBias, m
static double              g_detectorGpsSigma = 2.0; // m, --detectorGpsSigma
static double              g_spdSigma = 0.5;      // m/s, --spdSigma
static double              g_clockSigma = 0.02;   // s,   --clockSigma
static uint32_t            g_bsmBytes = 350;      // B,   --bsmBytes

// Ablation: revert the kinematic checks to fixed thresholds on consecutive
// beacons -- the naive formulation. Isolates the contribution of the
// noise-aware derivation, which cannot be shown by varying gpsSigma alone
// because the tolerances scale with sigma by construction.
static bool                g_naiveThresh = false; // --naiveThresholds

// Opt-in per-reception trace. Off by default -- a 50-vehicle /
// 60 s run emits ~1.5M rows (~120 MB). Trace a handful of runs and do the
// prior/threshold/LLR sweeps offline in pandas instead of re-simulating.
static std::ofstream g_trace;

/* =====================================================================
 * 4. Per-neighbour detector state
 * ===================================================================== */

/* =====================================================================
 * TRACK-KEYED STATE  (the mitigation)
 *
 * Identity-keyed detection has a structural attribution failure: when an
 * attacker transmits under a victim's identity, the forged and the genuine
 * messages share one state key, so accumulated evidence is charged to the
 * victim. The new sweep must quantify that effect; no stale percentage is
 * embedded in the implementation.
 *
 * The existing identity-contested signal detects that condition, but only by
 * reading the receiver-observable UDP source address -- unspoofable ONLY
 * because this is a simulator. It is not a deployable defence.
 *
 * This is: forged and genuine messages under one claimed identity describe two
 * mutually inconsistent, individually self-consistent trajectories. That is
 * observable from message CONTENT alone. So associate each reception with the
 * kinematic track it continues, and accumulate evidence per track rather than
 * per identity. The victim's own track stays clean; the impersonator's forged
 * track accumulates its own evidence.
 *
 * Both keyings are computed in the same run so the paired difference needs no
 * extra simulation and shares every random draw.
 * ===================================================================== */
struct Track
{
    bool   valid = false;
    double refX = 0.0, refY = 0.0, refTime = 0.0;   // association anchor
    double vx = 0.0, vy = 0.0;                       // last asserted velocity
    double lastTime = -1.0;
    double logEvidence = 0.0;
    bool   haveEvidenceUpdate = false;
    double lastEvidenceUpdate = 0.0;
    // Detector history is owned by the track. Association anchors above are
    // updated every message and therefore cannot also serve the deliberately
    // longer kinematic comparison baseline.
    bool   haveCheckHistory = false;
    double lastCheckTxTime = 0.0;
    std::set<uint32_t> seenSeq;
    std::deque<uint32_t> seqFifo;
    std::deque<double> rxTimes;
    bool   checkRefValid = false;
    double checkRefX = 0.0, checkRefY = 0.0, checkRefTime = 0.0;
    double windowPeakScore = 0.0;
    uint64_t windowMsgs = 0;
    // harness only -- association never reads these
    bool   carriedMalicious = false;
    bool   carriedOwner = false;
    uint64_t msgs = 0;
    std::map<uint32_t, uint64_t> srcCounts;  // true source -> messages
    uint32_t lastSrc = std::numeric_limits<uint32_t>::max();
    uint64_t idSwitches = 0;   // consecutive messages whose true source changed
};

/* Association is nearest-neighbour under a constant-velocity motion model with
 * a noise-scaled gate. This IS the standard NN-association baseline rather than
 * a novel tracker, which is the honest framing: the contribution of Section
 * "track keying" is WHERE evidence is stored, not a new data-association
 * algorithm. Track quality is therefore measured and reported rather than
 * assumed, and a perfect-association arm keyed on the harness's true source ID
 * bounds what any better tracker could add.
 *
 * A message belongs to a track if its asserted position is reachable from that
 * track's anchor at a plausible speed, allowing for sensor noise. Deliberately
 * generous: a missed association opens a spurious track, which costs a little
 * precision, whereas a wrong association re-creates the very collision being
 * avoided.
 *
 * LIFECYCLE. creation: no gated track accepts the message and the per-identity
 * capacity is free. association: minimum residual among gated candidates.
 * tie-break: lowest index, which is the oldest surviving track -- deterministic
 * so runs are reproducible. update: anchor and velocity are replaced by the
 * accepted message. expiry: a track idle for longer than TRACK_EXPIRY is
 * retired, archived into sufficient evaluation statistics, and its bounded
 * slot reused so a long run cannot deadlock at TRACK_MAX or grow unbounded.
 * out-of-order: a message older than a track's anchor is not gated against it.
 *
 * WHY EXPIRY EXISTS, AND WHY IT IS 20 s. Without expiry a long-lived identity
 * fills its TRACK_MAX slots and every later message is dropped from the track
 * arm entirely. So expiry is not optional. But it must fire only for
 * transmitters that are genuinely gone, never for ones that are merely quiet,
 * because retiring a live track discards its accumulated evidence. A vehicle
 * crosses the 300 m range at closing speeds up to ~66 m/s, so it leaves within
 * ~9 s; 20 s is 200 nominal beacon intervals and is intended to exceed an
 * ordinary in-range reception gap. Results must still report expiry sensitivity.
 */
static const double TRACK_GATE_SIGMA = 4.0;
static const uint32_t TRACK_MAX = 4;
static const double TRACK_EXPIRY = 20.0;  // s idle before a track is retired

static void EvaluateTrackChecks(Track& track,
                                const Bsm& b,
                                double now,
                                bool fired[CHK_COUNT])
{
    std::fill(fired, fired + CHK_COUNT, false);

    // Stateless checks are safe to recompute from the current message.
    fired[CHK_MAP_BOUNDS] =
        b.x < -50.0 || b.x > ROAD_LEN + 50.0 ||
        std::fabs(b.y) > ROAD_WIDTH;
    fired[CHK_STALENESS] = (now - b.txTime) > MAX_AGE;

    // Stateful checks use only observations assigned to this track.
    if (track.haveCheckHistory)
    {
        fired[CHK_REPLAY] = track.seenSeq.count(b.seq) > 0 ||
                            b.txTime <= track.lastCheckTxTime;
    }
    if (track.checkRefValid)
    {
        const double dt = b.txTime - track.checkRefTime;
        if (dt >= (g_naiveThresh ? 1e-6 : MIN_REF_DT))
        {
            const double dx = b.x - track.checkRefX;
            const double dy = b.y - track.checkRefY;
            const double sigmaV =
                std::sqrt(2.0) * g_detectorGpsSigma / dt;
            const double jumpTol =
                g_naiveThresh ? VMAX : VMAX + 3.0 * sigmaV;
            const double speedTol =
                g_naiveThresh
                    ? SPEED_TOL
                    : SPEED_TOL +
                          3.0 * std::sqrt(sigmaV * sigmaV +
                                          g_spdSigma * g_spdSigma);
            const double displacement = std::hypot(dx, dy);
            const double implied = displacement / dt;
            const double asserted = std::hypot(b.vx, b.vy);
            fired[CHK_POSITION_JUMP] = implied > jumpTol;
            fired[CHK_SPEED_MISMATCH] =
                std::fabs(implied - asserted) > speedTol;
            if (displacement > 3.0 * g_detectorGpsSigma && asserted > 1.0)
            {
                const double cosine =
                    (dx * b.vx + dy * b.vy) /
                    (displacement * asserted);
                fired[CHK_HEADING] = cosine < HEADING_COS_MIN;
            }
            track.checkRefX = b.x;
            track.checkRefY = b.y;
            track.checkRefTime = b.txTime;
        }
    }
    else
    {
        track.checkRefValid = true;
        track.checkRefX = b.x;
        track.checkRefY = b.y;
        track.checkRefTime = b.txTime;
    }

    track.rxTimes.push_back(now);
    while (!track.rxTimes.empty() &&
           track.rxTimes.front() < now - RATE_WINDOW)
    {
        track.rxTimes.pop_front();
    }
    fired[CHK_RATE] =
        static_cast<double>(track.rxTimes.size()) / RATE_WINDOW > RATE_LIMIT;

    track.haveCheckHistory = true;
    track.lastCheckTxTime = std::max(track.lastCheckTxTime, b.txTime);
    if (track.seenSeq.insert(b.seq).second)
    {
        track.seqFifo.push_back(b.seq);
    }
    if (track.seqFifo.size() > 500)
    {
        track.seenSeq.erase(track.seqFifo.front());
        track.seqFifo.pop_front();
    }
}

struct NeighborState
{
    std::vector<Track> tracks;   // mitigation: evidence keyed by trajectory
    // Perfect-association upper bound, harness-only: the same accumulation
    // keyed on the true source ID instead of on an associated trajectory.
    std::map<uint32_t, Track> oracleTracks;
    bool                have = false;
    double              lastTxTime = 0;
    std::set<uint32_t>   seenSeq;    // membership test
    std::deque<uint32_t> seqFifo;    // insertion order, for correct eviction
    std::deque<double>  rxTimes;
    double              logEvidence = 0.0;
    bool                haveEvidenceUpdate = false;
    double              lastEvidenceUpdate = 0.0;

    // --- evaluation harness only; the detector never reads these ----------
    // Every truth/source/latency field in this block is populated only for
    // receptions inside W. Detector and association histories above remain
    // continuous before W, but cannot leak labels into the endpoint.
    uint64_t            msgs = 0;
    double              firstSeen = -1.0;    // first reception inside W
    double              firstCross = -1.0;   // time score first exceeded threshold
    double              firstHostileSeen = -1.0;
    double              firstStreamCross = -1.0;
    double              lastSeen = -1.0;
    double              peakScore = 0.0;
    double              postHostilePeakScore = 0.0;
    std::set<uint32_t>   sourceIds;
    std::set<uint32_t>   sourceRoles;
    std::set<uint32_t> observableSourceIps;
    std::set<uint32_t>   victimIds;
    bool                sawOwner = false;
    bool                sawAssignedAttackerUse = false;
    bool                sawAttackActiveUse = false;
    bool                sawHostileUse = false;
    uint64_t            maliciousMsgs = 0;
    bool                identityContested = false;
    double              firstContested = -1.0;
    double              firstStreamContested = -1.0;
    bool                haveWindowScore = false;
    double              lastWindowScore = 0.0;
    std::vector<std::pair<double, double>> postOnsetCrossingIntervals;
    // Kinematic reference: a sample deliberately held back so the comparison
    // baseline is >= MIN_REF_DT, keeping differenced-position noise small.
    bool                refValid = false;
    double              refX = 0, refY = 0, refTime = 0;

    bool                warmReset = false;   // evidence cleared at warm-up end

    // Bounded archive for retired tracks.  Active slots are reused, so the
    // vector above never grows beyond TRACK_MAX, while these sufficient
    // statistics preserve decisions and track-quality accounting.
    uint32_t            retiredWindowTracks = 0;
    uint32_t            retiredTracksWithMessages = 0;
    double              retiredMaxTrackPeak = 0.0;
    double              retiredHonestTrackPeak = 0.0;
    double              retiredOwnerTrackPeak = 0.0;
    double              retiredPurityNumerator = 0.0;
    uint64_t            retiredPurityDenominator = 0;
    uint32_t            retiredTrackMerges = 0;
    uint64_t            retiredTrackIdSwitches = 0;
    std::set<uint32_t>  retiredSourcesSeen;
    uint64_t            trackCapacityDrops = 0;

    // --- PRIMARY endpoint accumulation over the evaluation window W ---
    // W is one calendar interval shared by every pair of every class, so
    // positives and negatives are decided by the same rule over matched
    // exposure. See PairRecord for why v4's two-rule contract was unsound.
    // Current-frame attribution is snapped when S reaches its window maximum.
    // This makes the reported definition exact: Q = S_peak * I(c_at_S_peak).
    StrideAttribution   currentStride;
    StrideAttribution   peakStride;

    uint64_t            windowMsgs = 0;
    double              windowFirstSeen = -1.0;
    double              windowLastSeen = -1.0;
    double              windowPeakScore = 0.0;
    double              windowFirstExceed = -1.0;
    // Separate from windowFirstExceed: a pre-onset exceedance must not censor
    // a later hostile-stream event, and an already-high score on the first
    // hostile reception is a zero-delay primary detection.
    double              streamWindowFirstExceed = -1.0;
};

/* The single gate for exported pair truth.  Keeping this in a source-derived
 * unit-testable helper prevents a later diagnostic from accidentally treating
 * warm-up/onset-blank traffic as endpoint truth while still allowing Assess()
 * to consume that traffic as detector history. */
static bool ObserveWindowTruth(NeighborState& state,
                               double now,
                               uint32_t sourceId,
                               uint32_t sourceRole,
                               uint32_t observableSourceIp,
                               uint32_t victimId,
                               uint32_t claimedId,
                               bool assignedAttackerMessage,
                               bool attackActiveMessage,
                               bool hostileMessage)
{
    if (now < g_evalStart)
    {
        return false;
    }
    ++state.msgs;
    if (hostileMessage)
    {
        ++state.maliciousMsgs;
    }
    const bool wasContested = state.identityContested;
    state.sourceIds.insert(sourceId);
    state.sourceRoles.insert(sourceRole);
    state.observableSourceIps.insert(observableSourceIp);
    state.identityContested = state.observableSourceIps.size() > 1;
    if (hostileMessage &&
        victimId != std::numeric_limits<uint32_t>::max())
    {
        state.victimIds.insert(victimId);
    }
    state.sawOwner |= sourceId == claimedId;
    state.sawAssignedAttackerUse |= assignedAttackerMessage;
    state.sawAttackActiveUse |= attackActiveMessage;
    state.sawHostileUse |= hostileMessage;
    state.lastSeen = now;
    if (state.firstSeen < 0.0)
    {
        state.firstSeen = now;
    }
    if (hostileMessage && state.firstHostileSeen < 0.0)
    {
        state.firstHostileSeen = now;
    }
    if (!wasContested && state.identityContested)
    {
        if (state.firstContested < 0.0)
        {
            state.firstContested = now;
        }
        if (state.firstHostileSeen >= 0.0 &&
            state.firstStreamContested < 0.0)
        {
            state.firstStreamContested = now;
        }
    }
    return true;
}

static void ObserveStreamWindowExceed(NeighborState& state,
                                      double now,
                                      double score,
                                      double threshold)
{
    if (state.firstHostileSeen < g_evalStart || now < g_evalStart ||
        score <= threshold || state.streamWindowFirstExceed >= 0.0)
    {
        return;
    }
    const double streamOnset = state.firstHostileSeen;
    if (now >= streamOnset)
    {
        state.streamWindowFirstExceed = now;
    }
}

static void ResetTrackMeasurement(Track& track, double initialLogEvidence)
{
    // Preserve association anchors/liveness so the first measured message can
    // continue a pre-warm-up trajectory, but discard every measured quantity.
    track.logEvidence = initialLogEvidence;
    track.haveEvidenceUpdate = false;
    track.lastEvidenceUpdate = 0.0;
    track.windowPeakScore = 0.0;
    track.windowMsgs = 0;
    track.carriedMalicious = false;
    track.carriedOwner = false;
    track.msgs = 0;
    track.srcCounts.clear();
    track.lastSrc = std::numeric_limits<uint32_t>::max();
    track.idSwitches = 0;
}

static void ResetMeasurementState(NeighborState& state,
                                  double initialLogEvidence)
{
    state.logEvidence = initialLogEvidence;
    state.haveEvidenceUpdate = false;
    state.currentStride = StrideAttribution();
    state.peakStride = StrideAttribution();

    state.retiredWindowTracks = 0;
    state.retiredTracksWithMessages = 0;
    state.retiredMaxTrackPeak = 0.0;
    state.retiredHonestTrackPeak = 0.0;
    state.retiredOwnerTrackPeak = 0.0;
    state.retiredPurityNumerator = 0.0;
    state.retiredPurityDenominator = 0;
    state.retiredTrackMerges = 0;
    state.retiredTrackIdSwitches = 0;
    state.retiredSourcesSeen.clear();
    state.trackCapacityDrops = 0;
    state.streamWindowFirstExceed = -1.0;
    for (Track& track : state.tracks)
    {
        ResetTrackMeasurement(track, initialLogEvidence);
    }
    for (auto& item : state.oracleTracks)
    {
        ResetTrackMeasurement(item.second, initialLogEvidence);
    }
    state.warmReset = true;
}

static void ArchiveAndReleaseTrack(NeighborState& state,
                                   Track& track,
                                   int64_t* evaluationOnlyNanos = nullptr)
{
    const auto evaluationOnlyStart = std::chrono::steady_clock::now();
    if (track.msgs > 0)
    {
        ++state.retiredTracksWithMessages;
        uint64_t dominant = 0;
        for (const auto& item : track.srcCounts)
        {
            dominant = std::max(dominant, item.second);
            state.retiredSourcesSeen.insert(item.first);
        }
        state.retiredPurityNumerator += static_cast<double>(dominant);
        state.retiredPurityDenominator += track.msgs;
        state.retiredTrackMerges += track.srcCounts.size() > 1 ? 1u : 0u;
        state.retiredTrackIdSwitches += track.idSwitches;
    }
    if (track.windowMsgs > 0)
    {
        ++state.retiredWindowTracks;
        state.retiredMaxTrackPeak =
            std::max(state.retiredMaxTrackPeak, track.windowPeakScore);
        if (!track.carriedMalicious)
        {
            state.retiredHonestTrackPeak =
                std::max(state.retiredHonestTrackPeak, track.windowPeakScore);
        }
        if (track.carriedOwner)
        {
            state.retiredOwnerTrackPeak =
                std::max(state.retiredOwnerTrackPeak, track.windowPeakScore);
        }
    }
    if (evaluationOnlyNanos != nullptr)
    {
        const auto evaluationOnlyEnd = std::chrono::steady_clock::now();
        *evaluationOnlyNanos +=
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                evaluationOnlyEnd - evaluationOnlyStart)
                .count();
    }
    // Slot release and bounded storage reuse are deployable tracker work and
    // intentionally remain charged to the detector timer.
    track = Track();
}

static void ExpireTracks(NeighborState& state,
                         double now,
                         int64_t* evaluationOnlyNanos = nullptr)
{
    for (Track& track : state.tracks)
    {
        if (track.valid && track.lastTime >= 0.0 &&
            (now - track.lastTime) > TRACK_EXPIRY)
        {
            ArchiveAndReleaseTrack(state, track, evaluationOnlyNanos);
        }
    }
}

static int AllocateTrackSlot(NeighborState& state, double initialLogEvidence)
{
    for (size_t index = 0; index < state.tracks.size(); ++index)
    {
        if (!state.tracks[index].valid)
        {
            state.tracks[index] = Track();
            state.tracks[index].valid = true;
            state.tracks[index].logEvidence = initialLogEvidence;
            return static_cast<int>(index);
        }
    }
    if (state.tracks.size() >= TRACK_MAX)
    {
        return -1;
    }
    state.tracks.emplace_back();
    state.tracks.back().valid = true;
    state.tracks.back().logEvidence = initialLogEvidence;
    return static_cast<int>(state.tracks.size() - 1);
}

// Return the threshold interval for which this score observation constitutes
// an upward crossing. Scores and configured thresholds are in [0,1]. For the
// first post-warm-up observation, runtime semantics are "alert if score > T",
// represented exactly by [0, score). Later observations use [previous, score)
// only when the score increased. Intervals are half-open: low <= T < high.
static bool CrossingInterval(bool havePrevious, double previous, double current,
                             std::pair<double, double>& interval)
{
    const double low = havePrevious ? previous : 0.0;
    if (!(current > low))
    {
        return false;
    }
    interval = {std::max(0.0, low), std::min(1.0, current)};
    return interval.second > interval.first;
}

static std::vector<std::pair<double, double>> MergeCrossingIntervals(
    std::vector<std::pair<double, double>> intervals)
{
    std::sort(intervals.begin(), intervals.end());
    std::vector<std::pair<double, double>> merged;
    for (const auto& interval : intervals)
    {
        if (!(interval.second > interval.first))
        {
            continue;
        }
        if (merged.empty() || interval.first > merged.back().second)
        {
            merged.push_back(interval);
        }
        else
        {
            merged.back().second = std::max(merged.back().second,
                                            interval.second);
        }
    }
    return merged;
}

static double TimeDecayFactor(double deltaTime, double halfLife)
{
    if (halfLife < 0.0 || deltaTime <= 0.0)
    {
        return 1.0;
    }
    return std::exp(-std::log(2.0) * deltaTime / halfLife);
}

/* =====================================================================
 * 5. Application: honest sender + attacker variants + detector
 * ===================================================================== */

class V2vBsmApp : public Application
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("V2vBsmApp")
                                .SetParent<Application>()
                                .SetGroupName("Applications")
                                .AddConstructor<V2vBsmApp>();
        return tid;
    }

    V2vBsmApp() = default;
    ~V2vBsmApp() override = default;

    void Setup(uint32_t id, Role role, Ipv4Address bcast, uint16_t port,
               double interval, bool detectorOn, double prior, double threshold,
               uint32_t victimId, double decayHalfLife, bool nullEvidence)
    {
        m_decayHalfLife = decayHalfLife;
        m_nullEvidence = nullEvidence;
        m_id = id;
        // Fixed per-vehicle localisation offset for NOISE_BIASED. Derived from
        // the vehicle id by golden-angle rotation rather than drawn, so it
        // consumes no RNG and cannot perturb any other arm's stream.
        {
            const double ang = static_cast<double>(id) * 2.39996322972865332;
            m_biasX = g_noiseBias * std::cos(ang);
            m_biasY = g_noiseBias * std::sin(ang);
        }
        m_role = role;
        m_bcast = bcast;
        m_port = port;
        m_interval = interval;
        m_detectorOn = detectorOn;
        m_threshold = threshold;
        m_victimId = victimId;
        m_initialLogEvidence = std::log(prior / (1.0 - prior));
    }

  private:
    void StartApplication() override
    {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->SetAllowBroadcast(true);
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
        m_socket->SetRecvCallback(MakeCallback(&V2vBsmApp::Receive, this));
        m_socket->Connect(InetSocketAddress(m_bcast, m_port));

        Ptr<Ipv4> ipv4 = GetNode()->GetObject<Ipv4>();
        m_selfAddr = ipv4->GetAddress(1, 0).GetLocal();

        // Fixed per-vehicle clock offset for the whole run.
        m_clockOffset = Gauss() * g_clockSigma;

        // CONST_OFFSET picks its offset once and keeps it.
        m_offsetX = 150.0 + UniformVariable01() * 100.0;
        m_offsetY = (UniformVariable01() < 0.5 ? -1.0 : 1.0) * 4.0;
        // Every assigned attacker uses the honest nominal schedule before the
        // configured onset. Send() chooses the next period from current time,
        // so flooders switch rate only after their first post-onset message.
        m_sendEvent = Simulator::Schedule(
            Seconds(UniformVariable01() * m_interval), &V2vBsmApp::Send, this);
    }

    void StopApplication() override
    {
        Simulator::Cancel(m_sendEvent);
        if (m_socket)
        {
            m_socket->Close();
        }
    }

    double UniformVariable01()
    {
        if (!m_rng)
        {
            m_rng = CreateObject<UniformRandomVariable>();
        }
        return m_rng->GetValue(0.0, 1.0);
    }

    // Zero-mean unit-variance normal, for sensor noise.
    double Gauss()
    {
        if (!m_norm)
        {
            m_norm = CreateObject<NormalRandomVariable>();
            m_norm->SetAttribute("Mean", DoubleValue(0.0));
            m_norm->SetAttribute("Variance", DoubleValue(1.0));
        }
        return m_norm->GetValue();
    }

    /* One position-noise draw on one axis.
     *
     * NOISE_GAUSSIAN reproduces the original expression exactly, including the
     * number and order of underlying Gauss() calls, so the frozen v9 sweep is
     * unaffected by this option existing.
     *
     * The alternatives break a different assumption each:
     *   STUDENT_T  heavy tails -- rare large errors the 4-sigma gate treats as
     *              impossible, scaled to unit variance so sigma is comparable;
     *   BIASED     a fixed per-vehicle offset -- error that does not average
     *              out, deterministic in the vehicle id so no RNG is consumed;
     *   CORRELATED AR(1) in time -- consecutive fixes err together, which is
     *              what defeats a displacement check between successive fixes.
     */
    double PosNoise(double& arState, double bias)
    {
        switch (g_noiseShape)
        {
        case NOISE_STUDENT_T:
        {
            const double z = Gauss();
            double chi = 0.0;
            for (int i = 0; i < 3; ++i) { const double g = Gauss(); chi += g * g; }
            // t_3 has variance 3; divide by sqrt(3) so sigma stays comparable.
            return g_gpsSigma * (z / std::sqrt(chi / 3.0)) / std::sqrt(3.0);
        }
        case NOISE_BIASED:
            return bias + Gauss() * g_gpsSigma;
        case NOISE_CORRELATED:
            arState = g_noiseRho * arState +
                      std::sqrt(1.0 - g_noiseRho * g_noiseRho) * Gauss();
            return arState * g_gpsSigma;
        case NOISE_GAUSSIAN:
        default:
            return Gauss() * g_gpsSigma;
        }
    }

    double CurrentPeriod(double now) const
    {
        if (now >= g_attackStart)
        {
            if (m_role == FLOODER)
            {
                return m_interval / 10.0;
            }
            if (m_role == SLY_FLOODER)
            {
                return m_interval / 1.6;
            }
        }
        return m_interval;
    }

    void Send()
    {
        Ptr<MobilityModel> mob = GetNode()->GetObject<MobilityModel>();
        Vector p = mob->GetPosition();
        Vector v = mob->GetVelocity();
        double trueNow = Simulator::Now().GetSeconds();
        const bool assignedAttacker = m_role != HONEST;
        const bool attackActive = assignedAttacker && trueNow >= g_attackStart;
        bool messageMalicious = false;

        // SENSOR NOISE. Without this, honest vehicles report the exact
        // mobility-model state and the empirical false-alarm rate of every
        // kinematic check is identically zero -- which makes FPR = 0.000 an
        // artifact of the simulator, not a property of the detector, and
        // leaves P(fire | benign) unmeasurable. Real GNSS carries metre-level
        // error and real OBU clocks drift relative to each other.
        Bsm b;
        b.x = p.x + PosNoise(m_arX, m_biasX);
        b.y = p.y + PosNoise(m_arY, m_biasY);
        b.vx = v.x + Gauss() * g_spdSigma;
        b.vy = v.y + Gauss() * g_spdSigma;
        b.txTime = trueNow + m_clockOffset;

        b.claimedId = m_id;
        b.seq = m_seq++;

        // Assigned attackers are deliberately indistinguishable from honest
        // senders before --attackStart. This creates a clean, retained
        // pre-attack history and a genuine temporal onset.
        if (attackActive)
        {
            switch (m_role)
            {
            case SPOOFER:
                // Assert a victim's identity while transmitting from our own
                // position -> the victim's track appears to teleport.
                b.claimedId = m_victimId;
                messageMalicious = true;
                break;

            case FALSIFIER:
                // Assert a position displaced by 200-1200 m.
                b.x = p.x + (UniformVariable01() * 1000.0 + 200.0);
                b.y = p.y + (UniformVariable01() * 40.0 - 20.0);
                messageMalicious = true;
                break;

            case REPLAYER:
                if (!m_captured.empty())
                {
                    // Rebroadcast a captured BSM verbatim: stale timestamp,
                    // stale position, duplicate sequence number. An empty
                    // capture buffer leaves the nominal message benign.
                    b = m_captured.front();
                    m_captured.pop_front();
                    messageMalicious = true;
                }
                break;

            case CONST_OFFSET:
                // Same offset every beacon: displacement between consecutive
                // messages is unchanged, so implied speed stays correct and
                // the position/speed checks see nothing wrong.
                b.x += m_offsetX;
                b.y += m_offsetY;
                messageMalicious = true;
                break;

            case REV_HEADING:
                b.vx = -b.vx;
                b.vy = -b.vy;
                messageMalicious = true;
                break;

            case SLY_FLOODER:
            case FLOODER:
                // Payload remains plausible; excess transmission itself is
                // the malicious action.
                messageMalicious = true;
                break;

            case HONEST:
            default:
                break;
            }
        }

        // Oracle fields are written after the attack transformation so a
        // replay cannot inherit the captured sender's ground truth.
        b.oracleId = m_id;
        b.oracleSeq = m_oracleSeq++;
        b.oracleTxTime = trueNow;
        b.oracleX = p.x;
        b.oracleY = p.y;
        b.oracleVx = v.x;
        b.oracleVy = v.y;
        b.oracleAssignedRole = static_cast<uint32_t>(m_role);
        b.oracleVictimId = std::numeric_limits<uint32_t>::max();
        if (messageMalicious && m_role == SPOOFER)
        {
            b.oracleVictimId = m_victimId;
        }
        else if (messageMalicious && m_role == REPLAYER)
        {
            // The owner of the replayed claimed identity is the framing
            // victim, even though the over-the-air source is the replayer.
            b.oracleVictimId = b.claimedId;
        }
        b.oracleSourceIsAttacker = assignedAttacker ? 1 : 0;
        b.oracleAttackActive = attackActive ? 1 : 0;
        b.oracleMessageIsMalicious = messageMalicious ? 1 : 0;

        // Evaluation-only opportunity accounting. This deliberately remains
        // separate from conditional detector confusion: a receiver/identity
        // pair that was in nominal range for malicious traffic but received
        // none is counted explicitly, not silently treated as a detector FN.
        if (messageMalicious && trueNow >= g_evalStart)
        {
            for (auto it = NodeList::Begin(); it != NodeList::End(); ++it)
            {
                uint32_t receiverId = (*it)->GetId();
                if (receiverId == m_id || IsAttackerId(receiverId))
                {
                    continue;
                }
                Ptr<MobilityModel> receiverMobility =
                    (*it)->GetObject<MobilityModel>();
                if (receiverMobility &&
                    CalculateDistance(p, receiverMobility->GetPosition()) <=
                        g_commRange)
                {
                    g_expectedMaliciousPairs.insert(
                        {receiverId, b.claimedId});
                }
            }
        }

        // Register the exact exposure set at the true transmission time.
        // This registry is evaluation-only; Assess() never reads it.
        if (m_role == HONEST && trueNow >= g_warmup)
        {
            TxTruth truth;
            truth.trueTxTime = trueNow;
            for (auto it = NodeList::Begin(); it != NodeList::End(); ++it)
            {
                uint32_t nid = (*it)->GetId();
                if (nid == m_id || IsAttackerId(nid))
                {
                    continue;
                }
                Ptr<MobilityModel> other = (*it)->GetObject<MobilityModel>();
                if (other &&
                    CalculateDistance(p, other->GetPosition()) <= g_commRange)
                {
                    truth.expectedReceivers.insert(nid);
                }
            }
            g_expected += truth.expectedReceivers.size();
            g_txTruth[{b.oracleId, b.oracleSeq}] = std::move(truth);
        }

        // sizeof(Bsm) is smaller than a real SAE J2735 BSM carrying an IEEE
        // 1609.2 signature and certificate is ~300-400 B. Transmitting the
        // bare struct understates channel load roughly sevenfold, which
        // matters most for the DoS scenarios and for any PDR claim. Pad to a
        // realistic frame size.
        Ptr<Packet> pkt = Create<Packet>(reinterpret_cast<uint8_t*>(&b), sizeof(Bsm));
        if (g_bsmBytes > sizeof(Bsm))
        {
            pkt->AddPaddingAtEnd(g_bsmBytes - sizeof(Bsm));
        }
        m_socket->Send(pkt);
        ++g_sent;

        m_sendEvent = Simulator::Schedule(Seconds(CurrentPeriod(trueNow)),
                                          &V2vBsmApp::Send, this);
    }

    void Receive(Ptr<Socket> socket)
    {
        Ptr<Packet> pkt;
        Address from;
        while ((pkt = socket->RecvFrom(from)))
        {
            const Ipv4Address observableSourceIp =
                InetSocketAddress::ConvertFrom(from).GetIpv4();
            if (observableSourceIp == m_selfAddr)
            {
                continue;   // ignore our own broadcast loopback
            }
            if (pkt->GetSize() < sizeof(Bsm))
            {
                continue;
            }

            Bsm b;
            pkt->CopyData(reinterpret_cast<uint8_t*>(&b), sizeof(Bsm));

            double now = Simulator::Now().GetSeconds();
            ++g_received;

            bool honestSender = b.oracleSourceIsAttacker == 0;
            bool past = (now >= g_warmup);

            // PDR and latency use true source/sequence and the true simulator
            // send time. This precedes claim validation so detector rejection
            // cannot bias radio-delivery measurements.
            bool expectedReceiver = false;
            auto txIt = g_txTruth.find({b.oracleId, b.oracleSeq});
            if (honestSender && past && m_role == HONEST && txIt != g_txTruth.end())
            {
                TxTruth& truth = txIt->second;
                expectedReceiver = truth.expectedReceivers.count(m_id) != 0;
                if (expectedReceiver &&
                    truth.countedReceivers.insert(m_id).second)
                {
                    ++g_pdrRx;
                    g_latencySum += now - truth.trueTxTime;
                    ++g_latencyN;
                }
            }

            bool finiteClaim = std::isfinite(b.txTime) && std::isfinite(b.x) &&
                               std::isfinite(b.y) && std::isfinite(b.vx) &&
                               std::isfinite(b.vy);
            bool validClaim = finiteClaim && b.claimedId < g_nVehicles &&
                              b.txTime <= now + MAX_FUTURE;
            if (!validClaim)
            {
                ++g_invalidBsm;
                continue;
            }

            // Evaluation labels are consumed only after claim validation and
            // outside Assess(). Count honest-receiver exposure even when the
            // detector is disabled for a timing arm.
            if (now >= g_evalStart && m_role == HONEST)
            {
                if (b.oracleSourceIsAttacker != 0)
                {
                    ++g_assignedAttackerRx;
                }
                if (b.oracleAttackActive != 0)
                {
                    ++g_attackActiveRx;
                }
                if (b.oracleMessageIsMalicious != 0)
                {
                    ++g_maliciousRx;
                    g_observedMaliciousPairs.insert({m_id, b.claimedId});
                }
            }

            // Attackers do not run the detector. REPLAYER buffers traffic.
            if (m_role == REPLAYER && m_captured.size() < 200)
            {
                m_captured.push_back(b);
            }
            // Raw observation for offline analysis. The UDP source address is
            // receiver-observable and may support a deployable contested-ID
            // output. All oracle-prefixed fields remain evaluation-only.
            if (g_trace.is_open() && m_role == HONEST)
            {
                Vector rp = GetNode()->GetObject<MobilityModel>()->GetPosition();
                g_trace << m_id << ',' << now << ',' << rp.x << ',' << rp.y << ','
                        << observableSourceIp << ',' << b.claimedId << ',' << b.seq
                        << ',' << b.txTime
                        << ',' << b.x << ',' << b.y << ',' << b.vx << ',' << b.vy
                        << ',' << b.oracleId << ',' << b.oracleSeq << ','
                        << b.oracleTxTime << ',' << b.oracleX << ',' << b.oracleY
                        << ',' << b.oracleVx << ',' << b.oracleVy << ','
                        << unsigned(b.oracleSourceIsAttacker) << ','
                        << RoleName(static_cast<Role>(b.oracleAssignedRole)) << ','
                        << unsigned(b.oracleAttackActive) << ','
                        << unsigned(b.oracleMessageIsMalicious) << ',';
                if (b.oracleVictimId == std::numeric_limits<uint32_t>::max())
                {
                    g_trace << -1;
                }
                else
                {
                    g_trace << b.oracleVictimId;
                }
                g_trace << ','
                        << (IsAttackerId(b.claimedId) ? 1 : 0) << ','
                        << (expectedReceiver ? 1 : 0) << '\n';
            }

            if (m_role != HONEST || !m_detectorOn)
            {
                continue;
            }

            // Timed region contains the detector and nothing else. The
            // evaluation bookkeeping below would not exist on a real OBU and
            // must stay outside, or the overhead figure is inflated.
            int64_t evaluationOnlyNanos = 0;
            auto t0 = std::chrono::steady_clock::now();
            double score = Assess(b, now, evaluationOnlyNanos);
            auto t1 = std::chrono::steady_clock::now();
            const int64_t elapsedNanos = std::max<int64_t>(
                0,
                std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0)
                        .count() -
                    evaluationOnlyNanos);
            g_detectorNanos += elapsedNanos;
            ++g_detectorCalls;
            // A mean hides the tail, and the tail is what decides whether a
            // deadline is missed. Keep every sample: at ~10 Hz x 70 vehicles x
            // 60 s this is a few hundred thousand int64s, cheap enough, and it
            // lets P50/P95/P99/max be exact rather than estimated.
            g_detectorSamples.push_back(elapsedNanos);

            // Peak resident state for this receiver. Sampled here because this
            // is the point at which the map has just grown.
            {
                // Estimate DEPLOYABLE payload only. sizeof(NeighborState) would
                // include the evaluation harness's oracle sets and counters,
                // which no on-board unit would carry, and would overstate the
                // footprint several-fold. The constants below are the fields
                // the detector actually reads:
                //   per key   : score, last-update time, last-tx time,
                //               kinematic reference (x, y, t, valid)  ~= 56 B
                //   per track : association anchor/velocity/liveness (49 B),
                //               evidence/timing (17 B), independent replay/
                //               kinematic fixed history (34 B)       = 100 B
                //   per seq   : 4 B in the replay set + 4 B in the FIFO,
                //               counted for identity AND every live track
                //   per rx    : 8 B in each identity/track rate window
                constexpr uint64_t KEY_BYTES = 56;
                constexpr uint64_t TRACK_FIXED_BYTES = 100;
                uint64_t tracks = 0;
                uint64_t bytes = 0;
                for (const auto& kv : m_neighbors)
                {
                    const NeighborState& ns = kv.second;
                    uint64_t liveTracks = 0;
                    for (const Track& track : ns.tracks)
                    {
                        if (track.valid)
                        {
                            ++liveTracks;
                            bytes += TRACK_FIXED_BYTES +
                                     track.seenSeq.size() * 8 +
                                     track.rxTimes.size() * 8;
                        }
                    }
                    tracks += liveTracks;
                    bytes += KEY_BYTES + ns.seenSeq.size() * 8 +
                             ns.rxTimes.size() * 8;
                }
                g_peakKeys = std::max(g_peakKeys,
                                      static_cast<uint64_t>(m_neighbors.size()));
                g_peakTracks = std::max(g_peakTracks, tracks);
                g_peakStateBytes = std::max(g_peakStateBytes, bytes);
            }

            NeighborState& st = m_neighbors[b.claimedId];
            const bool assignedAttackerMessage = b.oracleSourceIsAttacker != 0;
            const bool attackActiveMessage = b.oracleAttackActive != 0;
            const bool hostileMessage = b.oracleMessageIsMalicious != 0;
            // All exported pair truth, sources, labels, delays and quality
            // statistics obey W. Pre-W messages have already updated the
            // detector/association histories in Assess(), but stop here.
            if (!ObserveWindowTruth(st,
                                    now,
                                    b.oracleId,
                                    b.oracleAssignedRole,
                                    observableSourceIp.Get(),
                                    b.oracleVictimId,
                                    b.claimedId,
                                    assignedAttackerMessage,
                                    attackActiveMessage,
                                    hostileMessage))
            {
                continue;
            }
            st.peakScore = std::max(st.peakScore, score);
            if (st.firstHostileSeen >= 0.0)
            {
                st.postHostilePeakScore =
                    std::max(st.postHostilePeakScore, score);
            }
            std::pair<double, double> crossing;
            const bool upward = CrossingInterval(st.haveWindowScore,
                                                 st.lastWindowScore,
                                                 score,
                                                 crossing);
            if (st.firstHostileSeen >= 0.0 && upward)
            {
                st.postOnsetCrossingIntervals.push_back(crossing);
            }
            const bool newCrossing =
                upward && crossing.first <= m_threshold &&
                m_threshold < crossing.second;
            if (newCrossing && st.firstCross < 0.0)
            {
                st.firstCross = now;
            }
            if (newCrossing && st.firstHostileSeen >= 0.0 &&
                st.firstStreamCross < 0.0)
            {
                st.firstStreamCross = now;
            }
            st.haveWindowScore = true;
            st.lastWindowScore = score;

            /* --- PRIMARY endpoint: peak over the evaluation window W ------
             * One statistic, one window, both classes. Pre-onset excursions
             * are excluded from BOTH arms by the window itself rather than
             * by an asymmetric decision rule, which is what makes the
             * resulting matrix a single classifier's. */
            if (now >= g_evalStart)
            {
                ++st.windowMsgs;
                if (st.windowFirstSeen < 0.0)
                {
                    st.windowFirstSeen = now;
                }
                st.windowLastSeen = now;
                // Snapshot attribution at the observation defining S_peak.
                // If floating-point-equal peaks recur, retain the frame with
                // stronger attribution evidence; the score and decision stay
                // unchanged.  This is the sole code path defining
                // Q = S_peak * I(c_at_S_peak).
                if (score > st.windowPeakScore ||
                    (score == st.windowPeakScore &&
                     st.currentStride.evidence > st.peakStride.evidence))
                {
                    st.windowPeakScore = score;
                    st.peakStride = st.currentStride;
                }
                if (score > m_threshold && st.windowFirstExceed < 0.0)
                {
                    st.windowFirstExceed = now;
                }
                ObserveStreamWindowExceed(st, now, score, m_threshold);
            }
        }
    }

    /* Identity-keyed sequential plausibility detector. */
    double Assess(const Bsm& b, double now, int64_t& evaluationOnlyNanos)
    {
        NeighborState& st = m_neighbors[b.claimedId];
        if (!st.have)
        {
            st.logEvidence = m_initialLogEvidence;
        }

        // The checks run during warm-up so kinematic history is available,
        // but accumulated evidence, track evidence and STRIDE attribution are
        // all cleared when measurement begins.  Keeping only the identity
        // score reset allowed a pre-warm-up violation to leak into the final
        // STRIDE label even though it could not contribute to S_peak.
        if (!st.warmReset && now >= g_warmup)
        {
            ResetMeasurementState(st, m_initialLogEvidence);
        }

        bool fired[CHK_COUNT] = {};

        // -- CHK_MAP_BOUNDS ------------------------------------------
        fired[CHK_MAP_BOUNDS] =
            (b.x < -50.0 || b.x > ROAD_LEN + 50.0 ||
             std::fabs(b.y) > ROAD_WIDTH);

        // -- CHK_STALENESS -------------------------------------------
        fired[CHK_STALENESS] = ((now - b.txTime) > MAX_AGE);

        // -- CHK_REPLAY ----------------------------------------------
        if (st.have)
        {
            fired[CHK_REPLAY] = (st.seenSeq.count(b.seq) > 0) ||
                                (b.txTime <= st.lastTxTime);
        }

        // -- CHK_POSITION_JUMP / CHK_SPEED_MISMATCH / CHK_HEADING ----
        //
        // NOISE-AWARE KINEMATICS. Differencing two noisy positions over a
        // short interval amplifies sensor error: the implied-speed error has
        // std-dev sqrt(2)*sigma/dt, which at sigma = 2 m and dt = 0.1 s is
        // 28 m/s -- roughly twice SPEED_TOL. Comparing consecutive beacons
        // therefore trips the kinematic checks on ordinary honest traffic and
        // drives FPR to 1.0.
        //
        // Two corrections: (a) compare against a REFERENCE sample at least
        // MIN_REF_DT old, which cuts the error by the ratio of intervals, and
        // (b) widen the tolerances by 3 sigma of the residual error. Both are
        // derived from the declared sensor model, not tuned to the result.
        if (st.refValid)
        {
            double dt = b.txTime - st.refTime;
            if (dt >= (g_naiveThresh ? 1e-6 : MIN_REF_DT))
            {
                double dx = b.x - st.refX;
                double dy = b.y - st.refY;
                double sigmaV = std::sqrt(2.0) * g_detectorGpsSigma / dt;
                double jumpTol  = g_naiveThresh ? VMAX : VMAX + 3.0 * sigmaV;
                double speedTol = g_naiveThresh
                                      ? SPEED_TOL
                                      : SPEED_TOL +
                                            3.0 * std::sqrt(sigmaV * sigmaV +
                                                            g_spdSigma * g_spdSigma);
                double implied = std::sqrt(dx * dx + dy * dy) / dt;
                double asserted = std::sqrt(b.vx * b.vx + b.vy * b.vy);
                fired[CHK_POSITION_JUMP] = (implied > jumpTol);
                fired[CHK_SPEED_MISMATCH] =
                    (std::fabs(implied - asserted) > speedTol);

                // -- CHK_HEADING -------------------------------------
                // Compare the asserted velocity DIRECTION against the
                // direction actually travelled. Negating the velocity
                // vector leaves |v| untouched, so SPEED_MISMATCH is blind
                // to it; the dot product is not. Only meaningful once the
                // vehicle has moved well beyond GPS noise.
                double disp = std::sqrt(dx * dx + dy * dy);
                if (disp > 3.0 * g_detectorGpsSigma && asserted > 1.0)
                {
                    double cosang = (dx * b.vx + dy * b.vy) / (disp * asserted);
                    fired[CHK_HEADING] = (cosang < HEADING_COS_MIN);
                }

                // Advance the reference only once it has been used, so the
                // comparison baseline never shrinks below MIN_REF_DT.
                st.refX = b.x;
                st.refY = b.y;
                st.refTime = b.txTime;
            }
        }
        else
        {
            st.refX = b.x;
            st.refY = b.y;
            st.refTime = b.txTime;
            st.refValid = true;
        }

        // -- CHK_RATE ------------------------------------------------
        st.rxTimes.push_back(now);
        while (!st.rxTimes.empty() && st.rxTimes.front() < now - RATE_WINDOW)
        {
            st.rxTimes.pop_front();
        }
        fired[CHK_RATE] =
            (static_cast<double>(st.rxTimes.size()) / RATE_WINDOW > RATE_LIMIT);

        // -- Sequential log-evidence update ----------------------------
        // The checks are correlated, especially the two displacement checks.
        // Therefore the sigmoid below is only a bounded decision-score
        // transform; it is not a calibrated probability or posterior.
        const double deltaTime = st.haveEvidenceUpdate
                                     ? std::max(0.0, now - st.lastEvidenceUpdate)
                                     : 0.0;
        const double decayFactor = st.haveEvidenceUpdate
                                       ? TimeDecayFactor(deltaTime,
                                                         m_decayHalfLife)
                                       : 1.0;
        double logEvidence =
            decayFactor *
                std::max(-LOG_EVIDENCE_CLAMP,
                         std::min(LOG_EVIDENCE_CLAMP, st.logEvidence)) +
            (1.0 - decayFactor) * m_initialLogEvidence;

        // Sequential evidence update in log-odds. Each fired check k
        // contributes its log-evidence weight log(d_k/f_k); the running total
        // is a bounded log-evidence score, NOT posterior log-odds -- the
        // checks are correlated and the weights are assumptions, so the
        // quantity is not calibrated. See the header note.
        //
        // THREAT ATTRIBUTION, and why it is keyed on evidence.
        // The class is the STRIDE tag of the class receiving the largest
        // check contribution this frame. Selecting instead by largest DREAD
        // impact -- as an earlier revision did -- makes the assigned class a
        // function of the impact weights, and the priority index then
        // multiplies that same weight in twice. Attribution must depend only
        // on what was observed.
        //
        // A plausibility violation can be consistent with more than one STRIDE
        // class, so when the runner-up class comes within STRIDE_AMBIGUITY of
        // the winner the frame is ambiguous. The frame attached to S_peak is
        // the reported attribution; this prevents a lower-score observation
        // elsewhere in W from determining Q.
        for (int k = 0; k < CHK_COUNT; ++k)
        {
            const CheckModel& c = g_check[k];
            const double contribution = std::log(c.d / c.f);
            logEvidence +=
                fired[k] ? contribution
                         : (m_nullEvidence
                                ? std::log((1.0 - c.d) / (1.0 - c.f))
                                : 0.0);
        }
        st.currentStride = AttributeStrideFrame(fired);
        logEvidence =
            std::max(-LOG_EVIDENCE_CLAMP,
                     std::min(LOG_EVIDENCE_CLAMP, logEvidence));
        st.logEvidence = logEvidence;
        st.haveEvidenceUpdate = true;
        st.lastEvidenceUpdate = now;
        double score = 1.0 / (1.0 + std::exp(-logEvidence));

        /* --- MITIGATION: evaluate and accumulate evidence per TRACK -------
         * Associate this reception with the kinematic track it continues,
         * then evaluate replay, rate and kinematic checks against that track's
         * independent history before applying the identical evidence update.
         * Stateless map/freshness checks are recomputed from the frame. Uses
         * message content only -- no source address, no PKI -- so unlike the
         * identity-contested signal this is deployable.
         *
         * Deliberately NOT fed back into `score`: the identity-keyed value
         * remains the primary endpoint so the two keyings can be compared
         * within a single run over identical random draws. */
        {
            const double asserted = std::hypot(b.vx, b.vy);
            int chosen = -1;
            double bestCost = std::numeric_limits<double>::infinity();
            // Expiry archives sufficient statistics and releases the slot.
            // Reusing that slot bounds retained storage at TRACK_MAX instead
            // of appending one dead Track for every expiry cycle.
            ExpireTracks(st, now, &evaluationOnlyNanos);
            for (size_t t = 0; t < st.tracks.size(); ++t)
            {
                Track& tr = st.tracks[t];
                if (!tr.valid)
                {
                    continue;
                }
                const double dt = b.txTime - tr.refTime;
                if (dt < 0.0)
                {
                    continue;   // stale relative to this track
                }
                // Predict forward on the track's own last asserted velocity
                // and gate on sensor noise plus a physical speed allowance.
                const double px = tr.refX + tr.vx * dt;
                const double py = tr.refY + tr.vy * dt;
                const double residual = std::hypot(b.x - px, b.y - py);
                const double gate =
                    TRACK_GATE_SIGMA * g_detectorGpsSigma + VMAX * dt;
                if (residual <= gate && residual < bestCost)
                {
                    bestCost = residual;
                    chosen = static_cast<int>(t);
                }
            }
            if (chosen < 0)
            {
                // No existing trajectory explains this message: a second
                // transmitter is claiming this identity, or the sender just
                // teleported. Either way it gets its own evidence account.
                chosen = AllocateTrackSlot(st, m_initialLogEvidence);
            }
            std::chrono::steady_clock::time_point evaluationOnlyStart;
            if (chosen >= 0)
            {
                Track& tr = st.tracks[chosen];
                bool trackFired[CHK_COUNT] = {};
                EvaluateTrackChecks(tr, b, now, trackFired);
                const double trackDelta =
                    tr.haveEvidenceUpdate ? now - tr.lastEvidenceUpdate : 0.0;
                const double trackDecay =
                    tr.haveEvidenceUpdate
                        ? TimeDecayFactor(trackDelta, m_decayHalfLife)
                        : 1.0;
                double trackEvidence =
                    trackDecay * std::max(-LOG_EVIDENCE_CLAMP,
                                          std::min(LOG_EVIDENCE_CLAMP,
                                                   tr.logEvidence)) +
                    (1.0 - trackDecay) * m_initialLogEvidence;
                for (int k = 0; k < CHK_COUNT; ++k)
                {
                    const CheckModel& c = g_check[k];
                    trackEvidence +=
                        trackFired[k]
                            ? std::log(c.d / c.f)
                            : (m_nullEvidence
                                   ? std::log((1.0 - c.d) / (1.0 - c.f))
                                   : 0.0);
                }
                trackEvidence = std::max(-LOG_EVIDENCE_CLAMP,
                                         std::min(LOG_EVIDENCE_CLAMP,
                                                  trackEvidence));
                tr.logEvidence = trackEvidence;
                tr.haveEvidenceUpdate = true;
                tr.lastEvidenceUpdate = now;
                tr.refX = b.x;
                tr.refY = b.y;
                tr.refTime = b.txTime;
                tr.vx = b.vx;
                tr.vy = b.vy;
                tr.lastTime = now;
                // Everything below is evaluation-window measurement or
                // harness truth/quality bookkeeping. Stop charging it to the
                // deployable identity+NN detector before doing any of it.
                evaluationOnlyStart = std::chrono::steady_clock::now();
                if (now >= g_evalStart)
                {
                    ++tr.windowMsgs;
                    tr.windowPeakScore =
                        std::max(tr.windowPeakScore,
                                 1.0 / (1.0 + std::exp(-trackEvidence)));
                }
                // Harness labels only; never read by the association logic.
                if (now >= g_evalStart)
                {
                    ++tr.msgs;
                    tr.carriedMalicious |=
                        (b.oracleMessageIsMalicious != 0);
                    tr.carriedOwner |= (b.oracleId == b.claimedId);
                    ++tr.srcCounts[b.oracleId];
                    if (tr.lastSrc != std::numeric_limits<uint32_t>::max() &&
                        tr.lastSrc != b.oracleId)
                    {
                        ++tr.idSwitches;   // association crossed transmitters
                    }
                    tr.lastSrc = b.oracleId;
                }
            }
            else
            {
                evaluationOnlyStart = std::chrono::steady_clock::now();
                if (now >= g_evalStart)
                {
                    // A full bounded tracker silently omitted this message in
                    // earlier revisions.  Keep the arm bounded, but expose
                    // every W-local omission so mitigation results cannot be
                    // interpreted without their capacity loss rate.
                    ++st.trackCapacityDrops;
                }
            }

            /* Perfect-association arm. Identical per-track checking and
             * accumulation, but the key is the harness's true source instead
             * of an associated trajectory.
             * EVALUATION ONLY -- reads the oracle, so it is not deployable; it
             * exists to bound what a better tracker could buy. */
            {
                Track& ot = st.oracleTracks[b.oracleId];
                if (!ot.valid)
                {
                    ot.valid = true;
                    ot.logEvidence = m_initialLogEvidence;
                }
                bool oracleFired[CHK_COUNT] = {};
                EvaluateTrackChecks(ot, b, now, oracleFired);
                const double oDelta =
                    ot.haveEvidenceUpdate ? now - ot.lastEvidenceUpdate : 0.0;
                const double oDecay =
                    ot.haveEvidenceUpdate
                        ? TimeDecayFactor(oDelta, m_decayHalfLife)
                        : 1.0;
                double oEvidence =
                    oDecay * std::max(-LOG_EVIDENCE_CLAMP,
                                      std::min(LOG_EVIDENCE_CLAMP,
                                               ot.logEvidence)) +
                    (1.0 - oDecay) * m_initialLogEvidence;
                for (int k = 0; k < CHK_COUNT; ++k)
                {
                    const CheckModel& c = g_check[k];
                    oEvidence +=
                        oracleFired[k]
                            ? std::log(c.d / c.f)
                            : (m_nullEvidence
                                   ? std::log((1.0 - c.d) / (1.0 - c.f))
                                   : 0.0);
                }
                oEvidence = std::max(-LOG_EVIDENCE_CLAMP,
                                     std::min(LOG_EVIDENCE_CLAMP, oEvidence));
                ot.logEvidence = oEvidence;
                ot.haveEvidenceUpdate = true;
                ot.lastEvidenceUpdate = now;
                if (now >= g_evalStart)
                {
                    ++ot.msgs;
                    ++ot.windowMsgs;
                    ot.windowPeakScore =
                        std::max(ot.windowPeakScore,
                                 1.0 / (1.0 + std::exp(-oEvidence)));
                    ot.carriedMalicious |=
                        (b.oracleMessageIsMalicious != 0);
                    ot.carriedOwner |= (b.oracleId == b.claimedId);
                }
                const auto evaluationOnlyEnd =
                    std::chrono::steady_clock::now();
                evaluationOnlyNanos +=
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        evaluationOnlyEnd - evaluationOnlyStart)
                        .count();
            }
            (void)asserted;
        }

        // Update history
        st.have = true;
        // max(), not assignment: a replayed stale message would otherwise
        // roll the monotonic-timestamp baseline backwards and let every
        // subsequent stale message pass CHK_REPLAY.
        st.lastTxTime = std::max(st.lastTxTime, b.txTime);
        if (st.seenSeq.insert(b.seq).second)
        {
            st.seqFifo.push_back(b.seq);
        }
        // Evict oldest-INSERTED, not lowest-valued. A std::set is ordered by
        // value, so erase(begin()) let an attacker injecting low sequence
        // numbers flush the genuine history and defeat CHK_REPLAY.
        if (st.seqFifo.size() > 500)
        {
            st.seenSeq.erase(st.seqFifo.front());
            st.seqFifo.pop_front();
        }

        return score;
    }

  public:
    // Collapse one receiver's identity-keyed states into evaluation records.
    void Finalize()
    {
        if (m_role != HONEST || !m_detectorOn)
        {
            return;
        }
        for (const auto& kv : m_neighbors)
        {
            const NeighborState& st = kv.second;
            if (st.msgs == 0)
            {
                continue;
            }
            double ttd = (st.firstCross >= 0.0 && st.firstSeen >= 0.0)
                             ? st.firstCross - st.firstSeen
                             : -1.0;
            // Latency clock for the PRIMARY endpoint. Measured from when the
            // hostile stream first became observable INSIDE W, using the same
            // "score > threshold" test the classification uses. The v4 clock
            // required a NEW crossing, so a pair could simultaneously be a
            // classification true positive and a survival non-event.
            const double streamOnset =
                (st.firstHostileSeen >= 0.0)
                    ? std::max(g_evalStart, st.firstHostileSeen)
                    : -1.0;
            double streamTtd =
                (streamOnset >= 0.0 &&
                 st.streamWindowFirstExceed >= streamOnset)
                    ? st.streamWindowFirstExceed - streamOnset
                    : -1.0;
            bool preexistingAlert =
                st.firstCross >= 0.0 && st.firstHostileSeen >= 0.0 &&
                st.firstCross < st.firstHostileSeen;
            double finalScore =
                1.0 / (1.0 + std::exp(-st.logEvidence));
            PairRecord p;
            p.receiverId = m_id;
            p.claimedId = kv.first;
            p.sourceIds = st.sourceIds;
            p.sourceRoles = st.sourceRoles;
            p.observableSourceIps = st.observableSourceIps;
            p.victimIds = st.victimIds;
            p.ownerSeen = st.sawOwner;
            p.assignedAttackerUse = st.sawAssignedAttackerUse;
            p.attackActiveUse = st.sawAttackActiveUse;
            p.hostileUse = st.sawHostileUse;
            p.maliciousMsgs = st.maliciousMsgs;
            p.everContested = st.identityContested;
            p.contestedStreamAlert = st.firstStreamContested >= 0.0;
            p.preexistingContested =
                st.firstContested >= 0.0 && st.firstHostileSeen >= 0.0 &&
                st.firstContested < st.firstHostileSeen;
            p.firstContested = st.firstContested;
            p.firstStreamContested = st.firstStreamContested;
            p.ownerIsAttacker = IsAttackerId(kv.first);
            p.peakScore = st.peakScore;
            p.streamPeakScore = st.sawHostileUse
                                    ? st.postHostilePeakScore
                                    : st.peakScore;
            p.finalScore = finalScore;
            p.finalAlert = finalScore > m_threshold;
            p.everAlert = st.firstCross >= 0.0;
            p.streamAlert = st.firstStreamCross >= 0.0;
            p.preexistingAlert = preexistingAlert;
            p.firstSeen = st.firstSeen;
            p.firstCross = st.firstCross;
            p.firstHostileSeen = st.firstHostileSeen;
            p.firstStreamCross = st.firstStreamCross;
            p.lastSeen = st.lastSeen;
            p.timeToDetect = ttd;
            p.streamTimeToDetect = streamTtd;
            p.postOnsetCrossingIntervals =
                MergeCrossingIntervals(st.postOnsetCrossingIntervals);
            p.msgs = st.msgs;

            // --- PRIMARY endpoint ---
            p.eligible = st.windowMsgs > 0;
            p.windowMsgs = st.windowMsgs;
            p.windowExposure =
                (st.windowFirstSeen >= 0.0 && st.windowLastSeen >= 0.0)
                    ? std::max(0.0, st.windowLastSeen - st.windowFirstSeen)
                    : 0.0;
            p.windowPeakScore = st.windowPeakScore;
            p.windowFirstExceed = st.windowFirstExceed;
            p.windowAlert = p.eligible && st.windowPeakScore > m_threshold;

            // --- track-keyed decision ---
            p.trackCount = st.retiredWindowTracks;
            p.maxTrackPeak = st.retiredMaxTrackPeak;
            p.honestTrackPeak = st.retiredHonestTrackPeak;
            p.ownerTrackPeak = st.retiredOwnerTrackPeak;
            p.trackCapacityDrops = st.trackCapacityDrops;
            p.trackMerges = st.retiredTrackMerges;
            p.trackIdSwitches = st.retiredTrackIdSwitches;
            double purityNum = st.retiredPurityNumerator;
            uint64_t purityDen = st.retiredPurityDenominator;
            std::set<uint32_t> sourcesSeen = st.retiredSourcesSeen;
            uint32_t tracksWithMessages = st.retiredTracksWithMessages;
            for (const Track& tr : st.tracks)
            {
                if (!tr.valid || tr.msgs == 0)
                {
                    continue;
                }
                ++tracksWithMessages;
                uint64_t dominant = 0;
                for (const auto& kv : tr.srcCounts)
                {
                    dominant = std::max(dominant, kv.second);
                    sourcesSeen.insert(kv.first);
                }
                purityNum += static_cast<double>(dominant);
                purityDen += tr.msgs;
                p.trackMerges += (tr.srcCounts.size() > 1) ? 1u : 0u;
                p.trackIdSwitches += tr.idSwitches;

                if (tr.windowMsgs == 0)
                {
                    continue;
                }
                ++p.trackCount;
                p.maxTrackPeak = std::max(p.maxTrackPeak, tr.windowPeakScore);
                if (!tr.carriedMalicious)
                {
                    p.honestTrackPeak =
                        std::max(p.honestTrackPeak, tr.windowPeakScore);
                }
                if (tr.carriedOwner)
                {
                    p.ownerTrackPeak =
                        std::max(p.ownerTrackPeak, tr.windowPeakScore);
                }
            }
            p.trackPurity = purityDen ? purityNum / static_cast<double>(purityDen)
                                      : 1.0;
            // One track per true source is the ideal; anything beyond that is
            // fragmentation of a single transmitter across several tracks.
            p.trackFragments =
                (tracksWithMessages > sourcesSeen.size())
                    ? static_cast<uint32_t>(tracksWithMessages -
                                            sourcesSeen.size())
                    : 0u;

            p.oracleTrackHonestPeak = 0.0;
            for (const auto& kv : st.oracleTracks)
            {
                const Track& ot = kv.second;
                if (ot.windowMsgs == 0 || ot.carriedMalicious)
                {
                    continue;
                }
                p.oracleTrackHonestPeak =
                    std::max(p.oracleTrackHonestPeak, ot.windowPeakScore);
            }
            p.strideClass = st.peakStride.category;
            p.strideAmbiguous = st.peakStride.ambiguous;
            p.strideMargin = st.peakStride.category == S_NONE
                                 ? 0.0
                                 : st.peakStride.evidence -
                                       st.peakStride.runnerUpEvidence;
            p.strideImpact = st.peakStride.category == S_NONE
                                 ? 0.0
                                 : g_strideImpact[st.peakStride.category];
            p.peakPriority =
                PriorityIndex(p.windowPeakScore, p.strideClass);
            // ONE decision variable. The trust label is the detection decision
            // -- score against tau -- so it cannot disagree with windowAlert.
            // A previous revision banded the priority index here instead,
            // which gave the paper two different decision rules and made the
            // reported label depend on the DREAD weights.
            p.trustCompromised = p.windowAlert;

            p.trackAlert = p.eligible && p.maxTrackPeak > m_threshold;
            p.honestTrackAlert =
                p.eligible && p.honestTrackPeak > m_threshold;
            p.ownerTrackAlert =
                p.eligible && p.ownerTrackPeak > m_threshold;
            p.oracleTrackHonestAlert =
                p.eligible && p.oracleTrackHonestPeak > m_threshold;

            g_pairs.push_back(std::move(p));
        }
    }

  private:
    double     m_decayHalfLife = 3.430961849152064;
    bool       m_nullEvidence = false;
    uint32_t   m_id = 0;
    Role       m_role = HONEST;
    Ipv4Address m_bcast;
    Ipv4Address m_selfAddr;
    uint16_t   m_port = 0;
    double     m_interval = 0.1;
    bool       m_detectorOn = true;
    double     m_initialLogEvidence = 0.0;
    double     m_threshold = 0.5;
    uint32_t   m_victimId = 0;
    uint32_t   m_seq = 0;
    uint32_t   m_oracleSeq = 0;
    Ptr<Socket> m_socket;
    EventId    m_sendEvent;
    Ptr<UniformRandomVariable> m_rng;
    Ptr<NormalRandomVariable> m_norm;
    double m_arX = 0.0;          // AR(1) state, NOISE_CORRELATED only
    double m_arY = 0.0;
    double m_biasX = 0.0;        // fixed per-vehicle offset, NOISE_BIASED only
    double m_biasY = 0.0;
    double     m_clockOffset = 0.0;   // fixed per-vehicle clock offset, seconds
    double     m_offsetX = 0.0;       // CONST_OFFSET: fixed position bias
    double     m_offsetY = 0.0;
    std::map<uint32_t, NeighborState> m_neighbors;
    std::deque<Bsm> m_captured;
};

/* =====================================================================
 * 6. Metrics
 * ===================================================================== */

// An undefined rate is NaN, not zero. With attackerFraction = 0 there are no
// positives, so TPR is 0/0; returning 0.0 plots as "detector completely
// failed" at the benign operating point. NaN propagates and pandas drops it.
static const double UNDEF = std::numeric_limits<double>::quiet_NaN();

struct Confusion
{
    uint64_t tp = 0, fp = 0, tn = 0, fn = 0;
    double Tpr() const { return tp + fn ? double(tp) / (tp + fn) : UNDEF; }
    double Fpr() const { return fp + tn ? double(fp) / (fp + tn) : UNDEF; }
    double Precision() const { return tp + fp ? double(tp) / (tp + fp) : UNDEF; }
    double F1() const
    {
        uint64_t denominator = 2 * tp + fp + fn;
        return denominator ? double(2 * tp) / double(denominator) : UNDEF;
    }
};

static void AddDecision(Confusion& c, bool prediction, bool truth)
{
    if (prediction && truth) ++c.tp;
    else if (prediction && !truth) ++c.fp;
    else if (!prediction && truth) ++c.fn;
    else ++c.tn;
}

struct PairResult
{
    // PRIMARY endpoint. Every confusion matrix below is produced by one rule
    // -- windowPeakScore > threshold -- over one calendar window shared by
    // both classes. Pairs with no exposure inside that window are excluded
    // rather than counted as free true negatives.
    Confusion streamEver;
    Confusion ownerEver;   // truth: the claimed identity's owner is hostile
    Confusion streamFinal;
    Confusion ownerFinal;
    // EVALUATION-ONLY identifiability bound, NOT a deployable mitigation.
    // This keys on the receiver-observable UDP source address, which in this
    // simulation is static, unique per node and unspoofable. A real adversary
    // spoofs L2/L3 as readily as the application-layer identity, so these
    // numbers are an upper bound on what source-based disambiguation could
    // achieve, not a defence that can be fielded. It is also structurally
    // incapable of firing for attacks that do not impersonate.
    Confusion contested;
    uint64_t cleanFp = 0;
    uint64_t cleanTn = 0;
    uint64_t victimPairs = 0;
    uint64_t victimPairsAlerted = 0;
    uint64_t victimIds = 0;
    uint64_t victimIdsAlerted = 0;
    uint64_t victimPairsContested = 0;
    uint64_t victimIdsContested = 0;
    uint64_t eligiblePairs = 0;
    uint64_t ineligiblePairs = 0;
    // Mitigation arm: same victims, decided by track instead of identity.
    uint64_t victimPairsTrackAlerted = 0;
    uint64_t victimIdsTrackAlerted = 0;
    uint64_t trackCapacityDrops = 0;
    Confusion streamTrack;
    double medianTtd = UNDEF;
    double ttdDetectedFrac = UNDEF;
};

static PairResult EvaluatePairs()
{
    PairResult r;
    std::vector<double> ttds;
    uint64_t hostilePairs = 0;
    std::set<uint32_t> victimIds;
    std::set<uint32_t> alertedVictimIds;
    std::set<uint32_t> contestedVictimIds;
    std::set<uint32_t> trackAlertedVictimIds;

    for (const auto& p : g_pairs)
    {
        // A pair with no exposure inside W has no decision to contribute.
        // Excluding it also removes a v4 bias: pairs whose contact ended
        // before the attack began were counted as free true negatives
        // against a true-positive rate measured over a strictly later
        // window.
        if (!p.eligible)
        {
            ++r.ineligiblePairs;
            continue;
        }
        ++r.eligiblePairs;
        r.trackCapacityDrops += p.trackCapacityDrops;

        // ONE statistic, ONE window, applied identically to both classes.
        AddDecision(r.streamEver, p.windowAlert, p.hostileUse);
        // Mitigation arm: does track keying retain stream detection?
        AddDecision(r.streamTrack, p.trackAlert, p.hostileUse);
        AddDecision(r.ownerEver, p.windowAlert, p.ownerIsAttacker);
        AddDecision(r.streamFinal, p.finalAlert, p.hostileUse);
        AddDecision(r.ownerFinal, p.finalAlert, p.ownerIsAttacker);
        // Contestation is monotone and cannot occur before onset (every
        // sender uses its own address until it starts impersonating), so no
        // rule asymmetry is needed here either.
        AddDecision(r.contested, p.everContested, p.hostileUse);

        bool cleanPair = !p.ownerIsAttacker && !p.hostileUse;
        if (cleanPair)
        {
            p.windowAlert ? ++r.cleanFp : ++r.cleanTn;
        }

        const bool victimExposurePair =
            !p.ownerIsAttacker && p.hostileUse;
        if (victimExposurePair)
        {
            ++r.victimPairs;
            victimIds.insert(p.claimedId);
            // Victim framing uses the same window and rule as every other
            // decision. Pre-onset excursions are excluded by W, so they are
            // not miscredited to the impersonation.
            if (p.windowAlert)
            {
                ++r.victimPairsAlerted;
                alertedVictimIds.insert(p.claimedId);
            }
            // The measurement the mitigation exists for: is the VICTIM's own
            // trajectory convicted? Identity keying charges the attacker's
            // forged messages to this identity; track keying should not.
            if (p.ownerTrackAlert)
            {
                ++r.victimPairsTrackAlerted;
                trackAlertedVictimIds.insert(p.claimedId);
            }
            if (p.contestedStreamAlert)
            {
                ++r.victimPairsContested;
                contestedVictimIds.insert(p.claimedId);
            }
        }

        if (p.hostileUse)
        {
            ++hostilePairs;
            if (p.streamTimeToDetect >= 0.0)
            {
                ttds.push_back(p.streamTimeToDetect);
            }
        }
    }
    r.victimIds = victimIds.size();
    r.victimIdsAlerted = alertedVictimIds.size();
    r.victimIdsContested = contestedVictimIds.size();
    r.victimIdsTrackAlerted = trackAlertedVictimIds.size();
    if (hostilePairs)
    {
        r.ttdDetectedFrac = double(ttds.size()) / double(hostilePairs);
    }
    if (!ttds.empty())
    {
        std::sort(ttds.begin(), ttds.end());
        size_t mid = ttds.size() / 2;
        r.medianTtd = ttds.size() % 2
                          ? ttds[mid]
                          : 0.5 * (ttds[mid - 1] + ttds[mid]);
    }
    return r;
}

// Pair-level Mann-Whitney AUC over the PRIMARY decision statistic. Ranking by
// exactly the quantity the operating point thresholds is what places the
// reported (FPR, TPR) point on the reported curve. In v4 the AUC ranked peak
// scores while the endpoint required a new post-onset crossing, so the curve
// was systematically optimistic relative to its own operating point.
// ownerTruth selects the label only.
static double PairAuc(bool ownerTruth)
{
    std::vector<double> positive;
    std::vector<double> negative;
    for (const auto& p : g_pairs)
    {
        if (!p.eligible)
        {
            continue;
        }
        bool truth = ownerTruth ? p.ownerIsAttacker : p.hostileUse;
        (truth ? positive : negative).push_back(p.windowPeakScore);
    }
    if (positive.empty() || negative.empty())
    {
        return UNDEF;
    }
    double wins = 0.0;
    for (double p : positive)
    {
        for (double n : negative)
        {
            wins += p > n ? 1.0 : (p == n ? 0.5 : 0.0);
        }
    }
    return wins / double(positive.size() * negative.size());
}

/* Average precision (area under the precision-recall curve) over the same
 * statistic and the same eligible population as PairAuc. ROC-AUC is optimistic
 * under class imbalance, and hostile pairs are a small minority of every arm
 * here, so PR-AUC is the more honest ranking summary and the reviewer asked
 * for both. Computed by the step-wise sum of precision at each recall
 * increase, with ties handled by processing a whole tied group at once. */
[[maybe_unused]] static double PairPrAuc(bool ownerTruth)
{
    std::vector<std::pair<double, bool>> scored;
    uint64_t positives = 0;
    for (const auto& p : g_pairs)
    {
        if (!p.eligible)
        {
            continue;
        }
        const bool truth = ownerTruth ? p.ownerIsAttacker : p.hostileUse;
        positives += truth ? 1u : 0u;
        scored.emplace_back(p.windowPeakScore, truth);
    }
    if (positives == 0 || positives == scored.size())
    {
        return UNDEF;
    }
    std::sort(scored.begin(), scored.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    double ap = 0.0;
    uint64_t tp = 0, seen = 0;
    for (size_t i = 0; i < scored.size();)
    {
        size_t j = i;
        uint64_t groupTp = 0;
        while (j < scored.size() && scored[j].first == scored[i].first)
        {
            groupTp += scored[j].second ? 1u : 0u;
            ++j;
        }
        tp += groupTp;
        seen = j;
        if (groupTp)
        {
            // Precision at this operating point, weighted by the recall gained.
            ap += (static_cast<double>(tp) / static_cast<double>(seen)) *
                  (static_cast<double>(groupTp) /
                   static_cast<double>(positives));
        }
        i = j;
    }
    return ap;
}

/* Largest score any clean pair reached, and its distance below the decision
 * threshold. With zero observed false positives the rate alone says nothing
 * about how close the detector came to one; this margin does. */
[[maybe_unused]] static double MaxCleanScore()
{
    double worst = 0.0;
    bool any = false;
    for (const auto& p : g_pairs)
    {
        if (!p.eligible || p.hostileUse || p.ownerIsAttacker)
        {
            continue;
        }
        any = true;
        worst = std::max(worst, p.windowPeakScore);
    }
    return any ? worst : UNDEF;
}

/* =====================================================================
 * 7. Main
 * ===================================================================== */

// Must match the trailing std::cout << "CSV," ... line exactly.
static const char* CSV_SCHEMA =
    "schema,n,frac,n_attackers,attack,run,sim_time,interval,detector,score_model,"
    "mobility,"
    "null_ev,naive_th,prior,threshold,decay,decay_half_life_s,warmup,attack_start_s,"
    "comm_range,gps_sigma,"
    "detector_gps_sigma,spd_sigma,clock_sigma,bsm_bytes,sent,received,invalid_bsm,"
    "assigned_attacker_rx,attack_active_rx,malicious_rx,"
    "malicious_expected_pairs,malicious_expected_pairs_observed,"
    "malicious_observed_pairs_any_range,malicious_zero_reception_pairs,"
    "pairs,stream_tp,stream_fp,stream_tn,stream_fn,stream_tpr,stream_fpr,"
    "stream_precision,stream_f1,owner_tp,owner_fp,owner_tn,owner_fn,owner_tpr,"
    "owner_fpr,owner_precision,owner_f1,clean_fp,clean_tn,clean_fpr,victim_pairs,"
    "victim_pairs_alerted,victim_ids,victim_ids_alerted,contested_tp,contested_fp,"
    "contested_tn,contested_fn,contested_tpr,contested_fpr,contested_precision,"
    "contested_f1,victim_pairs_contested,victim_ids_contested,final_stream_tp,"
    "final_stream_fp,final_stream_tn,final_stream_fn,final_stream_tpr,"
    "final_stream_fpr,final_stream_precision,final_stream_f1,final_owner_tp,"
    "final_owner_fp,final_owner_tn,final_owner_fn,final_owner_tpr,final_owner_fpr,"
    "final_owner_precision,final_owner_f1,median_ttd,ttd_detected_frac,stream_auc,"
    "owner_auc,"
    "stream_pr_auc,owner_pr_auc,max_clean_score,clean_margin,"
    "latency_sum_s,latency_n,latency_ms,pdr_rx,pdr_expected,pdr,"
    "det_calls,det_nanos,det_us,"
    "det_p50_us,det_p95_us,det_p99_us,det_max_us,det_throughput_calls_per_s,"
    "peak_identity_keys_per_receiver,peak_live_tracks_per_receiver,"
    "estimated_state_payload_bytes_per_receiver,"
    // v5 primary-endpoint provenance
    "eval_window_start_s,onset_blank_s,eligible_pairs,ineligible_pairs,"
    "track_stream_tp,track_stream_fp,track_stream_tn,track_stream_fn,"
    "track_stream_tpr,track_stream_fpr,"
    "victim_pairs_track_alerted,victim_ids_track_alerted,"
    "track_capacity_dropped_messages";

static const char* PAIR_SCHEMA =
    "schema,n,frac,attack,run,score_model,threshold,decay_half_life_s,attack_start_s,"
    "receiver_id,claimed_id,source_count,source_ids,source_roles,"
    "observable_source_count,observable_source_ipv4s,identity_contested,"
    "contested_stream_alert,preexisting_contested,first_contested_s,"
    "first_stream_contested_s,owner_seen,"
    "assigned_attacker_use,attack_active_use,malicious_use,malicious_messages,"
    "owner_is_attacker,clean_pair,victim_exposure_pair,victim_ids,peak_score,"
    "stream_peak_score,final_score,final_alert,ever_alert,stream_alert,"
    "preexisting_alert,post_onset_crossing_intervals,first_seen_s,first_cross_s,"
    "time_to_detect_s,last_seen_s,"
    "observed_duration_s,censor_time_s,censored,first_malicious_seen_s,"
    "first_stream_cross_s,stream_time_to_detect_s,stream_observed_duration_s,"
    "stream_censor_time_s,stream_censored,messages,"
    // v5 primary endpoint: alert == (window_peak_score > threshold)
    "eval_window_start_s,eligible,window_msgs,window_exposure_s,"
    "window_peak_score,window_first_exceed_s,window_alert,"
    // mitigation: evidence keyed by kinematic track, not claimed identity
    "track_count,max_track_peak,honest_track_peak,owner_track_peak,"
    "track_alert,honest_track_alert,owner_track_alert,"
    "track_capacity_dropped_messages,"
    "track_purity,track_merges,track_fragments,track_id_switches,"
    "oracle_track_honest_peak,oracle_track_honest_alert,"
    // STRIDE / DREAD risk layer
    "stride_class,stride_ambiguous,stride_margin,stride_impact,"
    "priority_index,priority_band,trust_decision";

int main(int argc, char* argv[])
{
    uint32_t    nVehicles = 50;
    double      attackerFraction = 0.30;
    std::string attack = "mixed";     // spoof|falsify|replay|dos|mixed|none
    double      simTime = 60.0;
    double      interval = 0.1;       // 10 Hz nominal BSM rate
    double      prior = 0.05;         // initial bounded score
    double      threshold = 0.50;     // decision threshold on the score
    bool        detectorOn = true;    // set false to measure overhead
    uint32_t    runId = 1;
    bool        verbose = false;
    std::string traceFile = "";       // empty = no per-reception trace
    // This default has 0.98 retention over 0.1 s, matching the old default
    // while making memory invariant to message frequency.
    double      decayHalfLife = 3.430961849152064;
    double      legacyDecay = -1.0;   // deprecated per-nominal-message alias
    double      warmup = 5.0;         // s of start-up transient to discard
    double      attackStart = 10.0;   // assigned attackers switch after this time
    // Seconds to exclude after attack onset. Default 0: the knob exists for a
    // sensitivity check, not to move headline numbers. It cannot substitute
    // for the steady-state arm -- a single onset spike survives above a 0.5
    // threshold for several half-lives, so any blank large enough to excise
    // it would be threshold-dependent and would also delete exposure from the
    // negatives. Use --attackStart=0 to measure steady-state detectability.
    double      onsetBlank = 0.0;
    double      commRange = 300.0;    // m, nominal range for the PDR denominator
    bool        nullEvidence = false; // score non-firing checks as evidence too
    bool        csvHeaderOnly = false;
    std::string scoreModel = "reference";
    std::string mobilityModel = "constant";
    std::string llrAlias = "";
    std::string pairOutput = "";

    CommandLine cmd(__FILE__);
    cmd.AddValue("nVehicles", "Total vehicles", nVehicles);
    cmd.AddValue("attackerFraction", "Fraction hostile [0,1]", attackerFraction);
    cmd.AddValue("attack",
                 "none|spoof|falsify|replay|dos|constoffset|revheading|"
                 "slydos|mixed|mixedhard",
                 attack);
    cmd.AddValue("simTime", "Simulation seconds", simTime);
    cmd.AddValue("interval", "BSM interval (s)", interval);
    cmd.AddValue("prior", "Initial bounded score (not a calibrated prior)", prior);
    cmd.AddValue("threshold", "Decision-score threshold", threshold);
    cmd.AddValue("detector", "Enable detector (overhead baseline)", detectorOn);
    cmd.AddValue("run", "RNG run number (use >=30 distinct values)", runId);
    cmd.AddValue("verbose", "Per-node logging", verbose);
    cmd.AddValue("trace", "CSV file for per-reception trace (empty = off)", traceFile);
    cmd.AddValue("decayHalfLife", "Evidence half-life in seconds (-1 = never forget)",
                 decayHalfLife);
    cmd.AddValue("decay", "DEPRECATED: retention over one nominal interval (0,1]",
                 legacyDecay);
    cmd.AddValue("warmup", "Seconds of transient to discard", warmup);
    cmd.AddValue("onsetBlank",
                 "Seconds excluded after attack onset (sensitivity knob)",
                 onsetBlank);
    cmd.AddValue("attackStart", "Seconds when assigned attackers become active",
                 attackStart);
    cmd.AddValue("commRange", "Nominal comms range for the PDR denominator (m)", commRange);
    cmd.AddValue("nullEvidence", "Score non-firing checks (ablation; see header)", nullEvidence);
    cmd.AddValue("naiveThresholds", "Fixed kinematic thresholds on consecutive beacons (ablation)", g_naiveThresh);
    cmd.AddValue("gpsSigma", "Actual generated GNSS position noise std-dev (m)", g_gpsSigma);
    std::string noiseShapeArg = "gaussian";
    cmd.AddValue("noiseShape",
                 "Localisation-error shape: gaussian|student_t|biased|correlated",
                 noiseShapeArg);
    cmd.AddValue("noiseRho", "AR(1) coefficient for --noiseShape=correlated", g_noiseRho);
    cmd.AddValue("noiseBias", "Fixed per-vehicle offset (m) for --noiseShape=biased",
                 g_noiseBias);
    cmd.AddValue("detectorGpsSigma", "Detector-assumed GNSS position noise std-dev (m)", g_detectorGpsSigma);
    cmd.AddValue("spdSigma", "Speed noise std-dev (m/s)", g_spdSigma);
    cmd.AddValue("clockSigma",
                 "Std-dev of fixed per-vehicle clock offset (s)",
                 g_clockSigma);
    cmd.AddValue("bsmBytes", "On-air BSM size incl. 1609.2 overhead (B)", g_bsmBytes);
    cmd.AddValue("csvHeader", "Print the CSV schema and exit", csvHeaderOnly);
    cmd.AddValue("scoreModel", "Evidence weights: reference|simfit", scoreModel);
    cmd.AddValue("mobility",
                 "Mobility: constant|manoeuvre (bounded accel/braking and occasional one-tick lateral perturbations)",
                 mobilityModel);
    cmd.AddValue("llr", "Legacy alias: elicited|learned", llrAlias);
    cmd.AddValue("pairOutput", "Per receiver/claimed-identity CSV path", pairOutput);
    cmd.Parse(argc, argv);

    if      (noiseShapeArg == "gaussian")   g_noiseShape = NOISE_GAUSSIAN;
    else if (noiseShapeArg == "student_t")  g_noiseShape = NOISE_STUDENT_T;
    else if (noiseShapeArg == "biased")     g_noiseShape = NOISE_BIASED;
    else if (noiseShapeArg == "correlated") g_noiseShape = NOISE_CORRELATED;
    else
    {
        std::cerr << "ERROR: unknown --noiseShape=" << noiseShapeArg
                  << " (gaussian|student_t|biased|correlated)\n";
        return 1;
    }

    // The schema lives with the code that writes it. Keeping it in the sweep
    // script let the two drift apart silently and mislabel every column.
    if (csvHeaderOnly)
    {
        // Both schemas, so downstream tooling can be generated from the binary
        // instead of hand-maintained. Printing only the summary schema once
        // let a consumer silently adopt the wrong field list.
        std::cout << CSV_SCHEMA << "\n" << PAIR_SCHEMA << "\n";
        return 0;
    }

    if (!llrAlias.empty())
    {
        if (llrAlias == "elicited")
        {
            scoreModel = "reference";
        }
        else if (llrAlias == "learned")
        {
            scoreModel = "simfit";
        }
        else
        {
            std::cerr << "ERROR: --llr must be elicited or learned\n";
            return 2;
        }
    }

    const std::set<std::string> validAttacks = {
        "none",       "spoof",      "falsify", "replay",   "dos",
        "constoffset", "revheading", "slydos",  "mixed",   "mixedhard"};
    auto finite = [](double value) { return std::isfinite(value); };

    // Backward-compatible conversion only: --decay no longer means one
    // update per reception. It specifies retention over the nominal beacon
    // interval and is converted once to an equivalent wall-clock half-life.
    if (legacyDecay != -1.0)
    {
        if (!finite(legacyDecay) || legacyDecay <= 0.0 || legacyDecay > 1.0)
        {
            std::cerr << "ERROR: deprecated --decay must be in (0,1]\n";
            return 2;
        }
        decayHalfLife = legacyDecay == 1.0
                            ? -1.0
                            : -std::log(2.0) * interval / std::log(legacyDecay);
        std::cerr << "WARNING: --decay is deprecated; converted to "
                  << "--decayHalfLife=" << decayHalfLife << " s\n";
    }

    if (nVehicles < 2 || !finite(attackerFraction) ||
        attackerFraction < 0.0 || attackerFraction >= 1.0 ||
        validAttacks.count(attack) == 0 || !finite(simTime) ||
        !finite(interval) || !finite(prior) || !finite(threshold) ||
        !(decayHalfLife == -1.0 ||
          (finite(decayHalfLife) && decayHalfLife > 0.0)) ||
        !finite(warmup) || !finite(attackStart) || !finite(commRange) ||
        !finite(g_gpsSigma) || !finite(g_detectorGpsSigma) ||
        !finite(g_spdSigma) || !finite(g_clockSigma) || simTime <= 1.0 ||
        interval <= 0.0 || prior <= 0.0 || prior >= 1.0 ||
        threshold < 0.0 || threshold > 1.0 ||
        // attackStart == 0 is the steady-state arm: every attacker is
        // adversarial from its first transmitted message, so no onset
        // discontinuity exists for a plausibility check to latch onto.
        warmup < 0.0 || !finite(onsetBlank) || onsetBlank < 0.0 ||
        attackStart < 0.0 || !(attackStart < simTime) ||
        !(warmup < simTime) ||
        !(std::max(warmup, attackStart + onsetBlank) < simTime) ||
        commRange <= 0.0 ||
        g_noiseRho < 0.0 || g_noiseRho >= 1.0 || !finite(g_noiseRho) ||
        !finite(g_noiseBias) ||
        g_gpsSigma < 0.0 || g_detectorGpsSigma < 0.0 ||
        g_spdSigma < 0.0 || g_clockSigma < 0.0 ||
        g_bsmBytes < sizeof(Bsm) || runId == 0 ||
        (scoreModel != "reference" && scoreModel != "simfit") ||
        (mobilityModel != "constant" && mobilityModel != "manoeuvre"))
    {
        std::cerr
            << "ERROR: invalid configuration. Require nVehicles>=2, frac in [0,1), "
               "known attack/scoreModel/mobility, finite positive timing/range, prior in "
               "(0,1), threshold in [0,1], positive decayHalfLife (or -1), "
               "nonnegative noise, 0<=attackStart<simTime, warmup<simTime, "
               "max(warmup, attackStart+onsetBlank)<simTime, "
               "run>0, and bsmBytes>=sizeof(Bsm).\n";
        return 2;
    }

    g_check = scoreModel == "simfit" ? g_checkSimfit : g_checkReference;
    g_warmup = warmup;
    g_attackStart = attackStart;
    g_onsetBlank = onsetBlank;
    // One evaluation window for every pair of every class.
    g_evalStart = std::max(warmup, attackStart + onsetBlank);
    g_commRange = commRange;
    g_nVehicles = nVehicles;
    const double effectiveDecay = TimeDecayFactor(interval, decayHalfLife);

    if (!traceFile.empty())
    {
        g_trace.open(traceFile);
        if (!g_trace)
        {
            std::cerr << "ERROR: cannot open trace path: " << traceFile << "\n";
            return 2;
        }
        g_trace << std::setprecision(17);
        g_trace
            << "receiver_id,rx_time,receiver_true_x,receiver_true_y,"
               "observable_source_ipv4,claimed_id,"
               "claimed_seq,claimed_tx_time,claimed_x,claimed_y,claimed_vx,"
               "claimed_vy,oracle_source_id,oracle_tx_seq,oracle_tx_time,"
               "oracle_true_x,oracle_true_y,oracle_true_vx,oracle_true_vy,"
               "oracle_source_is_attacker,oracle_assigned_role,"
               "oracle_attack_active,oracle_message_is_malicious,oracle_victim_id,"
               "oracle_owner_is_attacker,"
               "oracle_expected_receiver\n";
    }

    RngSeedManager::SetSeed(12345);
    RngSeedManager::SetRun(runId);

    if (verbose)
    {
        LogComponentEnable("V2VCybersecurityV2", LOG_LEVEL_INFO);
    }

    uint32_t nAttackers =
        static_cast<uint32_t>(std::llround(nVehicles * attackerFraction));
    if (attack == "none")
    {
        nAttackers = 0;
    }
    if (nAttackers >= nVehicles)
    {
        std::cerr << "ERROR: configuration must leave at least one honest vehicle\n";
        return 2;
    }

    NodeContainer vehicles;
    vehicles.Create(nVehicles);

    /* --- 802.11p PHY/MAC ------------------------------------------- */
    YansWifiChannelHelper channel;
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                               "Exponent", DoubleValue(2.5),
                               "ReferenceLoss", DoubleValue(46.6777));
    channel.AddPropagationLoss("ns3::NakagamiPropagationLossModel");

    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    phy.Set("TxPowerStart", DoubleValue(20.0));   // dBm
    phy.Set("TxPowerEnd", DoubleValue(20.0));

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211p);
    wifi.SetRemoteStationManager(
        "ns3::ConstantRateWifiManager",
        "DataMode", StringValue("OfdmRate6MbpsBW10MHz"),
        "ControlMode", StringValue("OfdmRate6MbpsBW10MHz"));

    WifiMacHelper mac;
    // Exact model: WIFI_STANDARD_80211p with AdhocWifiMac, operating outside
    // a BSS and without association. No higher-layer vehicular control-plane
    // protocol is represented by this MAC configuration.
    mac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(phy, mac, vehicles);

    /* --- Highway mobility ------------------------------------------ */
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> pos = CreateObject<ListPositionAllocator>();
    Ptr<UniformRandomVariable> u = CreateObject<UniformRandomVariable>();

    // Build a balanced hostile-role multiset, then shuffle the complete role
    // vector across identities. Attacker status is therefore independent of
    // node ID and of the ID-derived lane/direction assignment below.
    std::vector<Role> roles(nVehicles, HONEST);
    std::vector<Role> attackMix;
    if (attack == "mixed")
    {
        attackMix = {SPOOFER, FALSIFIER, REPLAYER, FLOODER};
    }
    else if (attack == "mixedhard")
    {
        attackMix = {SPOOFER, FALSIFIER, REPLAYER, FLOODER,
                     CONST_OFFSET, REV_HEADING, SLY_FLOODER};
    }
    else if (attack == "spoof") attackMix = {SPOOFER};
    else if (attack == "falsify") attackMix = {FALSIFIER};
    else if (attack == "replay") attackMix = {REPLAYER};
    else if (attack == "dos") attackMix = {FLOODER};
    else if (attack == "constoffset") attackMix = {CONST_OFFSET};
    else if (attack == "revheading") attackMix = {REV_HEADING};
    else if (attack == "slydos") attackMix = {SLY_FLOODER};

    for (uint32_t i = 0; i < nAttackers; ++i)
    {
        roles[i] = attackMix[i % attackMix.size()];
    }
    for (uint32_t i = nVehicles - 1; i > 0; --i)
    {
        uint32_t j = std::min(
            i, static_cast<uint32_t>(u->GetValue(0.0, double(i + 1))));
        std::swap(roles[i], roles[j]);
    }

    std::vector<uint32_t> honestIds;
    for (uint32_t i = 0; i < nVehicles; ++i)
    {
        if (roles[i] == HONEST)
        {
            honestIds.push_back(i);
        }
        else
        {
            g_attackerIds.insert(i);
        }
    }

    // ConstantVelocityMobilityModel is UNBOUNDED: a vehicle spawned uniformly
    // over the segment drives straight off the end of it. At 60 s and 33 m/s
    // that is 1980 m of travel, so ~40% of HONEST vehicles would leave
    // [-50, ROAD_LEN+50] mid-run and be convicted by CHK_MAP_BOUNDS for it --
    // a modelling artifact that dominated the false-positive rate. Spawn each
    // vehicle far enough from its exit that it stays on the segment for the
    // whole run.
    const double kMaxSpeed = 33.0;
    double travel = kMaxSpeed * simTime;
    double spawnSpan = std::max(1.0, ROAD_LEN - travel);
    if (spawnSpan < 0.25 * ROAD_LEN)
    {
        std::cerr << "WARNING: simTime " << simTime << " s leaves only "
                  << spawnSpan << " m of spawn span on a " << ROAD_LEN
                  << " m segment; raise ROAD_LEN or lower simTime.\n";
    }

    std::vector<double> speeds(nVehicles);
    std::vector<double> dirs(nVehicles);
    for (uint32_t i = 0; i < nVehicles; ++i)
    {
        double lane = (i % 4) * 3.5 - 5.25;      // 4 lanes, 3.5 m wide
        dirs[i] = (i % 4 < 2) ? 1.0 : -1.0;      // two directions of travel
        double x = u->GetValue(0.0, spawnSpan);
        if (dirs[i] < 0.0)
        {
            x = ROAD_LEN - x;                    // mirror the westbound lanes
        }
        pos->Add(Vector(x, lane, 1.5));
        speeds[i] = u->GetValue(20.0, kMaxSpeed);   // 72-119 km/h
    }
    mobility.SetPositionAllocator(pos);
    mobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
    mobility.Install(vehicles);
    for (uint32_t i = 0; i < nVehicles; ++i)
    {
        vehicles.Get(i)
            ->GetObject<ConstantVelocityMobilityModel>()
            ->SetVelocity(Vector(speeds[i] * dirs[i], 0.0, 0.0));
    }

    /* --- Manoeuvring mobility (--mobility=manoeuvre) --------------------
     * Constant velocity is the favourable case for this detector: it makes
     * both the kinematic checks and nearest-trajectory association easier
     * than real driving, because no honest vehicle ever produces a kinematic
     * surprise. This arm removes that advantage.
     *
     * Rather than add a car-following model -- mainline ns-3 has none, and
     * writing one would introduce far more unvalidated behaviour than it
     * removes -- we re-set each vehicle's velocity on a fixed tick. Velocity
     * is therefore piecewise constant with genuine acceleration, braking and
     * lateral motion at the tick boundaries, which is what actually stresses
     * the checks. Bounds are ordinary highway values:
     *   longitudinal accel  |a| <= 2.5 m/s^2, speed held in [15, 35] m/s
     *   lateral perturbation one 1-s tick at 0.875 m/s (about 0.875 m)
     * Scope: piecewise-constant velocity, not a calibrated car-following
     * model. Swap in SUMO traces if fidelity of the mobility itself, rather
     * than its effect on the detector, becomes the research question. */
    if (mobilityModel == "manoeuvre")
    {
        const double kTick = 1.0;          // s between manoeuvre decisions
        const double kMaxAccel = 2.5;      // m/s^2
        const double kLaneWidth = 3.5;     // m
        Ptr<UniformRandomVariable> mv = CreateObject<UniformRandomVariable>();
        for (double t = warmup; t < simTime; t += kTick)
        {
            for (uint32_t i = 0; i < nVehicles; ++i)
            {
                Simulator::Schedule(
                    Seconds(t), [i, &vehicles, mv, kTick, kMaxAccel,
                                 kLaneWidth, kMaxSpeed]() {
                        Ptr<ConstantVelocityMobilityModel> m =
                            vehicles.Get(i)
                                ->GetObject<ConstantVelocityMobilityModel>();
                        Vector v = m->GetVelocity();
                        const double dir = (v.x >= 0.0) ? 1.0 : -1.0;
                        double speed = std::fabs(v.x);
                        // Accelerate or brake within the physical bound.
                        speed += mv->GetValue(-kMaxAccel, kMaxAccel) * kTick;
                        speed = std::max(15.0, std::min(kMaxSpeed, speed));
                        // Occasional one-tick lateral perturbation. The next
                        // tick redraws vy, so this is only a ~0.875 m lateral
                        // perturbation, not a sustained manoeuvre model.
                        double vy = 0.0;
                        if (mv->GetValue(0.0, 1.0) < 0.05)
                        {
                            vy = (mv->GetValue(0.0, 1.0) < 0.5 ? -1.0 : 1.0) *
                                 (kLaneWidth / 4.0);
                        }
                        m->SetVelocity(Vector(speed * dir, vy, 0.0));
                    });
            }
        }
    }

    /* --- Networking ------------------------------------------------- */
    InternetStackHelper internet;
    internet.Install(vehicles);

    Ipv4AddressHelper address;
    address.SetBase("10.1.0.0", "255.255.0.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);
    Ipv4Address bcast("10.1.255.255");
    uint16_t port = 8080;

    /* --- Applications ----------------------------------------------- */
    std::vector<Ptr<V2vBsmApp>> apps;
    for (uint32_t i = 0; i < nVehicles; ++i)
    {
        Role role = roles[i];
        uint32_t victim = honestIds.front();
        if (role == SPOOFER)
        {
            uint32_t k = std::min(
                static_cast<uint32_t>(honestIds.size() - 1),
                static_cast<uint32_t>(
                    u->GetValue(0.0, double(honestIds.size()))));
            victim = honestIds[k];
        }

        Ptr<V2vBsmApp> app = CreateObject<V2vBsmApp>();
        app->Setup(i, role, bcast, port, interval, detectorOn, prior,
                   threshold, victim, decayHalfLife, nullEvidence);
        vehicles.Get(i)->AddApplication(app);
        app->SetStartTime(Seconds(1.0));
        app->SetStopTime(Seconds(simTime));
        apps.push_back(app);
    }

    // No FlowMonitor: it does not track broadcast flows usefully, and an
    // installed-but-unread monitor costs memory and invites the question of
    // where the reported latency and PDR actually come from. Both are
    // measured directly in the application layer -- see g_expected/g_pdrRx.

    Simulator::Stop(Seconds(simTime + 1.0));
    Simulator::Run();

    for (auto& a : apps)
    {
        a->Finalize();
    }

    /* --- Results ---------------------------------------------------- */
    PairResult pr = EvaluatePairs();

    double pdr = g_expected ? double(g_pdrRx) / double(g_expected) : UNDEF;
    double meanLatency = g_latencyN ? (g_latencySum / g_latencyN) * 1000.0 : UNDEF;
    double perMsgUs = g_detectorCalls ? (g_detectorNanos / g_detectorCalls) / 1000.0 : 0.0;
    const double detectorThroughput =
        g_detectorNanos > 0.0
            ? static_cast<double>(g_detectorCalls) * 1.0e9 / g_detectorNanos
            : UNDEF;
    // Exact order statistics of the per-call cost. A mean cannot answer
    // whether a deadline is missed; the tail can.
    auto pct = [](std::vector<int64_t>& v, double q) -> double {
        if (v.empty())
        {
            return UNDEF;
        }
        size_t i = static_cast<size_t>(q * (v.size() - 1) + 0.5);
        return static_cast<double>(v[std::min(i, v.size() - 1)]) / 1000.0;
    };
    std::sort(g_detectorSamples.begin(), g_detectorSamples.end());
    const double detP50 = pct(g_detectorSamples, 0.50);
    const double detP95 = pct(g_detectorSamples, 0.95);
    const double detP99 = pct(g_detectorSamples, 0.99);
    const double detMax = pct(g_detectorSamples, 1.00);
    double cleanFpr = pr.cleanFp + pr.cleanTn
                          ? double(pr.cleanFp) / double(pr.cleanFp + pr.cleanTn)
                          : UNDEF;
    double streamAuc = PairAuc(false);
    double ownerAuc = PairAuc(true);
    double streamPrAuc = PairPrAuc(false);
    double ownerPrAuc = PairPrAuc(true);
    double maxClean = MaxCleanScore();
    double cleanMargin = std::isfinite(maxClean) ? (threshold - maxClean) : UNDEF;
    uint64_t maliciousZeroReceptionPairs = 0;
    for (const EvaluationPairKey& expectedPair : g_expectedMaliciousPairs)
    {
        if (g_observedMaliciousPairs.count(expectedPair) == 0)
        {
            ++maliciousZeroReceptionPairs;
        }
    }

    if (!pairOutput.empty())
    {
        std::ofstream pairs(pairOutput);
        if (!pairs)
        {
            std::cerr << "ERROR: cannot open pairOutput path: " << pairOutput << "\n";
            Simulator::Destroy();
            return 2;
        }
        pairs << PAIR_SCHEMA << '\n' << std::setprecision(17);
        for (const auto& p : g_pairs)
        {
            std::ostringstream sources;
            bool first = true;
            for (uint32_t source : p.sourceIds)
            {
                if (!first)
                {
                    sources << ';';
                }
                sources << source;
                first = false;
            }
            std::ostringstream sourceRoles;
            first = true;
            for (uint32_t role : p.sourceRoles)
            {
                if (!first)
                {
                    sourceRoles << ';';
                }
                sourceRoles << RoleName(static_cast<Role>(role));
                first = false;
            }
            std::ostringstream observableSources;
            first = true;
            for (uint32_t source : p.observableSourceIps)
            {
                if (!first)
                {
                    observableSources << ';';
                }
                observableSources << Ipv4Address(source);
                first = false;
            }
            std::ostringstream victims;
            first = true;
            for (uint32_t victim : p.victimIds)
            {
                if (!first)
                {
                    victims << ';';
                }
                victims << victim;
                first = false;
            }
            std::ostringstream crossingIntervals;
            crossingIntervals << std::setprecision(17);
            first = true;
            for (const auto& intervalBounds : p.postOnsetCrossingIntervals)
            {
                if (!first)
                {
                    crossingIntervals << '|';
                }
                crossingIntervals << intervalBounds.first << ':'
                                  << intervalBounds.second;
                first = false;
            }
            bool cleanPair = !p.ownerIsAttacker && !p.hostileUse;
            // Mutually exclusive stream labels used by every downstream tool:
            // clean_pair            = honest owner AND no malicious message;
            // victim_exposure_pair  = honest owner AND >=1 malicious message.
            // The latter is exposure under a victim's claimed identity, not a
            // claim that the victim's genuine messages were malicious.
            bool victimExposurePair = !p.ownerIsAttacker && p.hostileUse;
            double observedDuration =
                std::max(0.0, p.lastSeen - p.firstSeen);
            double censorTime =
                p.everAlert ? p.timeToDetect : observedDuration;
            // Survival must use the SAME origin and the SAME event
            // definition as the primary endpoint. Gating on the legacy
            // streamAlert (a v4 crossing) while timing from the v5 window
            // exceedance let the two disagree, producing a negative
            // follow-up time whenever a pair crossed under the old rule but
            // never exceeded inside the evaluation window.
            const double streamOnsetTime =
                p.hostileUse
                    ? std::max(g_evalStart, p.firstHostileSeen)
                    : -1.0;
            const bool streamEvent =
                p.hostileUse && p.streamTimeToDetect >= 0.0;
            double streamObservedDuration =
                p.hostileUse
                    ? std::max(0.0, p.lastSeen - streamOnsetTime)
                    : -1.0;
            double streamCensorTime =
                !p.hostileUse
                    ? -1.0
                    : (streamEvent ? p.streamTimeToDetect
                                   : streamObservedDuration);
            int streamCensored = p.hostileUse ? (streamEvent ? 0 : 1) : -1;
            pairs << "v6_pair," << nVehicles << ',' << attackerFraction << ','
                  << attack << ',' << runId << ',' << scoreModel << ','
                  << threshold << ',' << decayHalfLife << ',' << attackStart << ','
                  << p.receiverId << ',' << p.claimedId
                  << ',' << p.sourceIds.size() << ',' << sources.str() << ','
                  << sourceRoles.str() << ',' << p.observableSourceIps.size() << ','
                  << observableSources.str() << ','
                  << (p.everContested ? 1 : 0) << ','
                  << (p.contestedStreamAlert ? 1 : 0) << ','
                  << (p.preexistingContested ? 1 : 0) << ','
                  << p.firstContested << ',' << p.firstStreamContested << ','
                  << (p.ownerSeen ? 1 : 0) << ','
                  << (p.assignedAttackerUse ? 1 : 0) << ','
                  << (p.attackActiveUse ? 1 : 0) << ','
                  << (p.hostileUse ? 1 : 0) << ',' << p.maliciousMsgs << ','
                  << (p.ownerIsAttacker ? 1 : 0) << ','
                  << (cleanPair ? 1 : 0) << ','
                  << (victimExposurePair ? 1 : 0)
                  << ',' << victims.str() << ',' << p.peakScore << ','
                  << p.streamPeakScore << ','
                  << p.finalScore << ','
                  << (p.finalAlert ? 1 : 0) << ',' << (p.everAlert ? 1 : 0)
                  << ',' << (p.streamAlert ? 1 : 0) << ','
                  << (p.preexistingAlert ? 1 : 0) << ','
                  << crossingIntervals.str() << ',' << p.firstSeen << ','
                  << p.firstCross << ','
                  << p.timeToDetect << ',' << p.lastSeen << ','
                  << observedDuration << ',' << censorTime << ','
                  << (p.everAlert ? 0 : 1) << ',' << p.firstHostileSeen << ','
                  << p.firstStreamCross << ',' << p.streamTimeToDetect << ','
                  << streamObservedDuration << ',' << streamCensorTime << ','
                  << streamCensored << ',' << p.msgs << ','
                  << g_evalStart << ',' << (p.eligible ? 1 : 0) << ','
                  << p.windowMsgs << ',' << p.windowExposure << ','
                  << p.windowPeakScore << ',' << p.windowFirstExceed << ','
                  << (p.windowAlert ? 1 : 0) << ','
                  << p.trackCount << ',' << p.maxTrackPeak << ','
                  << p.honestTrackPeak << ',' << p.ownerTrackPeak << ','
                  << (p.trackAlert ? 1 : 0) << ','
                  << (p.honestTrackAlert ? 1 : 0) << ','
                  << (p.ownerTrackAlert ? 1 : 0) << ','
                  << p.trackCapacityDrops << ','
                  << p.trackPurity << ',' << p.trackMerges << ','
                  << p.trackFragments << ',' << p.trackIdSwitches << ','
                  << p.oracleTrackHonestPeak << ','
                  << (p.oracleTrackHonestAlert ? 1 : 0) << ','
                  << StrideName(p.strideClass) << ','
                  << (p.strideAmbiguous ? 1 : 0) << ',' << p.strideMargin
                  << ',' << p.strideImpact << ','
                  << p.peakPriority << ',' << PriorityBand(p.peakPriority)
                  << ','
                  << (p.trustCompromised ? "compromised" : "trusted") << '\n';
        }
    }

    std::cout << "\n===== V2V Sequential Plausibility Detection =====\n";
    std::cout << "vehicles=" << nVehicles
              << "  attackers=" << nAttackers
              << "  attack=" << attack
              << "  run=" << runId
              << "  detector=" << (detectorOn ? "on" : "off")
              << "  score_model=" << scoreModel
              << "  attack_start=" << attackStart << " s\n";
    std::cout << "BSMs sent            : " << g_sent << "\n";
    std::cout << "BSM receptions       : " << g_received << "\n";
    std::cout << "Mean app latency (ms): " << meanLatency << "  (expected honest "
              << "receiver deliveries, n=" << g_latencyN << ")\n";
    std::cout << "PDR @ " << commRange << " m      : " << pdr
              << "  (" << g_pdrRx << "/" << g_expected << ")\n";
    std::cout << "Detector cost (us/msg): " << perMsgUs << "\n";

    if (detectorOn)
    {
        std::cout << "-- stream attribution @ score threshold " << threshold
                  << " (primary: window_peak_score > threshold, applied "
                     "identically to both classes over W=["
                  << g_evalStart << ", " << simTime << "]) --\n";
        std::cout << "pairs=" << g_pairs.size()
                  << "  TP=" << pr.streamEver.tp << " FP=" << pr.streamEver.fp
                  << " TN=" << pr.streamEver.tn << " FN=" << pr.streamEver.fn
                  << "  TPR=" << pr.streamEver.Tpr()
                  << "  FPR=" << pr.streamEver.Fpr()
                  << "  F1=" << pr.streamEver.F1() << "\n";
        std::cout << "-- owner attribution (claimed owner is hostile) --\n";
        std::cout << "TPR=" << pr.ownerEver.Tpr()
                  << "  FPR=" << pr.ownerEver.Fpr()
                  << "  F1=" << pr.ownerEver.F1() << "\n";
        std::cout << "Clean-pair FPR=" << cleanFpr
                  << "  victim receiver/identity pairs=" << pr.victimPairs
                  << " (alerted " << pr.victimPairsAlerted << ")"
                  << "  unique victims=" << pr.victimIds
                  << " (alerted " << pr.victimIdsAlerted
                  << ", contested " << pr.victimIdsContested << ")\n";
        std::cout << "-- observable-source contested-ID mitigation --\n"
                  << "TP=" << pr.contested.tp << " FP=" << pr.contested.fp
                  << " TN=" << pr.contested.tn << " FN=" << pr.contested.fn
                  << "  TPR=" << pr.contested.Tpr()
                  << "  FPR=" << pr.contested.Fpr()
                  << "  F1=" << pr.contested.F1() << "\n";
        std::cout << "Median time-to-detect (s): " << pr.medianTtd
                  << "  (over the " << pr.ttdDetectedFrac
                  << " fraction with a new post-malicious crossing; time starts "
                     "at first malicious reception and non-detections are "
                     "right-censored)\n";
    }

    std::cout << std::setprecision(17);
    std::cout << "CSV,v6," << nVehicles << "," << attackerFraction << ","
              << nAttackers << "," << attack << "," << runId << "," << simTime
              << "," << interval << "," << (detectorOn ? 1 : 0) << ","
              << scoreModel << "," << mobilityModel << ","
              << (nullEvidence ? 1 : 0) << ","
              << (g_naiveThresh ? 1 : 0) << "," << prior << "," << threshold
              << "," << effectiveDecay << "," << decayHalfLife << "," << warmup
              << "," << attackStart << "," << commRange << ","
              << g_gpsSigma << "," << g_detectorGpsSigma << "," << g_spdSigma
              << "," << g_clockSigma << "," << g_bsmBytes << "," << g_sent
              << "," << g_received << "," << g_invalidBsm << ","
              << g_assignedAttackerRx << "," << g_attackActiveRx << ","
              << g_maliciousRx << "," << g_expectedMaliciousPairs.size() << ","
              << (g_expectedMaliciousPairs.size() -
                  maliciousZeroReceptionPairs) << ","
              << g_observedMaliciousPairs.size() << ","
              << maliciousZeroReceptionPairs << ","
              << g_pairs.size() << ","
              << pr.streamEver.tp << "," << pr.streamEver.fp << ","
              << pr.streamEver.tn << "," << pr.streamEver.fn << ","
              << pr.streamEver.Tpr() << "," << pr.streamEver.Fpr() << ","
              << pr.streamEver.Precision() << "," << pr.streamEver.F1() << ","
              << pr.ownerEver.tp << "," << pr.ownerEver.fp << ","
              << pr.ownerEver.tn << "," << pr.ownerEver.fn << ","
              << pr.ownerEver.Tpr() << "," << pr.ownerEver.Fpr() << ","
              << pr.ownerEver.Precision() << "," << pr.ownerEver.F1() << ","
              << pr.cleanFp << "," << pr.cleanTn << "," << cleanFpr << ","
              << pr.victimPairs << "," << pr.victimPairsAlerted << ","
              << pr.victimIds << "," << pr.victimIdsAlerted << ","
              << pr.contested.tp << "," << pr.contested.fp << ","
              << pr.contested.tn << "," << pr.contested.fn << ","
              << pr.contested.Tpr() << "," << pr.contested.Fpr() << ","
              << pr.contested.Precision() << "," << pr.contested.F1() << ","
              << pr.victimPairsContested << "," << pr.victimIdsContested << ","
              << pr.streamFinal.tp << "," << pr.streamFinal.fp << ","
              << pr.streamFinal.tn << "," << pr.streamFinal.fn << ","
              << pr.streamFinal.Tpr() << "," << pr.streamFinal.Fpr() << ","
              << pr.streamFinal.Precision() << "," << pr.streamFinal.F1() << ","
              << pr.ownerFinal.tp << "," << pr.ownerFinal.fp << ","
              << pr.ownerFinal.tn << "," << pr.ownerFinal.fn << ","
              << pr.ownerFinal.Tpr() << "," << pr.ownerFinal.Fpr() << ","
              << pr.ownerFinal.Precision() << "," << pr.ownerFinal.F1() << ","
              << pr.medianTtd << "," << pr.ttdDetectedFrac << ","
              << streamAuc << "," << ownerAuc << ","
              << streamPrAuc << "," << ownerPrAuc << ","
              << maxClean << "," << cleanMargin << ","
              << g_latencySum << ","
              << g_latencyN << "," << meanLatency << "," << g_pdrRx << ","
              << g_expected << "," << pdr << "," << g_detectorCalls << ","
              << g_detectorNanos << "," << perMsgUs << ","
              << detP50 << "," << detP95 << "," << detP99 << "," << detMax
              << "," << detectorThroughput << "," << g_peakKeys << ","
              << g_peakTracks << ","
              << g_peakStateBytes << ","
              << g_evalStart << "," << g_onsetBlank << ","
              << pr.eligiblePairs << "," << pr.ineligiblePairs << ","
              << pr.streamTrack.tp << "," << pr.streamTrack.fp << ","
              << pr.streamTrack.tn << "," << pr.streamTrack.fn << ","
              << pr.streamTrack.Tpr() << "," << pr.streamTrack.Fpr() << ","
              << pr.victimPairsTrackAlerted << ","
              << pr.victimIdsTrackAlerted << ","
              << pr.trackCapacityDrops << "\n";

    Simulator::Destroy();
    return 0;
}
