/* Assertions over detector/metric code extracted from the production source. */
#include <core.inc>

#include <cmath>
#include <cstdio>

static int failures = 0;

#define CHECK(condition, label)                                                \
    do                                                                         \
    {                                                                          \
        if (condition)                                                         \
        {                                                                      \
            std::printf("PASS  %s\n", label);                                  \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            std::fprintf(stderr, "FAIL  %s (line %d)\n", label, __LINE__);      \
            ++failures;                                                        \
        }                                                                      \
    } while (false)

static bool Near(double actual, double expected, double tolerance = 1e-12)
{
    return std::fabs(actual - expected) <= tolerance;
}

// windowAlert is the v5 PRIMARY decision and drives every confusion matrix.
// The legacy everAlert/streamAlert arguments are retained because the crossing
// telemetry they exercise is still emitted as a secondary diagnostic.
static PairRecord Pair(uint32_t claimedId,
                       bool hostileUse,
                       bool ownerIsAttacker,
                       bool everAlert,
                       bool streamAlert,
                       bool finalAlert,
                       double peakScore,
                       double streamPeakScore,
                       double streamTtd,
                       bool windowAlert,
                       bool eligible = true)
{
    PairRecord pair{};
    pair.receiverId = 1;
    pair.claimedId = claimedId;
    pair.sourceIds.insert(claimedId);
    pair.ownerSeen = true;
    pair.hostileUse = hostileUse;
    pair.ownerIsAttacker = ownerIsAttacker;
    pair.peakScore = peakScore;
    pair.streamPeakScore = streamPeakScore;
    pair.finalScore = finalAlert ? 0.9 : 0.1;
    pair.finalAlert = finalAlert;
    pair.everAlert = everAlert;
    pair.streamAlert = streamAlert;
    pair.preexistingAlert = everAlert && hostileUse && !streamAlert;
    pair.firstSeen = 5.0;
    pair.firstCross = everAlert ? 6.0 : -1.0;
    pair.firstHostileSeen = hostileUse ? 7.0 : -1.0;
    pair.firstStreamCross =
        streamAlert ? pair.firstHostileSeen + streamTtd : -1.0;
    pair.lastSeen = 20.0;
    pair.timeToDetect = everAlert ? 1.0 : -1.0;
    pair.streamTimeToDetect = streamAlert ? streamTtd : -1.0;
    pair.msgs = 100;
    // v5 primary endpoint. windowPeakScore mirrors peakScore so the AUC
    // fixtures stay readable; windowAlert is set explicitly so a test can
    // express a decision independently of the legacy crossing fields.
    pair.eligible = eligible;
    pair.windowMsgs = eligible ? 100 : 0;
    pair.windowExposure = eligible ? 15.0 : 0.0;
    pair.windowPeakScore = peakScore;
    pair.windowFirstExceed = windowAlert ? 8.0 : -1.0;
    pair.windowAlert = eligible && windowAlert;
    return pair;
}

static Bsm Message(uint32_t seq, double time, double x, double speed = 25.0)
{
    Bsm message{};
    message.claimedId = 7;
    message.seq = seq;
    message.txTime = time;
    message.x = x;
    message.y = 0.0;
    message.vx = speed;
    message.vy = 0.0;
    message.oracleId = 7;
    return message;
}

static void TestMetrics()
{
    Confusion f1;
    f1.tp = 3;
    f1.fp = 1;
    f1.tn = 7;
    f1.fn = 2;
    CHECK(Near(f1.F1(), 2.0 / 3.0),
          "F1 is 2TP/(2TP+FP+FN)");

    g_pairs.clear();
    g_pairs.push_back(Pair(10, true, false, true, true, false, 0.9, 0.9, 1.0, true));
    g_pairs.push_back(Pair(11, true, true, false, false, false, 0.1, 0.1, -1.0, false));
    g_pairs.push_back(Pair(12, false, false, true, false, true, 0.5, 0.5, -1.0, true));
    g_pairs.push_back(Pair(13, false, false, false, false, false, 0.1, 0.1, -1.0, false));
    // No exposure inside the evaluation window: must appear in no cell.
    g_pairs.push_back(
        Pair(14, true, true, true, true, true, 0.99, 0.99, 0.5, true, false));
    g_pairs[0].everContested = true;
    g_pairs[0].contestedStreamAlert = true;
    g_pairs[1].everContested = true;
    g_pairs[1].preexistingContested = true;
    g_pairs[2].everContested = true;

    PairResult result = EvaluatePairs();
    CHECK(result.streamEver.tp == 1 && result.streamEver.fp == 1 &&
              result.streamEver.tn == 1 && result.streamEver.fn == 1,
          "stream confusion applies one rule to both classes");
    CHECK(result.ownerEver.tp == 0 && result.ownerEver.fp == 2 &&
              result.ownerEver.tn == 1 && result.ownerEver.fn == 1,
          "owner attribution counts impersonated victims as negatives");
    CHECK(result.cleanFp == 1 && result.cleanTn == 1,
          "clean-pair false alarms have an explicit denominator");
    CHECK(result.victimPairs == 1 && result.victimPairsAlerted == 1 &&
              result.victimIds == 1 && result.victimIdsAlerted == 1,
          "victim pair and unique-identity counts remain separate");
    CHECK(result.contested.tp == 2 && result.contested.fp == 1 &&
              result.contested.tn == 1 && result.contested.fn == 0,
          "contesting uses one label-independent rule; contestation cannot "
          "precede onset so no asymmetry is needed");
    CHECK(result.eligiblePairs == 4 && result.ineligiblePairs == 1,
          "pairs with no exposure inside the window are excluded, not counted "
          "as free true negatives");
    CHECK(Near(result.ttdDetectedFrac, 0.5) && Near(result.medianTtd, 1.0),
          "TTD uses hostile-onset detections and exposes censoring fraction");
    CHECK(Near(PairAuc(false), 0.625),
          "stream AUC ranks the statistic the operating point thresholds");
    CHECK(Near(PairAuc(true), 1.0 / 6.0),
          "owner AUC ranks the same statistic, differing only in the label");
}

static void TestCrossingTelemetry()
{
    std::pair<double, double> interval;
    CHECK(CrossingInterval(false, 0.9, 0.4, interval) &&
              Near(interval.first, 0.0) && Near(interval.second, 0.4),
          "first measured score crosses exactly [0,score)");
    CHECK(CrossingInterval(true, 0.2, 0.7, interval) &&
              Near(interval.first, 0.2) && Near(interval.second, 0.7),
          "rising transition crosses [previous,current)");
    CHECK(!CrossingInterval(true, 0.7, 0.7, interval) &&
              !CrossingInterval(true, 0.8, 0.3, interval),
          "flat and falling scores create no upward-crossing interval");

    auto merged = MergeCrossingIntervals(
        {{0.7, 0.9}, {0.2, 0.4}, {0.35, 0.5}, {0.5, 0.7}});
    CHECK(merged.size() == 1 && Near(merged[0].first, 0.2) &&
              Near(merged[0].second, 0.9),
          "overlapping and adjacent threshold intervals are merged");
    CHECK(merged[0].first <= 0.2 && 0.2 < merged[0].second &&
              !(merged[0].first <= 0.9 && 0.9 < merged[0].second),
          "crossing interval endpoints implement low<=T<high");
}

static void TestPrimaryStreamDelay()
{
    NeighborState state;
    g_evalStart = 5.0;

    NeighborState truth;
    CHECK(!ObserveWindowTruth(truth, 4.0, 8, 1, 123, 7, 7,
                              true, true, true) &&
              truth.msgs == 0 && !truth.sawHostileUse &&
              truth.sourceIds.empty() && truth.victimIds.empty(),
          "pre-W hostile reception remains history, not exported truth");
    CHECK(ObserveWindowTruth(truth, 5.0, 7, 0, 124,
                             std::numeric_limits<uint32_t>::max(), 7,
                             false, false, false) &&
              truth.msgs == 1 && !truth.sawHostileUse && truth.sawOwner &&
              truth.sourceIds.size() == 1 && truth.sourceIds.count(7) == 1,
          "first W reception defines truth without leaking pre-W attacker labels");

    // A high score before hostile use belongs to the pair-wide diagnostic,
    // not to the hostile-stream survival clock.
    state.windowFirstExceed = 5.5;
    ObserveStreamWindowExceed(state, 5.5, 0.9, 0.5);
    CHECK(state.streamWindowFirstExceed < 0.0,
          "pre-hostile exceedance cannot create a stream event");

    // If the score is already high when the first hostile message arrives,
    // the primary peak rule has detected that message with zero delay; it
    // must not wait for a new upward crossing.
    state.firstHostileSeen = 7.0;
    ObserveStreamWindowExceed(state, 7.0, 0.9, 0.5);
    CHECK(Near(state.streamWindowFirstExceed, 7.0),
          "already-high first hostile observation is a zero-delay event");
    ObserveStreamWindowExceed(state, 8.0, 0.95, 0.5);
    CHECK(Near(state.streamWindowFirstExceed, 7.0),
          "stream delay retains the first above-threshold observation");

    NeighborState later;
    later.firstHostileSeen = 7.0;
    ObserveStreamWindowExceed(later, 7.0, 0.4, 0.5);
    ObserveStreamWindowExceed(later, 8.25, 0.6, 0.5);
    CHECK(Near(later.streamWindowFirstExceed - later.firstHostileSeen, 1.25),
          "later above-threshold observation gives positive stream delay");

    NeighborState beforeWindow;
    beforeWindow.firstHostileSeen = 3.0;
    ObserveStreamWindowExceed(beforeWindow, 4.0, 0.9, 0.5);
    ObserveStreamWindowExceed(beforeWindow, 5.0, 0.9, 0.5);
    CHECK(beforeWindow.streamWindowFirstExceed < 0.0,
          "malicious use only before W cannot create a W-positive event");
}

static void TestVictimTemporalAttribution()
{
    g_pairs.clear();
    // Both honest identities are later used maliciously. The first peaked
    // before the evaluation window opened and never exceeds inside it; the
    // second does. Under v5 the exclusion is done by the WINDOW, not by a
    // label-dependent rule, so the same decision applies to every class.
    g_pairs.push_back(
        Pair(20, true, false, true, false, false, 0.9, 0.8, -1.0, false));
    g_pairs.back().preexistingAlert = true;
    g_pairs.push_back(
        Pair(21, true, false, true, true, false, 0.9, 0.9, 1.0, true));
    // The owner's messages and hostile forgeries may be wrongly merged into
    // one associated track.  That mixed track is not pure-honest, but it
    // still convicts the victim trajectory and must count in victim harm.
    g_pairs[0].honestTrackAlert = false;
    g_pairs[0].ownerTrackAlert = true;
    PairResult result = EvaluatePairs();
    CHECK(result.victimPairs == 2 && result.victimPairsAlerted == 1 &&
              result.victimIds == 2 && result.victimIdsAlerted == 1,
          "pre-window excursions are not credited as victim framing");
    CHECK(result.victimPairsTrackAlerted == 1 &&
              result.victimIdsTrackAlerted == 1,
          "mixed owner/hostile track remains visible in victim-track harm");
}

static void TestTimeDecay()
{
    CHECK(Near(TimeDecayFactor(2.0, 2.0), 0.5),
          "one elapsed half-life retains half the excess evidence");
    CHECK(Near(TimeDecayFactor(10.0, -1.0), 1.0) &&
              Near(TimeDecayFactor(0.0, 2.0), 1.0),
          "negative half-life disables forgetting and zero time does not decay");
    CHECK(Near(TimeDecayFactor(0.5, 2.0) * TimeDecayFactor(1.5, 2.0),
               TimeDecayFactor(2.0, 2.0)),
          "time decay composes by elapsed time, not update count");

    g_check = g_checkReference;
    g_warmup = 0.0;
    g_detectorGpsSigma = 2.0;
    g_spdSigma = 0.5;
    g_naiveThresh = false;
    Receiver frequent(0.05, 2.0, false);
    Receiver sparse(0.05, 2.0, false);
    for (Receiver* receiver : {&frequent, &sparse})
    {
        NeighborState& state = receiver->m_neighbors[7];
        state.have = true;
        state.warmReset = true;
        state.logEvidence = 4.0;
        state.haveEvidenceUpdate = true;
        state.lastEvidenceUpdate = 0.0;
    }
    double frequentScore = 0.0;
    for (uint32_t step = 1; step <= 10; ++step)
    {
        const double time = 0.1 * step;
        frequentScore = frequent.Assess(Message(step, time, 25.0 * time), time);
    }
    double sparseScore = 0.0;
    for (uint32_t step = 1; step <= 5; ++step)
    {
        const double time = 0.2 * step;
        sparseScore = sparse.Assess(Message(step, time, 25.0 * time), time);
    }
    CHECK(Near(frequentScore, sparseScore, 1e-10),
          "equivalent elapsed time gives the same forgetting at different rates");
}

static void TestTrackHistoryIsolation()
{
    g_check = g_checkReference;
    g_warmup = 0.0;
    g_evalStart = 0.0;
    g_detectorGpsSigma = 2.0;
    g_spdSigma = 0.5;
    g_naiveThresh = false;

    Receiver collision(0.05, -1.0, false);
    double identityScore = 0.0;
    for (uint32_t sequence = 1; sequence <= 8; ++sequence)
    {
        const double firstTime = 0.2 * (sequence - 1);
        Bsm first = Message(sequence, firstTime, 25.0 * firstTime);
        first.oracleId = 70;
        identityScore = collision.Assess(first, firstTime);

        const double secondTime = firstTime + 0.1;
        Bsm second = Message(
            sequence, secondTime, 1000.0 + 25.0 * secondTime);
        second.oracleId = 71;
        identityScore = collision.Assess(second, secondTime);
    }
    const NeighborState& collisionState = collision.m_neighbors.at(7);
    bool cleanTracks = collisionState.tracks.size() == 2;
    for (const Track& track : collisionState.tracks)
    {
        cleanTracks &= track.valid && track.windowPeakScore < 0.06;
    }
    CHECK(identityScore > 0.5 && cleanTracks,
          "colliding identity history alerts while two consistent track histories stay clean");
    CHECK(collisionState.oracleTracks.size() == 2 &&
              collisionState.oracleTracks.at(70).windowPeakScore < 0.06 &&
              collisionState.oracleTracks.at(71).windowPeakScore < 0.06,
          "oracle-source tracks also isolate replay, rate and kinematic history");

    Receiver attacked(0.05, -1.0, false);
    Bsm normal = Message(1, 0.0, 0.0);
    normal.oracleId = 80;
    attacked.Assess(normal, 0.0);
    Bsm replay = Message(1, 0.1, 2.5);
    replay.oracleId = 80;
    const double attackedIdentityScore = attacked.Assess(replay, 0.1);
    const Track& attackedTrack = attacked.m_neighbors.at(7).tracks.front();
    CHECK(attackedTrack.windowPeakScore > 0.5 &&
              Near(attackedTrack.windowPeakScore, attackedIdentityScore),
          "an uncontested replay raises identical identity and track-local evidence");

    Track warmed;
    warmed.valid = true;
    bool warmFired[CHK_COUNT] = {};
    EvaluateTrackChecks(warmed, normal, 0.0, warmFired);
    warmed.logEvidence = 3.0;
    warmed.haveEvidenceUpdate = true;
    warmed.carriedOwner = true;
    ResetTrackMeasurement(warmed, -2.0);
    CHECK(warmed.haveCheckHistory && warmed.seenSeq.count(1) == 1 &&
              warmed.rxTimes.size() == 1 && warmed.checkRefValid &&
              Near(warmed.logEvidence, -2.0) && !warmed.haveEvidenceUpdate &&
              !warmed.carriedOwner,
          "warm-up reset clears measured evidence but preserves track check history");

    Bsm outOfOrder = Message(2, -0.1, -2.5);
    bool staleFired[CHK_COUNT] = {};
    EvaluateTrackChecks(warmed, outOfOrder, 0.1, staleFired);
    CHECK(staleFired[CHK_REPLAY] && Near(warmed.lastCheckTxTime, 0.0),
          "out-of-order track reception fires replay without rolling history backward");
}

static void TestStrideDreadAndPriority()
{
    g_check = g_checkReference;
    bool fired[CHK_COUNT] = {};
    fired[CHK_RATE] = true;
    StrideAttribution attribution = AttributeStrideFrame(fired);
    CHECK(attribution.category == S_DOS && !attribution.ambiguous,
          "rate evidence maps to denial of service without ambiguity");

    fired[CHK_REPLAY] = true;
    attribution = AttributeStrideFrame(fired);
    CHECK(attribution.category == S_DOS && attribution.ambiguous &&
              attribution.runnerUpEvidence > 0.0,
          "near-tied evidence from different STRIDE classes is ambiguous");

    for (bool& value : fired)
    {
        value = false;
    }
    fired[CHK_POSITION_JUMP] = true;
    attribution = AttributeStrideFrame(fired);
    CHECK(attribution.category == S_SPOOFING && !attribution.ambiguous &&
              Near(attribution.runnerUpEvidence, 0.0),
          "position-jump evidence maps to spoofing provenance");

    fired[CHK_POSITION_JUMP] = false;
    fired[CHK_SPEED_MISMATCH] = true;
    fired[CHK_HEADING] = true;
    attribution = AttributeStrideFrame(fired);
    CHECK(attribution.category == S_TAMPERING && !attribution.ambiguous &&
              Near(attribution.runnerUpEvidence, 0.0),
          "multiple tampering checks do not create false ambiguity");

    for (int category = 0; category < S_COUNT; ++category)
    {
        const DreadComponents& dread = g_dread[category];
        const double expected =
            (dread.damage + dread.reproducibility + dread.exploitability +
             dread.affected + dread.discoverability) /
            50.0;
        CHECK(Near(dread.normalised, expected),
              "DREAD normalisation equals the published five-component sum");
    }
    CHECK(Near(PriorityIndex(0.8, S_DOS), 0.8 * g_strideImpact[S_DOS]) &&
              Near(PriorityIndex(0.8, S_NONE), 0.0),
          "priority is S_peak times impact of the class at S_peak");

    // A pre-warm-up map violation must not leak into the attribution attached
    // to a clean measurement-window observation.
    g_warmup = 1.0;
    g_evalStart = 1.0;
    g_detectorGpsSigma = 2.0;
    g_spdSigma = 0.5;
    g_naiveThresh = false;
    Receiver receiver(0.05, 3.430961849152064, false);
    receiver.Assess(Message(1, 0.9, -100.0), 0.9);
    CHECK(receiver.m_neighbors.at(7).currentStride.category == S_SPOOFING,
          "pre-warm-up violation is observed for detector history");
    receiver.Assess(Message(2, 1.0, 0.0), 1.0);
    const NeighborState& state = receiver.m_neighbors.at(7);
    CHECK(state.warmReset && state.currentStride.category == S_NONE &&
              state.peakStride.category == S_NONE,
          "warm-up reset clears STRIDE state before the first measured frame");
}

static void TestTrackLifecycleBound()
{
    NeighborState state;
    for (uint32_t index = 0; index < TRACK_MAX; ++index)
    {
        const int slot = AllocateTrackSlot(state, -2.0);
        CHECK(slot >= 0, "track allocator fills each bounded active slot");
        Track& track = state.tracks[slot];
        track.lastTime = 0.0;
        track.msgs = 2;
        track.windowMsgs = 2;
        track.windowPeakScore = 0.7 + 0.01 * index;
        track.srcCounts[index] = 2;
        track.carriedOwner = index == 0;
        track.carriedMalicious = index == 0;
        track.haveCheckHistory = true;
        track.seenSeq.insert(index);
        track.seqFifo.push_back(index);
        track.rxTimes.push_back(0.0);
    }
    CHECK(state.tracks.size() == TRACK_MAX &&
              AllocateTrackSlot(state, -2.0) < 0,
          "track allocator refuses capacity beyond TRACK_MAX");

    ExpireTracks(state, TRACK_EXPIRY + 1.0);
    CHECK(state.tracks.size() == TRACK_MAX &&
              state.retiredWindowTracks == TRACK_MAX &&
              Near(state.retiredMaxTrackPeak, 0.73) &&
              Near(state.retiredOwnerTrackPeak, 0.70) &&
              Near(state.retiredHonestTrackPeak, 0.73),
          "expiry archives decision statistics without growing storage");
    CHECK(std::all_of(state.tracks.begin(), state.tracks.end(),
                      [](const Track& track) {
                          return !track.valid && !track.haveCheckHistory &&
                                 track.seenSeq.empty() && track.seqFifo.empty() &&
                                 track.rxTimes.empty();
                      }),
          "expiry clears retired track-local detector histories before slot reuse");

    bool allReused = true;
    for (uint32_t cycle = 0; cycle < 100; ++cycle)
    {
        const int slot = AllocateTrackSlot(state, -2.0);
        allReused &= slot >= 0;
        if (slot < 0)
        {
            break;
        }
        state.tracks[slot].lastTime = cycle * (TRACK_EXPIRY + 1.0);
        state.tracks[slot].msgs = 1;
        state.tracks[slot].srcCounts[cycle] = 1;
        ExpireTracks(state, (cycle + 1) * (TRACK_EXPIRY + 1.0));
    }
    CHECK(allReused && state.tracks.size() == TRACK_MAX,
          "repeated expiry/recreation keeps retained track storage bounded");

    g_check = g_checkReference;
    g_warmup = 0.0;
    g_evalStart = 0.0;
    g_detectorGpsSigma = 2.0;
    g_spdSigma = 0.5;
    g_naiveThresh = false;
    Receiver saturated(0.05, -1.0, false);
    for (uint32_t index = 0; index <= TRACK_MAX; ++index)
    {
        Bsm message = Message(index + 1, 0.01 * index, 1000.0 * index);
        saturated.Assess(message, 0.01 * index);
    }
    CHECK(saturated.m_neighbors.at(7).trackCapacityDrops == 1,
          "fifth incompatible W trajectory is counted as a capacity drop");
}

static void TestDetectorState()
{
    g_check = g_checkReference;
    g_warmup = 0.0;
    g_detectorGpsSigma = 2.0;
    g_spdSigma = 0.5;
    g_naiveThresh = false;

    Receiver clean(0.05, 3.430961849152064, false);
    double score = 0.0;
    for (uint32_t seq = 0; seq < 300; ++seq)
    {
        const double time = 0.1 * seq;
        score = clean.Assess(Message(seq, time, 25.0 * time), time);
    }
    CHECK(score < 0.10, "clean internally consistent stream stays near initial score");

    Receiver fifo(0.05, -1.0, false);
    for (uint32_t seq = 1000; seq < 1600; ++seq)
    {
        const double time = 0.1 * (seq - 1000);
        fifo.Assess(Message(seq, time, 25.0 * time), time);
    }
    for (uint32_t seq = 0; seq < 50; ++seq)
    {
        const double time = 60.0 + 0.1 * seq;
        fifo.Assess(Message(seq, time, 25.0 * time), time);
    }
    const NeighborState& fifoState = fifo.m_neighbors.at(7);
    CHECK(fifoState.seenSeq.size() == fifoState.seqFifo.size() &&
              fifoState.seenSeq.size() == 500,
          "replay set and FIFO remain bounded and synchronized");
    CHECK(fifoState.seenSeq.count(1599) == 1,
          "low injected sequence numbers cannot evict recent history");
    CHECK(fifoState.seenSeq.count(1000) == 0,
          "FIFO evicts oldest insertion, not lowest sequence value");

    Receiver transient(0.05, 0.5, false);
    for (uint32_t seq = 0; seq <= 5; ++seq)
    {
        const double time = 0.1 * seq;
        transient.Assess(Message(seq, time, 25.0 * time), time);
    }
    double spike = transient.Assess(Message(6, 1.0, 1000.0), 1.0);
    score = spike;
    for (uint32_t seq = 7; seq < 500; ++seq)
    {
        const double time = 1.0 + 0.1 * (seq - 6);
        const double x = 1000.0 + 25.0 * (time - 1.0);
        score = transient.Assess(Message(seq, time, x), time);
    }
    CHECK(spike > 0.5, "one impossible displacement raises an alert");
    CHECK(score < 0.5, "decay lets a later coherent stream fall below threshold");

    Receiver strictNoise(0.05, 3.430961849152064, false);
    g_detectorGpsSigma = 0.0;
    strictNoise.Assess(Message(0, 0.0, 0.0, 70.0), 0.0);
    double strictScore =
        strictNoise.Assess(Message(1, 0.5, 35.0, 70.0), 0.5);

    Receiver tolerantNoise(0.05, 3.430961849152064, false);
    g_detectorGpsSigma = 10.0;
    tolerantNoise.Assess(Message(0, 0.0, 0.0, 70.0), 0.0);
    double tolerantScore =
        tolerantNoise.Assess(Message(1, 0.5, 35.0, 70.0), 0.5);
    CHECK(strictScore > 0.5 && tolerantScore < 0.10,
          "detectorGpsSigma changes assumed tolerance, not generated data");
}

int main()
{
    TestMetrics();
    TestCrossingTelemetry();
    TestPrimaryStreamDelay();
    TestVictimTemporalAttribution();
    TestTimeDecay();
    TestTrackHistoryIsolation();
    TestStrideDreadAndPriority();
    TestTrackLifecycleBound();
    TestDetectorState();
    if (failures != 0)
    {
        std::fprintf(stderr, "%d detector assertion(s) failed\n", failures);
        return 1;
    }
    std::printf("All detector assertions passed.\n");
    return 0;
}
