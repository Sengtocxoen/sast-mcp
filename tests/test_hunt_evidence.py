"""
Evidence tests: a clean result has to be proven, not assumed.

Section 4 of docs/hunt-pipeline/ARCHITECTURE.md records six "0 crashes" verdicts
that were never tests at all - `nohup cmd &` died when the tool call returned -
and two of those targets were sitting on real bugs. Section 3 records a harness
running at 0 exec/s and a build whose target objects carried no coverage
counters. In all three cases the fuzzer reported success.

So these tests encode the campaign's measured numbers as the bar a clean claim
must clear:

    vgmstream    exec/s: 0,  14,309 execs / 40min  -> throughput collapse, not clean
    vgmstream*   3,934 exec/s after the memory fix -> admissible
    fluidsynth   cov: 20 from 30 counters          -> harness-only instrumentation
    fluidsynth*  cov: 1480 from 12,990 counters    -> admissible
    nohup &      no INITED line at all             -> never ran
    paldither    PoC built at -O1                  -> dead-store elimination
    OpenFBX      assert(false) with a return below -> not reportable
    dmc_unrar    assert with no fallback           -> reportable
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

from hunt import evidence  # noqa: E402

# A healthy libFuzzer run.
GOOD_LIBFUZZER = """INFO: Running with entropic power schedule (0xFF, 100).
INFO: seed corpus: files: 112 min: 1b max: 65536b
#2	INITED cov: 4087 ft: 8123 corp: 112/41Kb exec/s: 0 rss: 48Mb
#4096	NEW    cov: 4101 ft: 8200 corp: 118/44Kb lim: 4096 exec/s: 3934 rss: 61Mb
#198260	DONE   cov: 4101 ft: 8200 corp: 118/44Kb exec/s: 3934 rss: 61Mb
Done 198260 runs in 50 second(s)
"""

# The vgmstream harness before the memory-STREAMFILE rewrite: it ran, but at
# effectively zero throughput because every execution wrote a temp file.
FILESYSTEM_BOUND = """#2	INITED cov: 3689 ft: 7001 corp: 455/120Kb exec/s: 0 rss: 70Mb
#14309	DONE   cov: 3689 ft: 7001 corp: 455/120Kb exec/s: 0 rss: 71Mb
Done 14309 runs in 2400 second(s)
"""

# fluidsynth with the target object uninstrumented: the counters are the
# harness alone.
BLIND_BUILD = """#2	INITED cov: 20 ft: 24 corp: 1/1b exec/s: 0 rss: 29Mb
#524288	DONE   cov: 20 ft: 24 corp: 1/1b exec/s: 12000 rss: 30Mb
Done 524288 runs in 44 second(s)
"""

# What a dead `nohup cmd &` leaves behind.
NEVER_RAN = """nohup: ignoring input and appending output to 'nohup.out'
"""

GO_FUZZ_OK = """fuzz: elapsed: 0s, gathering baseline coverage: 0/112 completed
fuzz: elapsed: 3s, execs: 48512 (16170/sec), new interesting: 4 (total: 116)
PASS
ok  	example.com/pkg	3.142s
"""

GO_FUZZ_BUILD_FAIL = """# example.com/pkg [example.com/pkg.test]
./fuzz_test.go:12:2: undefined: ParseThing
FAIL	example.com/pkg [build failed]
"""


# -- libFuzzer / Go log validation ----------------------------------------

def test_healthy_libfuzzer_run_is_admissible():
    r = evidence.validate_fuzz_log(GOOD_LIBFUZZER)
    assert r["engine"] == "libfuzzer"
    assert r["ran"] is True
    assert r["execs"] == 198260
    assert r["coverage"] == 4101
    assert r["exec_per_sec"] == 3934
    assert r["clean_claim_admissible"] is True


def test_missing_inited_line_means_it_never_ran():
    """Six campaign verdicts died exactly here. No INITED, no test."""
    r = evidence.validate_fuzz_log(NEVER_RAN)
    assert r["ran"] is False
    assert r["clean_claim_admissible"] is False
    assert "never_started" in r["flags"]


def test_empty_log_is_not_a_clean_result():
    r = evidence.validate_fuzz_log("")
    assert r["clean_claim_admissible"] is False
    assert r["ran"] is False


def test_zero_exec_rate_is_flagged_as_throughput_collapse():
    """vgmstream: 14,309 execs across 455 parsers in 40 minutes."""
    r = evidence.validate_fuzz_log(FILESYSTEM_BOUND)
    assert r["ran"] is True
    assert "throughput_collapse" in r["flags"]
    assert r["clean_claim_admissible"] is False
    hint = " ".join(r["hints"]).lower()
    assert "streamfile" in hint or "filesystem" in hint


def test_post_fix_throughput_is_accepted():
    r = evidence.validate_fuzz_log(GOOD_LIBFUZZER)
    assert "throughput_collapse" not in r["flags"]


def test_low_coverage_counter_is_flagged_as_blind_build():
    """fluidsynth reported cov: 20 - that was the harness, not the parser."""
    r = evidence.validate_fuzz_log(BLIND_BUILD)
    assert "coverage_suspiciously_low" in r["flags"]
    assert r["clean_claim_admissible"] is False
    assert "instrument" in " ".join(r["hints"]).lower()


def test_go_fuzz_log_with_execs_is_admissible():
    r = evidence.validate_fuzz_log(GO_FUZZ_OK)
    assert r["engine"] == "go"
    assert r["ran"] is True
    assert r["execs"] == 48512
    assert r["exec_per_sec"] == 16170
    assert r["clean_claim_admissible"] is True


def test_go_build_failure_is_not_a_clean_result():
    r = evidence.validate_fuzz_log(GO_FUZZ_BUILD_FAIL)
    assert r["ran"] is False
    assert r["clean_claim_admissible"] is False
    assert "build_failed" in r["flags"]


def test_crash_in_log_is_reported_and_short_circuits_cleanliness():
    log = GOOD_LIBFUZZER + "==1234==ERROR: AddressSanitizer: heap-buffer-overflow\n"
    r = evidence.validate_fuzz_log(log)
    assert r["crash_detected"] is True
    assert r["sanitizer"] == "AddressSanitizer"
    # A crash is a finding; "clean" is simply not the question any more.
    assert r["clean_claim_admissible"] is False


# -- instrumentation counters ---------------------------------------------

def test_uninstrumented_object_is_caught():
    """fluid_sffile.c.o had zero sanitizer_cov symbols; CMake dropped the flags."""
    def runner(argv):
        if any("fluid_sffile" in a for a in argv):
            return 0, "0000000000000000 T fluid_sffile_parse\n", ""
        return 0, "\n".join(f"0000 b __sanitizer_cov_counter{i}" for i in range(500)), ""

    r = evidence.check_instrumentation(["build/fluid_sffile.c.o", "build/harness.o"],
                                       runner=runner)
    assert r["blind"] is True
    assert "build/fluid_sffile.c.o" in r["uninstrumented"]
    assert r["clean_claim_admissible"] is False


def test_instrumented_objects_pass():
    def runner(cmd):
        return 0, "\n".join(f"0000 b __sanitizer_cov_counter{i}" for i in range(12990)), ""

    r = evidence.check_instrumentation(["build/fluid_sffile.c.o"], runner=runner)
    assert r["blind"] is False
    assert r["clean_claim_admissible"] is True


def test_missing_nm_is_an_error_not_a_pass():
    def runner(argv):
        return 127, "", "nm: command not found"

    r = evidence.check_instrumentation(["x.o"], runner=runner)
    assert r["clean_claim_admissible"] is False
    assert r["errors"]


# -- harness filesystem IO ------------------------------------------------

def test_harness_doing_file_io_is_flagged_with_the_right_seam():
    src = """
    int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
        FILE *f = fopen("/tmp/in.bin", "wb");
        fwrite(d, 1, n, f);
        fclose(f);
        STREAMFILE *sf = open_stdio_streamfile("/tmp/in.bin");
        return 0;
    }
    """
    r = evidence.check_harness_filesystem_io(src)
    assert r["filesystem_io"] is True
    assert any("fopen" in h["call"] for h in r["hits"])
    assert "STREAMFILE" in " ".join(r["seams"])


def test_memory_only_harness_is_clean():
    src = """
    int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
        return parse_from_memory(d, n);
    }
    """
    r = evidence.check_harness_filesystem_io(src)
    assert r["filesystem_io"] is False
    assert r["hits"] == []


# -- assert triage --------------------------------------------------------

def test_assert_with_a_return_below_is_not_reportable():
    """OpenFBX: 6 crashes, all one assert(false), all clean under -DNDEBUG."""
    src = """
    Element* parse(Cursor* c) {
        assert(false);
        return Error("unknown element");
    }
    """
    r = evidence.classify_assert_crash(src, line=3)
    assert r["verdict"] == "not_reportable"
    assert "ndebug" in r["detail"].lower()


def test_assert_with_no_fallback_is_reportable():
    """dmc_unrar: identical symptom, no fallback, SEGV under NDEBUG."""
    src = """
    void read_block(reader* r) {
        assert(r->size > 0);
        memcpy(r->buf, r->src, r->size);
    }
    """
    r = evidence.classify_assert_crash(src, line=3)
    assert r["verdict"] == "reportable"


def test_assert_triage_needs_a_real_line():
    r = evidence.classify_assert_crash("int main(){}", line=999)
    assert r["verdict"] == "unknown"


# -- the remaining section 4 gates ---------------------------------------

def test_parallel_timeouts_must_be_rerun_single_threaded():
    """5 fluidsynth 'timeouts' completed in 97-235ms alone - CPU contention."""
    log = "ERROR: libFuzzer: timeout after 25 seconds\nRunning 8 workers\n"
    r = evidence.needs_single_threaded_rerun(log, jobs=8)
    assert r["rerun_required"] is True
    assert "single" in r["command_hint"].lower() or "-jobs=1" in r["command_hint"]


def test_timeout_without_parallelism_is_believed():
    log = "ERROR: libFuzzer: timeout after 25 seconds\n"
    r = evidence.needs_single_threaded_rerun(log, jobs=1)
    assert r["rerun_required"] is False


def test_store_signal_poc_must_be_built_at_O0():
    """At -O1, dead-store elimination deleted paldither's overflowing memcpy."""
    r = evidence.check_poc_build_flags("clang -O1 -g poc.c -o poc")
    assert r["valid"] is False
    assert "-O0" in r["detail"]


def test_poc_at_O0_is_accepted():
    r = evidence.check_poc_build_flags("clang -O0 -g -fsanitize=address poc.c -o poc")
    assert r["valid"] is True


def test_asan_poc_at_O1_is_still_accepted():
    """ASan reports the access itself, so optimisation does not hide it."""
    r = evidence.check_poc_build_flags("clang -O1 -fsanitize=address poc.c", signal="asan")
    assert r["valid"] is True


# -- aggregate ------------------------------------------------------------

def test_assess_refuses_to_bless_an_unproven_clean_run():
    r = evidence.assess(log=NEVER_RAN, claimed_crashes=0)
    assert r["verdict"] == "unproven"
    assert r["clean_claim_admissible"] is False
    assert r["blocking_flags"]


def test_assess_blesses_a_proven_clean_run():
    r = evidence.assess(log=GOOD_LIBFUZZER, claimed_crashes=0)
    assert r["verdict"] == "proven_clean"
    assert r["clean_claim_admissible"] is True


def test_assess_reports_a_crash_as_a_finding():
    log = GOOD_LIBFUZZER + "==1==ERROR: AddressSanitizer: SEGV on unknown address\n"
    r = evidence.assess(log=log, claimed_crashes=1)
    assert r["verdict"] == "crash"
