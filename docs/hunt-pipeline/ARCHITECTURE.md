# Static-analysis architecture for the OSS memory-safety hunt

Status as of 2026-10-04. Covers the static/triage side of the pipeline built during
`OSS-Hunt-2026-09-30`: **13 Critical, 16 High, 3 Medium — 32 reports, 30 verified patches.**

---

## 0. The headline, because it inverts the obvious design

The pipeline has two static stages. **They did not perform remotely alike, and the useful one is not the one
you would expect.**

| stage | what it does | hits | real findings | precision |
|---|---|---|---|---|
| **Target gating** | picks *which library* to attack | 297 → 62 → **2** survivors | **2 of 2** | **~100%** |
| **Shape scanning** | picks *which line* to attack | 60 hits across two scanners | **1** (already known) | **<2%** |

**Conclusion: spend the static-analysis budget on target selection, not on site detection.** Pattern-matching
C for "the shape of a bug" produced almost nothing usable — every `scan3` hit I inspected was a false positive.
Pattern-matching *projects* for "the shape of an unmined target" was close to perfectly predictive.

This is the opposite of how SAST is normally sold, and it is the single most reusable thing in this document.

---

## 1. Stage A — target gating (the part that works)

```
nothings/single_file_libs README  (canonical catalog, ~400 entries)
        │
        ├─ parse markdown table rows  →  297 unique GitHub repos      [catalog_all_297.tsv]
        │
        ├─ keep format-parser tags only
        │     image · audio · 3d · mesh · pack · parse · file · serial · video
        │                                              →  62 repos    [catalog_parsers_62.tsv]
        │
        └─ gate each repo on FOUR independent signals ────────────────┐
                                                                      │
   G1  maintained    git log -1 (NEVER pushed_at — it lies)   ≤ ~1yr  │
   G2  not saturated raw.githubusercontent OSS-Fuzz project.yaml ⇒404 │
   G3  no in-repo harness   find -iname '*fuzz*'                      │
   G4  uncontested    open PR/issue count + author diversity          │
                                                                      ▼
                                                        2 survivors, 2 findings
                                                        dmc_unrar (2 High)
                                                        tinyply   (1 CRITICAL)
```

### Why each gate earns its place — all four rejected something real

* **G1 maintained.** Killed `tiffloader` (1784d), `pocketmod` (2042d), `chibi-xmplay` (2124d), `microtar`
  (870d), `fast_obj` (480d), `cmp` (421d). Also the reason `libsixel` (629d) was dropped.
  **`pushed_at` is a lie** — it reported miniaudio as 2026-08-19 when `git log -1` said 2026-03-04.
* **G2 not saturated.** Killed `tinygltf`, `dr_libs` (⊃ dr_wav/dr_mp3/dr_flac), `stb` (⊃ stb_vorbis /
  stb_image / stb_truetype), `lz4`, `miniz` — all return **200**. Checking by *name* is not enough: names
  differ, so fuzzy-match against the full project list.
  **Inverse case worth knowing:** a vendored OSS-Fuzz'd dependency is a reason to hunt the *wrapper*. miniz is
  fuzzed and behaved correctly; `assetsys` lied to it about a buffer size → Critical.
* **G3 no in-repo harness.** Killed `bddisasm` (ships `bdshemu_fuzz` + a fuzzing Dockerfile), `qoi`,
  `minimp3`, `ufbx`, `tinyexr`.
  **Refinement that paid:** an in-repo harness is not disqualifying if it covers the wrong API. cgltf's own
  `fuzz/main.c` only calls `cgltf_parse` + `cgltf_validate`, never `cgltf_load_buffers` nor the accessor
  readers — so the accessors were fair game (they turned out clean at 6.1M execs, but the reasoning held).
* **G4 uncontested.** Killed `nanosvg` (**45 open PRs from 36 distinct authors**, and PR #300 already fixed
  the class I was about to report) and `Nuklear` (315 open issues). Author diversity is the signal, not the
  raw count.

### Supplementary gate, cheap and decisive
`grep -rl "GHSA-" <repo>` = 0 means the project has never carried an advisory. Non-ecosystem C libraries are
mostly absent from GitHub's advisory DB, so this catches what the API misses. Every C target in this hunt
returned 0 except `wildmidi` (4 advisories ⇒ swept ground ⇒ that finding is still on HOLD, dedup unfinished).

---

## 2. Stage B — shape scanning (the part that mostly did not work)

Three regex scanners, one per write-primitive shape that had actually produced a Critical.

| script | shape | derived from | result |
|---|---|---|---|
| `scan1_narrowing_cast.py` | `malloc(X)` then a copy to an **offset** destination with length `X` | paldither | no new finding |
| `scan2_cast_signed_bound.py` | narrowing cast of a parsed size, later used as a **signed bound** | assetsys | 7 hits, **1** = the known bug |
| `scan3_mul_alloc_overflow.py` | allocation size from a **multiplication** with int-width operands | videocodec, vox_loader, speech | 53 hits, **0** real |

### `scan2` — self-validating, but low yield
It found the confirmed `assetsys.h:6204` bug as **hit #2**, which is a genuine known-positive proving the
scanner works. The other six were not bugs:
* `strpool.h:889` — a real signed/unsigned clamp failure, but `strpool_inject` rejects `length <= 0` up front,
  so reaching it needs a **1 GiB** string. Latent, not reportable.
* `cute_tiled.h:998` — same `pow2ceil` shape, same unreachability.
* `tinyexr` hits — in bundled `basisu` and an unrelated `envmap` tool.

### `scan3` — 53 hits, zero real
Every one inspected was a false positive, for two recurring reasons:
* **Guarded.** `m3d.h:832` is stb_image's `_m3dstbi__malloc_mad3`, which exists *precisely* to prevent this and
  is protected by `mad3sizes_valid`.
* **Not attacker-controlled.** raylib's `width*height*sizeof(Color)` dimensions come from the application, not
  from a file.

**Why precision is so bad:** `malloc(a*b*c)` is idiomatic and almost always fine. The scanner cannot see the
guard three lines up, cannot tell whether the operands are file-derived, and cannot model the integer promotion
that actually decides the outcome. These are the three things that matter and all three need the surrounding
code.

**Verdict: keep `scan2` as a cheap sweep over a *new* codebase; retire `scan3`.** Better use of the same
budget: read the allocation sites of the one target that already passed Stage A.

---

## 3. What actually finds the bugs: the fuzzing stage Stage A feeds

Stage A/B only *choose* work. Every one of the 32 findings was proven by fuzzing + ASan, and the campaigns
were worth far more than the scanners. Two engineering results from this hunt dominate everything else:

* **Never let a harness touch the filesystem.** vgmstream's harness wrote a temp file per execution and ran at
  **0 exec/s** (libFuzzer's own counter rounded to zero) — 14,309 executions across 455 parsers in 40 minutes.
  Reimplementing its `STREAMFILE` vtable over memory (~40 lines) gave **3,934 exec/s** and 198,260 executions,
  and *raised* coverage 3,689 → 4,087 because serving companion-file opens from the same buffer reached paths
  the slow harness never did. Most media libraries have this seam: `STREAMFILE`, `SDL_RWops`,
  `fluid_file_callbacks_t`, `stbi_io_callbacks`.
* **Verify the target's objects are instrumented.** A fluidsynth build reported **30** coverage counters
  (`cov: 20`) — that was the harness alone; `fluid_sffile.c.o` had **zero** `sanitizer_cov` symbols because
  CMake silently ignored `-DCMAKE_C_FLAGS` on a reconfigure and left `-O2 -g -DNDEBUG`. After wiping the build
  dir and using `CMAKE_C_FLAGS_DEBUG`: **12,990** counters, `cov: 1480`. A blind fuzzer still runs and still
  reports "0 crashes".

---

## 4. Triage gates — where most of the value actually sits

These exist because each one caught me shipping something wrong. They are the difference between 32 reports and
32 *credible* reports.

| gate | what it caught |
|---|---|
| **Rebuild from pristine before trusting any stored artifact** | `fuzz-cgltf` held 3 crashes reproducing **3/3 deterministically**. All cgltf.h copies were md5-identical to upstream and a fresh rebuild was clean — the old binary had been built against a header I had patched to unmask. **Not findings.** |
| **Check whether a correct non-assert path exists** | OpenFBX: 6 crashes, all one `assert(false)`, all clean under `-DNDEBUG` because the next line is `return Error(...)` ⇒ **not reportable**. dmc_unrar: same-looking assert, **no** fallback ⇒ SEGV under NDEBUG ⇒ **reportable**. Identical symptom, opposite verdict. |
| **Re-run `-jobs` timeouts single-threaded** | 5 fluidsynth "timeouts" completed in 97–235 ms alone — CPU contention. vgmstream's *did* hang standalone and were real. |
| **Build store-signal PoCs at `-O0`** | At `-O1`, dead-store elimination deleted the overflowing `memcpy` and paldither reported "survived" — indistinguishable from fixed. |
| **Demand a `cov:`/`INITED` line before believing a negative** | `nohup cmd &` dies when the tool call returns; six "0 crashes" verdicts were never tests. Two of those five targets were sitting on real bugs. |
| **Confirm the claimed disclosure route exists** | `GET /repos/{o}/{r}/private-vulnerability-reporting` returned `enabled:false` on **11 of 12** targets. The "open a private GHSA" line originally in all reports was impossible to follow. Only nodemailer and fluidsynth have a working private channel. |
| **Read `SECURITY.md` before writing the report, not after** | vgmstream's contains an explicit **LLM clause** ("LLM-generated reports or patches with no clear human participation may be closed without warning") and calls DoS "not huge". raylib's directs reports to public Issues, so seeking an embargo would contradict the maintainer. |

---

## 5. Relationship to the pre-existing SAST MCP server

This pipeline is **not** a replacement for the `sast-local` MCP server; they answer different questions.

* `sast-local` (`opengrep_scan` with `config=auto` → `p/default`, plus `gitleaks_scan`, canary first) is for
  breadth over a codebase you already own, and is the right tool for web/app code.
* The scanners here are three narrow C memory-safety shapes, and §2 is a measured argument that they are **not
  worth running broadly**.
* Both share one rule: **validate the tool before believing a negative.** For `sast-local` that means a canary
  file; here it means the known-positive hit (`scan2` finding the assetsys bug) or an `INITED cov:` line.

---

## 6. Reproducing Stage A

```sh
curl -s https://raw.githubusercontent.com/nothings/single_file_libs/master/README.md -o sfl.md
# parse rows -> 297 repos -> filter parser tags -> 62 -> gate:
git -C <repo> log -1 --format=%ad --date=short                              # G1, never pushed_at
curl -s -o /dev/null -w '%{http_code}' \
  https://raw.githubusercontent.com/google/oss-fuzz/master/projects/<p>/project.yaml   # G2, 404 = unmined
find <repo> -iname '*fuzz*' -not -path '*/.git/*'                           # G3
curl -s "https://api.github.com/repos/<r>/pulls?state=open&per_page=100"    # G4, count DISTINCT authors
grep -rl "GHSA-" <repo> | wc -l                                            # supplementary
```

Unauthenticated GitHub API is **60 requests/hour** — gate by category, not all 297 at once.

## 7. Known gaps

* ~235 catalog entries were filtered out by category and never gated. The `2d` (12), `json` (11) and `net` (19)
  tags contain parsers.
* `scan1` has never produced a finding; it is unvalidated, with no known-positive.
* Stage A's G4 (uncontested) is a judgement call, not a threshold — "36 distinct authors" was obviously
  contested, but there is no principled cutoff.
