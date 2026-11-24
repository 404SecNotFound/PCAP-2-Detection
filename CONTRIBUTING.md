# Contributing

Thank you for helping. This series stays useful only if every rule is tested and every claim can be traced to evidence.

## Adding a case

1. Create `cases/<YYYY-MM-DD>-<short-slug>/` using the exercise date from the source page.
2. Copy the layout of an existing case.

```
README.md
analysis/      timeline.md, stages.md, decoded-config.md
iocs/          iocs.csv, iocs.stix.json, hashes.txt
detections/    suricata/, yara/, sigma/, kql/, siem/
tests/         expected-alerts.json, run_tests.sh
attack-layer.json
media/         screenshots and media/README.md
```

3. Credit the original author in the case README and link the original exercise page. Never commit the capture, the exercise zip or any extracted sample.
4. Generate the STIX bundle from `iocs.csv` with `python3 tools/build_stix.py <case-dir>` so the ids stay deterministic.
5. Add the walkthrough under `docs/<slug>/` and a row to the cases table in the root README and in `docs/index.html`.

## Rule naming

- Suricata sids for this series use the range 9260000 to 9269999. Check existing cases and take sids that are not already in use.
- YARA rule names use lower case with underscores and include the family or carrier type.
- Sigma rules hold one rule per file, each with a UUIDv4 `id`, and the file name matches the rule title in lower case with underscores.
- KQL files hold one query each and start with a comment naming the file.

## Evidence labels

Every factual statement in `analysis/` carries one label.

- `[PCAP]` seen in the capture
- `[Decoded]` recovered by static decoding
- `[Notes]` stated by the exercise author
- `[Inference]` your own reasoning

If a value cannot be confirmed, write `TODO` and say what is missing. Never invent a value.

## Writing style

UK English, plain direct sentences, no em dashes. Defang network indicators in human-readable files (`hxxp`, `[.]`). Machine-readable feeds keep live values and say so.

## Tests required before a pull request

1. Run `cases/<case>/tests/run_tests.sh --pcap <path> [--mp4 <path>]` against your local copy of the capture and record the measured counts in `expected-alerts.json`.
2. Run the checks from `.github/workflows/validate.yml` locally where you can (sigma check, YARA compile, `suricata -T`, STIX validation, JSON checks, hygiene).
3. Confirm `git status` shows no capture, archive, executable, library or video file.
4. Open a pull request against `main`. Do not force-push shared branches.
