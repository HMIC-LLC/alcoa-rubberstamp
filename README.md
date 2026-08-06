# ALCOA RubberStamp v1.0.0

ALCOA RubberStamp creates a deterministic commitment to a directory of files.
It is a reference implementation of the lowest-friction layer of the
State-Governed Anchoring Protocol (SGAP): private payload, portable manifest,
independently checkable commitment.

It is not a validated GMP system, a Part 11 compliance product, an electronic
signature system, or proof that a record is true. It proves that a particular
set of file bytes and portable relative paths matches a particular commitment.

## Requirements

- Python 3.10 or newer
- Optional: `opentimestamps-client` and its `ots` command for public timestamping

The commitment and verification engine uses only the Python standard library.
No network call occurs unless `--ots` or `--ots-receipt` is explicitly supplied.

## Create a commitment

```text
python alcoa_rubberstamp.py create --root /path/to/records
```

The default output directory is `<root>/stamps`. It is excluded from the file
set. A custom output directory is also excluded when it is inside the root:

```text
python alcoa_rubberstamp.py create --root /path/to/records --out /path/to/records/proofs
```

The command writes:

- `alcoa-manifest-<UTC>.json`: file paths, sizes, hashes, algorithm metadata,
  optional prior-state binding, and the commitment
- `alcoa-commitment-<UTC>.txt`: the commitment alone

The manifest never contains the absolute root path.

## Verify a file set

```text
python alcoa_rubberstamp.py verify \
  --root /path/to/records \
  --manifest /path/to/records/stamps/alcoa-manifest-<UTC>.json \
  --commitment-file /path/to/records/stamps/alcoa-commitment-<UTC>.txt
```

Verification reports added, missing, size-changed, and content-changed files.
It also recomputes the file-tree root, prior-state digest, and final commitment.

## Optional OpenTimestamps proof

Install the external client:

```text
python -m pip install opentimestamps-client
```

Then opt into network submission:

```text
python alcoa_rubberstamp.py create --root /path/to/records --ots
```

The tool executes `ots stamp <commitment-file>`. If the client is missing,
times out, returns an error, or fails to create a receipt, RubberStamp exits
nonzero. The local manifest and commitment remain available for inspection or
later submission.

An `.ots` file is not automatically a confirmed Bitcoin timestamp. Calendar
proofs may require later upgrade. Verify independently after the calendar has
anchored the commitment:

```text
python alcoa_rubberstamp.py verify \
  --root /path/to/records \
  --manifest /path/to/alcoa-manifest-<UTC>.json \
  --ots-receipt /path/to/alcoa-commitment-<UTC>.txt.ots
```

The original commitment text file must remain beside its `.ots` receipt for
the OpenTimestamps client.

## Time claims and prior-state binding

A file-set commitment alone makes no time claim.

A successfully verified OpenTimestamps proof can establish an external upper
bound: the committed bytes existed no later than the independently verified
anchor time.

To create a candidate lower bound as well, explicitly bind an independently
verifiable prior state:

```text
python alcoa_rubberstamp.py create \
  --root /path/to/records \
  --prior-state examples/prior-state.example.json \
  --ots
```

The prior-state JSON is canonically encoded and its SHA-256 digest is included
in the final commitment. This only supports a lower-bound claim when the named
state was independently authentic and was unpredictable before its stated
observation. RubberStamp validates the document's shape; it does not validate
the outside world, its clock, its source, or its unpredictability.

Therefore:

- no prior state + no verified OTS proof: no time bound
- authentic prior-state binding only: candidate lower bound only
- verified OTS proof only: external upper bound only
- authentic prior-state binding + verified OTS proof: candidate bounded interval

## Precise privacy and network semantics

Without `--ots` or `--ots-receipt`, RubberStamp performs no intentional network
operation. It reads the selected local files and writes local artifacts.

With `--ots`, the external OpenTimestamps client communicates with its calendar
servers. The commitment file is supplied to that client. OpenTimestamps commits
to the file and normal network metadata (including source IP, timing, routing,
and server logs) may be observable. RubberStamp does not send filenames,
directory structure, file contents, or its manifest to the calendar servers,
but this statement cannot constrain independent behavior of the installed
OpenTimestamps client or network infrastructure.

The shareable manifest contains relative filenames, sizes, and per-file hashes.
Those values may themselves be sensitive. Review the manifest before sharing it.
The optional prior-state document is embedded in the manifest and must not
contain secrets.

## Commitment algorithm

Schema: `hmic.alcoa-rubberstamp.manifest/v1`

Algorithm: `sgap-file-set-merkle-sha256-v1`

1. Reject symlinks and portable path collisions.
2. Normalize each relative path to Unicode NFC and `/` separators.
3. Sort paths by their UTF-8 bytes.
4. For each file, compute SHA-256 of the content and record its byte size.
5. Compute each leaf as SHA-256 of a domain tag, normalized path, size, and
   binary content hash, separated by NUL bytes.
6. Build a binary Merkle tree with domain-separated parent hashes; duplicate an
   odd final node at each layer.
7. Canonically encode and hash the optional prior-state object, or use 32 zero
   bytes when none is supplied.
8. Compute the final commitment from a domain tag, file-tree root, and
   prior-state digest.

The file path, content hash, and size are all committed. The construction is
stable across supported operating systems for the same portable file set.

## Deliberate limitations

- Regular files only; symlinks are rejected.
- Paths that differ only by Unicode normalization or case folding are rejected
  to avoid Windows/macOS/Linux ambiguity.
- The tool does not stop other processes from editing files. It detects common
  changes during hashing and exits nonzero, but callers should still use a
  quiescent snapshot for high-consequence work.
- It does not provide identity, authorization, electronic signatures, workflow
  integration, retention governance, or validation.
- It does not prove scientific correctness, intent, or regulatory compliance.

## Tests

```text
python -m unittest discover -s tests -v
```

## License

MIT. See `LICENSE`.
