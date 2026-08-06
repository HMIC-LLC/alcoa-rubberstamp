# Changelog

## 1.0.0 - 2026-08-04

- Define a versioned, domain-separated, cross-platform commitment algorithm.
- Commit normalized relative path, content SHA-256, and byte size.
- Reject symlinks and case/Unicode-normalization path collisions.
- Remove absolute source paths from shareable manifests.
- Exclude the selected output directory, including custom in-root output names.
- Add explicit schema, algorithm, tool version, and UTC artifact timestamps.
- Add deterministic file-set verification with added/missing/changed detection.
- Make OpenTimestamps an explicit opt-in network action and fail nonzero on error.
- Add optional canonical prior-state binding and bounded-time claim guidance.
- Clarify privacy, network metadata, validation, and regulatory limitations.

This is a new public interface. It intentionally does not reproduce the custom
ASCII-hex Merkle construction or command-line interface of the unpublished
0.1 prototype.
