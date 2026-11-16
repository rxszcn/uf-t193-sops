# YAML anchors, aliases and merge keys

SOPS preserves the YAML anchor/alias/merge-key structure of a document across
encryption and decryption. A file that organizes environment parameters with
anchors and merge keys (`<<`) keeps those definitions and references after an
encrypt → store → decrypt round trip: it does not grow, and changing the base
value keeps propagating to every reference.

## Why this needed work

Before this change the YAML loader expanded every alias into an independent
copy. A merge key (`<<`) was loaded as an ordinary string key and its merged
mapping was baked into the document. After an encrypt/decrypt cycle the file
therefore contained:

* no `&anchor` definitions and no `*alias` references at all, only expanded
  snapshots, which made the file grow with each use;
* a literal `!!merge <<` key whose value was an inline copy;
* no propagation: editing the base configuration no longer changed the
  references, contrary to how YAML anchors are understood;
* and none of this produced a warning.

## Encryption semantics

A plaintext value referenced from several places through anchors is encrypted
**once**, at its anchor definition. Every alias is stored as a reference
(`*name`) and points at that single ciphertext.

This has the consequences one expects from YAML anchors:

* editing the anchor definition changes every reference;
* the encrypted file does not grow with the number of references;
* re-encrypting the same plaintext produces a stable document.

The alternative — encrypting an independent ciphertext at every use — would
reintroduce the snapshot behaviour (growth, no propagation) while paying for
duplicate ciphertext, so it was rejected as the default. Documents that have
been converted away from YAML (see below) do use per-use ciphertext, because
their target format cannot express the reference.

### What is authenticated

Anchor and alias **names** are cleartext and are not encrypted, but they decide
which plaintext a location reveals: repointing `*name` at a different anchor
would change the plaintext without touching any ciphertext. They are therefore
included in the MAC (see `WriteStructureToMAC`). The anchored values themselves
are covered by the regular value walk. `Encrypt` and `Decrypt` write the same
structure to the MAC, so their results agree.

### Encryption-policy mismatches are reported

Because the alias is a reference, the encryption policy (suffix/regex rules) at
the **anchor definition** decides the stored form. If an alias sits at a location
that the policy would treat differently (for example the anchor is encrypted but
an alias is under an `_unencrypted` suffix), the value can end up in cleartext
where encryption was expected. `Encrypt` emits a warning for each such case
rather than silently proceeding; the document is not refused, since this is a
property of the reference structure, not a syntax error.

## Interoperability with older versions

The new format is deliberately aligned so that upgrades do not break existing
files:

* **Old files, new SOPS** can still be decrypted. A document written by a version
  that expanded aliases loads as a merge key with an inline mapping
  (`!!merge <<` is recognized as a merge key) and decrypts exactly as before.
* **New files, old SOPS** fail to decrypt *only when the document actually
  contains anchors or aliases*, because the old code cannot interpret `&name`
  and `*name` nodes. This is unavoidable: preserving the reference is the point
  of the change, and an old version has no representation for it. Files without
  anchors are byte-for-byte compatible in both directions.
* **Documents written by old versions and re-encrypted by the new one** keep the
  same MAC for the value/content part, so they remain decryptable by old versions.
  When the new code rewrites an inline `<<` mapping it writes the plain merge key
  (`<<:`) instead of `!!merge <<:`; both are valid YAML, the parser-level
  meaning is the same, and old versions read the rewritten file fine.
* A document that is anchor-free never uses the new structure, so its MAC and
  its bytes are unchanged.

## Other output formats

JSON, INI, dotenv and binary have no notion of anchors. When a tree is emitted
to one of them, aliases and merge keys are resolved to the values they refer to
first (`ResolveAliases`, called by the CLI before encryption), which reproduces
the pre-existing expanded output. Writing a tree that *still* contains anchors to
such a format is refused with `stores.ErrAnchorsNotSupported` rather than
duplicating ciphertext.

`--extract` always resolves the extracted subtree: it is emitted as a
standalone document, so an alias may refer to an anchor that is not part of the
output. This matches what extract produced before aliases were preserved.

## Editing

`set` and `unset` treat references as references:

* writing a path that runs through an alias edits the anchor definition, so the
  alias stays a reference and every other alias sees the change;
* writing inside an anchor definition keeps it anchored;
* the merge key is addressable by its YAML spelling, `["<<"]`, so a path can
  replace or remove it instead of creating a second literal `<<` key.

The YAML store refuses to emit documents that could not be parsed again: an
alias with no preceding anchor, or a merge key whose value is not a
mapping/sequence of mappings.

## Tests

* `stores/yaml/store_test.go` covers loading, round-tripping and re-parsing
  anchors, merge keys (single and sequence) and the literal quoted `"<<"`.
* `anchors_test.go` covers resolution, merge precedence, recursive/unresolved
  aliases, mutation through aliases, MAC coverage, and the mismatch warning.
* `anchors_roundtrip_test.go` covers a full encrypt → parse → decrypt → parse
  cycle and asserts that the re-parsed structure is identical, and that a
  shared plaintext is encrypted exactly once.
* `decrypt/anchors_test.go` covers the public decryption API.
