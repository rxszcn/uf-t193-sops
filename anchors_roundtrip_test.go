package sops_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/pgp"
	"github.com/getsops/sops/v3/stores"
	"github.com/getsops/sops/v3/stores/json"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
)

// The document below uses every structure the anchor support has to preserve:
// an anchored mapping that is both merged with << and aliased, an anchored
// scalar, an anchored sequence, and a literal string key that merely looks like
// a merge key.
const anchorDocument = `defaults: &defaults
    timeout: 10
    retries: 3
prod:
    <<: *defaults
    timeout: 20
dev: *defaults
shared: &shared secret-value
also: *shared
list: &list
    - a
    - b
list2: *list
"<<": literal
`

// TestEncryptedAnchorRoundTrip is the end-to-end counterpart of the store-level
// tests: a document is encrypted, written out, parsed again, decrypted and
// emitted. The emitted plaintext must be byte-identical to the input, and
// parsing it again must yield the same anchor/alias/merge-key structure. This
// is what fails if anchors are expanded into snapshots somewhere along the
// line.
func TestEncryptedAnchorRoundTrip(t *testing.T) {
	store := &yamlstore.Store{}
	branches, err := store.LoadPlainFile([]byte(anchorDocument))
	assert.NoError(t, err)

	original, err := store.EmitPlainFile(branches)
	assert.NoError(t, err)

	key := bytes.Repeat([]byte{'k'}, 32)
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
			Version:           "3.13.3",
			LastModified:      time.Now().UTC(),
			KeyGroups: []sops.KeyGroup{{
				&pgp.MasterKey{
					Fingerprint:  "0000000000000000000000000000000000000000",
					EncryptedKey: "encrypted",
					CreationDate: time.Now().UTC(),
				},
			}},
		},
	}

	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(key, cipher)
	assert.NoError(t, err)
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, key, tree.Metadata.LastModified.Format(time.RFC3339))
	assert.NoError(t, err)

	encrypted, err := store.EmitEncryptedFile(tree)
	assert.NoError(t, err)

	// The encrypted document must still contain one anchor definition per
	// anchor and one alias per use, rather than an encrypted copy at each use.
	for _, anchor := range []string{"&defaults", "&shared", "&list"} {
		assert.Equal(t, 1, bytes.Count(encrypted, []byte(anchor)), "anchor %s should be defined once", anchor)
	}
	// *defaults is used by the merge key and by "dev"; the scalar and sequence
	// anchors are used once each.
	assert.Equal(t, 2, bytes.Count(encrypted, []byte("*defaults")))
	assert.Equal(t, 1, bytes.Count(encrypted, []byte("*shared")))
	assert.Equal(t, 1, bytes.Count(encrypted, []byte("*list")))
	assert.Contains(t, string(encrypted), "<<: *defaults")

	// Load the encrypted document from scratch, as a decrypt run would.
	loaded, err := store.LoadEncryptedFile(encrypted)
	assert.NoError(t, err)
	assert.True(t, sops.HasAnchors(loaded.Branches))
	loaded.Metadata.DataKey = key

	decryptCipher := aes.NewCipher()
	computedMac, err := loaded.Decrypt(key, decryptCipher)
	assert.NoError(t, err)
	storedMac, err := decryptCipher.Decrypt(
		loaded.Metadata.MessageAuthenticationCode, key,
		loaded.Metadata.LastModified.Format(time.RFC3339))
	assert.NoError(t, err)
	assert.Equal(t, storedMac, computedMac)

	decrypted, err := store.EmitPlainFile(loaded.Branches)
	assert.NoError(t, err)
	assert.Equal(t, string(original), string(decrypted))

	// Re-parse the decrypted output and compare the structure it yields with
	// the structure of the input document, which is the check that would catch
	// a merge key degrading into an inline snapshot.
	reparsed, err := store.LoadPlainFile(decrypted)
	assert.NoError(t, err)
	reference, err := store.LoadPlainFile([]byte(anchorDocument))
	assert.NoError(t, err)
	assert.Equal(t, reference, reparsed)

	// And the re-parsed tree must still be anchor-aware, not just equal by
	// value: merging must remain a reference.
	merged, ok := reparsed[0][1].Value.(sops.TreeBranch)
	assert.True(t, ok)
	assert.Equal(t, sops.MergeKey{}, merged[0].Key)
	assert.Equal(t, sops.Alias{Name: "defaults"}, merged[0].Value)
}

// TestSharedPlaintextEncryptedOnce pins down the encryption semantics chosen
// for a plaintext value that is referenced several times through anchors: it is
// encrypted once, at the anchor definition. Every alias points at that single
// ciphertext, so a change to the base value propagates to all references, the
// document does not grow with each use, and re-encrypting is stable.
func TestSharedPlaintextEncryptedOnce(t *testing.T) {
	store := &yamlstore.Store{}
	branches, err := store.LoadPlainFile([]byte(`base: &base
    password: hunter2
a: *base
b: *base
`))
	assert.NoError(t, err)

	key := bytes.Repeat([]byte{'k'}, 32)
	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
			Version:           "3.13.3",
			LastModified:      time.Now().UTC(),
			KeyGroups: []sops.KeyGroup{{
				&pgp.MasterKey{
					Fingerprint:  "0000000000000000000000000000000000000000",
					EncryptedKey: "encrypted",
					CreationDate: time.Now().UTC(),
				},
			}},
		},
	}
	cipher := aes.NewCipher()
	mac, err := tree.Encrypt(key, cipher)
	assert.NoError(t, err)
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(mac, key, tree.Metadata.LastModified.Format(time.RFC3339))
	assert.NoError(t, err)

	encrypted, err := store.EmitEncryptedFile(tree)
	assert.NoError(t, err)

	// Exactly one ciphertext exists in the data portion of the document; the
	// other uses are aliases. (The metadata section has its own MAC ciphertext.)
	data, _, _ := bytes.Cut(encrypted, []byte("\nsops:"))
	assert.Equal(t, 1, bytes.Count(data, []byte("ENC[AES256_GCM")))
	assert.Equal(t, 1, bytes.Count(data, []byte("&base")))
	assert.Equal(t, 2, bytes.Count(data, []byte("*base")))

	loaded, err := store.LoadEncryptedFile(encrypted)
	assert.NoError(t, err)
	loaded.Metadata.DataKey = key
	_, err = loaded.Decrypt(key, aes.NewCipher())
	assert.NoError(t, err)
	plain, err := store.EmitPlainFile(loaded.Branches)
	assert.NoError(t, err)
	assert.Equal(t, `base: &base
    password: hunter2
a: *base
b: *base
`, string(plain))

	// Changing the base value is visible through every reference, which is the
	// behaviour the old inline-snapshot encoding silently broke.
	updated, changed := loaded.Branches[0].Set([]interface{}{"a", "password"}, "changed")
	assert.True(t, changed)
	plain, err = store.EmitPlainFile([]sops.TreeBranch{updated})
	assert.NoError(t, err)
	assert.Contains(t, string(plain), "password: changed")
	assert.NotContains(t, string(plain), "hunter2")
}

// prefixCipher makes the ciphertext visible in the emitted document, so the
// tests can count how many ciphertexts were produced.
type prefixCipher struct{}

func (prefixCipher) Encrypt(value interface{}, key []byte, path string) (string, error) {
	b, err := sops.ToBytes(value)
	if err != nil {
		return "", err
	}
	return "ENC:" + string(b), nil
}

func (prefixCipher) Decrypt(value string, key []byte, path string) (interface{}, error) {
	v, ok := strings.CutPrefix(value, "ENC:")
	if !ok {
		return nil, errors.New("value is not encrypted")
	}
	return v, nil
}

// TestMACOfLegacyAliasDocument compares the MAC computed for a tree that came
// from a document written before anchors were preserved. Such documents have no
// anchor structure, so the MAC must depend only on values, not on this change.
func TestMACOfLegacyAliasDocument(t *testing.T) {
	// The expansion of a document with aliases is itself anchor-free.
	branches := sops.TreeBranches{sops.TreeBranch{
		sops.TreeItem{Key: "a", Value: "v"},
		sops.TreeItem{Key: "b", Value: "v"},
	}}
	tree := sops.Tree{Branches: branches, Metadata: sops.Metadata{UnencryptedSuffix: sops.DefaultUnencryptedSuffix}}
	mac, err := tree.Encrypt(make([]byte, 32), prefixCipher{})
	assert.NoError(t, err)
	assert.NotEmpty(t, mac)

	// An equivalent anchored document additionally authenticates the structure,
	// so it gets a different MAC even where the values are the same.
	anchored := sops.Tree{Branches: sops.TreeBranches{sops.TreeBranch{
		sops.TreeItem{Key: "a", Value: sops.Anchor{Name: "a", Value: "v"}},
		sops.TreeItem{Key: "b", Value: sops.Alias{Name: "a"}},
	}}, Metadata: sops.Metadata{UnencryptedSuffix: sops.DefaultUnencryptedSuffix}}
	anchoredMac, err := anchored.Encrypt(make([]byte, 32), prefixCipher{})
	assert.NoError(t, err)
	assert.NotEqual(t, mac, anchoredMac)
}
func TestResolveAliasesForPlainFormat(t *testing.T) {
	store := &yamlstore.Store{}
	branches, err := store.LoadPlainFile([]byte(anchorDocument))
	assert.NoError(t, err)

	resolved, err := sops.ResolveAliases(branches)
	assert.NoError(t, err)
	assert.False(t, sops.HasAnchors(resolved))

	// The merged mapping is materialized at the merge site, with the explicit
	// key winning, and the alias at "dev" is expanded to the same content.
	prod := resolved[0][1].Value.(sops.TreeBranch)
	assert.Equal(t, sops.TreeBranch{
		sops.TreeItem{Key: "timeout", Value: 20},
		sops.TreeItem{Key: "retries", Value: 3},
	}, prod)
	dev := resolved[0][2].Value.(sops.TreeBranch)
	assert.Equal(t, sops.TreeBranch{
		sops.TreeItem{Key: "timeout", Value: 10},
		sops.TreeItem{Key: "retries", Value: 3},
	}, dev)
}

// Plain formats must refuse to write a tree that still has anchors, instead of
// silently duplicating ciphertext.
func TestPlainFormatRefusesAnchors(t *testing.T) {
	store := &yamlstore.Store{}
	branches, err := store.LoadPlainFile([]byte(anchorDocument))
	assert.NoError(t, err)

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			UnencryptedSuffix: sops.DefaultUnencryptedSuffix,
			Version:           "3.13.3",
			LastModified:      time.Now().UTC(),
			KeyGroups: []sops.KeyGroup{{
				&pgp.MasterKey{
					Fingerprint:  "0000000000000000000000000000000000000000",
					EncryptedKey: "encrypted",
					CreationDate: time.Now().UTC(),
				},
			}},
		},
	}
	_, err = store.EmitEncryptedFile(tree)
	assert.NoError(t, err)

	// The metadata-only tree used here has not been walked, so it still has
	// anchors; writing it as JSON must be refused.
	jsonStore := json.NewStore(&config.JSONStoreConfig{Indent: 4})
	_, err = jsonStore.EmitEncryptedFile(tree)
	assert.ErrorIs(t, err, stores.ErrAnchorsNotSupported)
}
