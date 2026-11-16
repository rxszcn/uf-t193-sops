package sops

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasAnchors(t *testing.T) {
	assert.False(t, HasAnchors(TreeBranches{TreeBranch{
		TreeItem{Key: "a", Value: "b"},
		TreeItem{Key: "c", Value: TreeBranch{TreeItem{Key: "d", Value: "e"}}},
	}}))

	assert.True(t, HasAnchors(TreeBranches{TreeBranch{
		TreeItem{Key: "a", Value: Anchor{Name: "x", Value: "b"}},
	}}))
	assert.True(t, HasAnchors(TreeBranches{TreeBranch{
		TreeItem{Key: "a", Value: Alias{Name: "x"}},
	}}))
	assert.True(t, HasAnchors(TreeBranches{TreeBranch{
		TreeItem{Key: MergeKey{}, Value: Alias{Name: "x"}},
	}}))
}

func TestResolveAliases(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{
			Key: "defaults",
			Value: Anchor{Name: "defaults", Value: TreeBranch{
				TreeItem{Key: "timeout", Value: 10},
				TreeItem{Key: "retries", Value: 3},
			}},
		},
		TreeItem{
			Key: "prod",
			Value: TreeBranch{
				TreeItem{Key: MergeKey{}, Value: Alias{Name: "defaults"}},
				TreeItem{Key: "timeout", Value: 20},
			},
		},
		TreeItem{Key: "dev", Value: Alias{Name: "defaults"}},
	}}

	resolved, err := ResolveAliases(branches)
	assert.NoError(t, err)
	assert.False(t, HasAnchors(resolved))

	expected := TreeBranches{TreeBranch{
		TreeItem{Key: "defaults", Value: TreeBranch{
			TreeItem{Key: "timeout", Value: 10},
			TreeItem{Key: "retries", Value: 3},
		}},
		// Explicit keys win over merged ones, and the merge key itself is gone.
		TreeItem{Key: "prod", Value: TreeBranch{
			TreeItem{Key: "timeout", Value: 20},
			TreeItem{Key: "retries", Value: 3},
		}},
		TreeItem{Key: "dev", Value: TreeBranch{
			TreeItem{Key: "timeout", Value: 10},
			TreeItem{Key: "retries", Value: 3},
		}},
	}}
	assert.Equal(t, expected, resolved)
}

// Earlier mappings in a merge sequence take precedence over later ones.
func TestResolveAliasesMergeSequencePrecedence(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "first", Value: Anchor{Name: "first", Value: TreeBranch{
			TreeItem{Key: "a", Value: 1},
			TreeItem{Key: "b", Value: 1},
		}}},
		TreeItem{Key: "second", Value: Anchor{Name: "second", Value: TreeBranch{
			TreeItem{Key: "b", Value: 2},
			TreeItem{Key: "c", Value: 2},
		}}},
		TreeItem{Key: "combined", Value: TreeBranch{
			TreeItem{Key: MergeKey{}, Value: []interface{}{
				Alias{Name: "first"},
				Alias{Name: "second"},
			}},
		}},
	}}

	resolved, err := ResolveAliases(branches)
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{
		TreeItem{Key: "a", Value: 1},
		TreeItem{Key: "b", Value: 1},
		TreeItem{Key: "c", Value: 2},
	}, resolved[0][2].Value)
}

func TestResolveAliasesUnknownAnchor(t *testing.T) {
	_, err := ResolveAliases(TreeBranches{TreeBranch{
		TreeItem{Key: "a", Value: Alias{Name: "missing"}},
	}})
	assert.Error(t, err)
}

func TestResolveAliasesRecursive(t *testing.T) {
	_, err := ResolveAliases(TreeBranches{TreeBranch{
		TreeItem{Key: "a", Value: Anchor{Name: "self", Value: TreeBranch{
			TreeItem{Key: "b", Value: Alias{Name: "self"}},
		}}},
	}})
	assert.Error(t, err)
}

func TestValidateAnchors(t *testing.T) {
	assert.NoError(t, ValidateAnchors(TreeBranches{TreeBranch{
		TreeItem{Key: "a", Value: Anchor{Name: "x", Value: "v"}},
		TreeItem{Key: "b", Value: Alias{Name: "x"}},
	}}))
	assert.Error(t, ValidateAnchors(TreeBranches{TreeBranch{
		TreeItem{Key: "b", Value: Alias{Name: "x"}},
		TreeItem{Key: "a", Value: Anchor{Name: "x", Value: "v"}},
	}}))
}

func TestSetThroughAliasEditsAnchorDefinition(t *testing.T) {
	branches := TreeBranch{
		TreeItem{Key: "defaults", Value: Anchor{Name: "defaults", Value: TreeBranch{
			TreeItem{Key: "timeout", Value: 10},
		}}},
		TreeItem{Key: "dev", Value: Alias{Name: "defaults"}},
	}

	updated, changed := branches.Set([]interface{}{"dev", "timeout"}, 30)
	assert.True(t, changed)
	// The alias is still a reference...
	assert.Equal(t, Alias{Name: "defaults"}, updated[1].Value)
	// ...and the anchor definition carries the new value, so every alias sees it.
	anchor := updated[0].Value.(Anchor)
	assert.Equal(t, 30, anchor.Value.(TreeBranch)[0].Value)
}

func TestUnsetThroughAliasEditsAnchorDefinition(t *testing.T) {
	branches := TreeBranch{
		TreeItem{Key: "defaults", Value: Anchor{Name: "defaults", Value: TreeBranch{
			TreeItem{Key: "timeout", Value: 10},
			TreeItem{Key: "retries", Value: 3},
		}}},
		TreeItem{Key: "dev", Value: Alias{Name: "defaults"}},
	}

	updated, err := branches.Unset([]interface{}{"dev", "timeout"})
	assert.NoError(t, err)
	assert.Equal(t, Alias{Name: "defaults"}, updated[1].Value)
	anchor := updated[0].Value.(Anchor)
	assert.Equal(t, TreeBranch{
		TreeItem{Key: "retries", Value: 3},
	}, anchor.Value)
}

func TestSetInsideAnchorKeepsAnchor(t *testing.T) {
	branches := TreeBranch{
		TreeItem{Key: "defaults", Value: Anchor{Name: "defaults", Value: TreeBranch{
			TreeItem{Key: "timeout", Value: 10},
		}}},
		TreeItem{Key: "dev", Value: Alias{Name: "defaults"}},
	}

	updated, changed := branches.Set([]interface{}{"defaults", "timeout"}, 40)
	assert.True(t, changed)
	anchor := updated[0].Value.(Anchor)
	assert.Equal(t, "defaults", anchor.Name)
	assert.Equal(t, 40, anchor.Value.(TreeBranch)[0].Value)
	assert.Equal(t, Alias{Name: "defaults"}, updated[1].Value)
}

func TestTruncateThroughAlias(t *testing.T) {
	branches := TreeBranch{
		TreeItem{Key: "defaults", Value: Anchor{Name: "defaults", Value: TreeBranch{
			TreeItem{Key: "timeout", Value: 10},
		}}},
		TreeItem{Key: "dev", Value: Alias{Name: "defaults"}},
	}

	v, err := branches.Truncate([]interface{}{"dev", "timeout"})
	assert.NoError(t, err)
	assert.Equal(t, 10, v)

	v, err = branches.Truncate([]interface{}{"dev"})
	assert.NoError(t, err)
	assert.Equal(t, TreeBranch{TreeItem{Key: "timeout", Value: 10}}, v)
}

func TestEncryptDoesNotEncryptAliases(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "shared", Value: Anchor{Name: "shared", Value: "secret"}},
		TreeItem{Key: "also", Value: Alias{Name: "shared"}},
		TreeItem{Key: "list", Value: Anchor{Name: "list", Value: []interface{}{"a"}}},
		TreeItem{Key: "list2", Value: Alias{Name: "list"}},
	}}
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedSuffix: DefaultUnencryptedSuffix}}

	_, err := tree.Encrypt(make([]byte, 32), encPrefixCipher{})
	assert.NoError(t, err)

	anchor := tree.Branches[0][0].Value.(Anchor)
	assert.Equal(t, "ENC:secret", anchor.Value)
	// The alias is still a reference; it was not encrypted a second time.
	assert.Equal(t, Alias{Name: "shared"}, tree.Branches[0][1].Value)
	listAnchor := tree.Branches[0][2].Value.(Anchor)
	assert.Equal(t, []interface{}{"ENC:a"}, listAnchor.Value)
	assert.Equal(t, Alias{Name: "list"}, tree.Branches[0][3].Value)
}

// A value referenced from a location with a different encryption policy than
// the anchor's is a hazard of reference semantics, and must be reported rather
// than silently stored in the wrong form.
func TestFindAnchorEncryptionMismatches(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "defaults", Value: Anchor{Name: "defaults", Value: TreeBranch{
			TreeItem{Key: "timeout", Value: 10},
		}}},
		TreeItem{Key: "dev", Value: Alias{Name: "defaults"}},
		// The alias is under an unencrypted suffix while the anchor is not.
		TreeItem{Key: "public_unencrypted", Value: Alias{Name: "defaults"}},
	}}
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedSuffix: DefaultUnencryptedSuffix}}

	mismatches := FindAnchorEncryptionMismatches(tree)
	assert.Len(t, mismatches, 1)
	assert.Equal(t, "defaults", mismatches[0].AnchorName)
	assert.Equal(t, "public_unencrypted", mismatches[0].AliasPath[strings.LastIndex(mismatches[0].AliasPath, ":")+1:])
	assert.True(t, mismatches[0].AnchorEncrypted)
	assert.False(t, mismatches[0].AliasEncrypted)
}

// YAML lets an anchor be redefined; an alias refers to the definition that
// precedes it, not to the last one in the document.
func TestResolveAliasesUsesPrecedingDefinition(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "first", Value: Anchor{Name: "x", Value: "one"}},
		TreeItem{Key: "use1", Value: Alias{Name: "x"}},
		TreeItem{Key: "second", Value: Anchor{Name: "x", Value: "two"}},
		TreeItem{Key: "use2", Value: Alias{Name: "x"}},
	}}

	resolved, err := ResolveAliases(branches)
	assert.NoError(t, err)
	assert.Equal(t, TreeBranches{TreeBranch{
		TreeItem{Key: "first", Value: "one"},
		TreeItem{Key: "use1", Value: "one"},
		TreeItem{Key: "second", Value: "two"},
		TreeItem{Key: "use2", Value: "two"},
	}}, resolved)
}

func TestEmitAsMapResolvesAliases(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "defaults", Value: Anchor{Name: "defaults", Value: TreeBranch{
			TreeItem{Key: "timeout", Value: 10},
		}}},
		TreeItem{Key: "dev", Value: Alias{Name: "defaults"}},
	}}

	data, err := EmitAsMap(branches)
	assert.NoError(t, err)
	assert.Equal(t, map[string]interface{}{
		"defaults": map[string]interface{}{"timeout": 10},
		"dev":      map[string]interface{}{"timeout": 10},
	}, data)
}

// Repointing an alias changes which plaintext a key reveals while leaving all
// ciphertext untouched, so the alias name has to be authenticated.
func TestMACCoversAliasNames(t *testing.T) {
	branches := TreeBranches{TreeBranch{
		TreeItem{Key: "a", Value: Anchor{Name: "a", Value: "first"}},
		TreeItem{Key: "b", Value: Anchor{Name: "b", Value: "second"}},
		TreeItem{Key: "ref", Value: Alias{Name: "a"}},
	}}
	tree := Tree{Branches: branches, Metadata: Metadata{UnencryptedSuffix: DefaultUnencryptedSuffix}}
	macA, err := tree.Encrypt(make([]byte, 32), encPrefixCipher{})
	assert.NoError(t, err)

	// Same values and same ciphertext, only the alias target differs.
	tampered := Tree{Branches: TreeBranches{TreeBranch{
		TreeItem{Key: "a", Value: Anchor{Name: "a", Value: "first"}},
		TreeItem{Key: "b", Value: Anchor{Name: "b", Value: "second"}},
		TreeItem{Key: "ref", Value: Alias{Name: "b"}},
	}}, Metadata: Metadata{UnencryptedSuffix: DefaultUnencryptedSuffix}}
	macB, err := tampered.Encrypt(make([]byte, 32), encPrefixCipher{})
	assert.NoError(t, err)

	assert.NotEqual(t, macA, macB)
}
