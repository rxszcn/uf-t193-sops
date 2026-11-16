package sops

import (
	"fmt"
	"io"
	"strings"
)

// This file implements the semantics of YAML anchors, aliases and merge keys
// (<<) in the sops tree.
//
// Anchors are kept as references rather than being expanded while loading: an
// anchor definition is stored as an Anchor wrapping its content, and every use
// of it is stored as an Alias naming the anchor. This is what lets a document
// keep its shape, keep its size, and keep later edits of the anchor visible at
// every alias, across an encrypt/decrypt round trip.
//
// Aliases are structural: they carry no plaintext of their own. Encrypt walks
// the anchored content exactly once, so the ciphertext exists only at the
// anchor definition. Formats that cannot express anchors (JSON, INI, dotenv,
// binary) therefore have to resolve aliases to their (already decrypted)
// values when emitting plaintext; see ResolveAliases.

// anchorScope maps anchor names to the values they refer to. Anchors may be
// redefined in a document; per YAML semantics an alias refers to the most
// recent preceding definition, which is why the resolver registers anchors as
// it walks the document in order rather than pre-collecting them.
type anchorScope map[string]interface{}

func anchorScopeFor(branch TreeBranch) anchorScope {
	scope := anchorScope{}
	var collect func(value interface{})
	collect = func(value interface{}) {
		switch value := value.(type) {
		case Anchor:
			scope[value.Name] = value.Value
			collect(value.Value)
		case TreeBranch:
			for _, item := range value {
				collect(item.Value)
			}
		case []interface{}:
			for _, item := range value {
				collect(item)
			}
		}
	}
	collect(branch)
	return scope
}

// WriteStructureToMAC writes the structural part of the tree (anchor and alias
// names) to a MAC writer, in document order. Anchor and alias names are
// cleartext, yet they decide which plaintext a location reveals, so leaving
// them out of the MAC would let someone repoint an alias at a different anchor
// without touching any ciphertext. The anchored values themselves are covered
// by the regular value walk.
//
// Encrypt and Decrypt both call it over the same (unmodified) structure, so
// their MACs agree. Merge keys are deliberately not written: a document written
// by a version that expanded aliases contains a merge key with an inline copy,
// and had no anchor or alias names to authenticate; writing "<<" here would
// change the MAC of such files and make them undecryptable. When a merge key
// points at an alias, that alias is written, which is what needs protecting.
//
// The exact bytes are part of the file format: changing them would make every
// document using anchors fail its MAC check.
func WriteStructureToMAC(w io.Writer, branches TreeBranches) error {
	for _, branch := range branches {
		if err := writeStructureToMACValue(w, branch); err != nil {
			return err
		}
	}
	return nil
}

func writeStructureToMACValue(w io.Writer, value interface{}) error {
	switch value := value.(type) {
	case Anchor:
		if _, err := fmt.Fprintf(w, "&%s:", value.Name); err != nil {
			return err
		}
		return writeStructureToMACValue(w, value.Value)
	case Alias:
		_, err := fmt.Fprintf(w, "*%s", value.Name)
		return err
	case TreeBranch:
		for _, item := range value {
			if err := writeStructureToMACValue(w, item.Value); err != nil {
				return err
			}
		}
		return nil
	case []interface{}:
		for _, item := range value {
			if err := writeStructureToMACValue(w, item); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// HasAnchors reports whether the branches contain an anchor, an alias or a
// merge key. Stores that cannot represent them use it to refuse to emit an
// encrypted file rather than silently duplicating ciphertext.
func HasAnchors(branches TreeBranches) bool {
	for _, branch := range branches {
		if hasAnchorsInValue(branch) {
			return true
		}
	}
	return false
}

func hasAnchorsInValue(value interface{}) bool {
	switch value := value.(type) {
	case Anchor, Alias, MergeKey:
		return true
	case TreeBranch:
		for _, item := range value {
			if _, isMerge := item.Key.(MergeKey); isMerge {
				return true
			}
			if hasAnchorsInValue(item.Value) {
				return true
			}
		}
	case []interface{}:
		for _, item := range value {
			if hasAnchorsInValue(item) {
				return true
			}
		}
	}
	return false
}

// ValidateAnchors checks that every alias refers to an anchor defined before it
// in the same document, which is what a YAML parser requires. Editors and
// mutation commands can otherwise produce a document that would no longer be
// valid YAML once written out.
func ValidateAnchors(branches TreeBranches) error {
	for _, branch := range branches {
		if err := validateAnchorsInValue(branch, make(map[string]bool)); err != nil {
			return err
		}
	}
	return nil
}

func validateAnchorsInValue(value interface{}, defined map[string]bool) error {
	switch value := value.(type) {
	case Anchor:
		// The anchor is defined before its content is traversed, so a value
		// may refer to its own anchor (a recursive structure), as YAML allows.
		defined[value.Name] = true
		return validateAnchorsInValue(value.Value, defined)
	case Alias:
		if !defined[value.Name] {
			return fmt.Errorf("YAML alias %q refers to an anchor that is not defined before it", value.Name)
		}
		return nil
	case TreeBranch:
		for _, item := range value {
			if err := validateAnchorsInValue(item.Value, defined); err != nil {
				return err
			}
		}
		return nil
	case []interface{}:
		for _, item := range value {
			if err := validateAnchorsInValue(item, defined); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

// AnchorEncryptionMismatch describes an alias whose encryption policy differs
// from the policy at the anchor it refers to.
type AnchorEncryptionMismatch struct {
	AnchorName      string
	AnchorPath      string
	AliasPath       string
	AnchorEncrypted bool
	AliasEncrypted  bool
}

func (m AnchorEncryptionMismatch) String() string {
	describe := func(encrypted bool) string {
		if encrypted {
			return "encrypted"
		}
		return "left in cleartext"
	}
	return fmt.Sprintf(
		"anchor %q is %s at %q, but its alias at %q is %s; "+
			"the alias is a reference, so the anchor's location decides whether the value is encrypted",
		m.AnchorName, describe(m.AnchorEncrypted), m.AnchorPath,
		describe(m.AliasEncrypted), m.AliasPath)
}

// FindAnchorEncryptionMismatches reports aliases whose own path would be
// treated differently from the path of the anchor they reference. Because an
// alias is a reference, the anchor's location decides the ciphertext, so such a
// document can expose cleartext where the policy asked for encryption (or show
// ciphertext where it asked for cleartext). This is a property of the document,
// not an error, so callers warn about it rather than refusing to proceed.
func FindAnchorEncryptionMismatches(tree Tree) []AnchorEncryptionMismatch {
	type anchorPolicy struct {
		path      string
		encrypted bool
	}
	anchors := map[string]anchorPolicy{}
	var mismatches []AnchorEncryptionMismatch

	var walk func(value interface{}, path []string)
	// shouldBeEncrypted always sees at least one comment scope during a real
	// walk, so provide an empty one here to keep its indexing valid.
	emptyComments := [][]string{{}}
	walk = func(value interface{}, path []string) {
		switch value := value.(type) {
		case Anchor:
			anchors[value.Name] = anchorPolicy{
				path:      strings.Join(path, ":"),
				encrypted: tree.shouldBeEncrypted(path, emptyComments, false),
			}
			walk(value.Value, path)
		case Alias:
			policy, ok := anchors[value.Name]
			if !ok {
				// Not yet defined; ValidateAnchors reports that separately.
				return
			}
			aliasEncrypted := tree.shouldBeEncrypted(path, emptyComments, false)
			if aliasEncrypted != policy.encrypted {
				mismatches = append(mismatches, AnchorEncryptionMismatch{
					AnchorName:      value.Name,
					AnchorPath:      policy.path,
					AliasPath:       strings.Join(path, ":"),
					AnchorEncrypted: policy.encrypted,
					AliasEncrypted:  aliasEncrypted,
				})
			}
		case TreeBranch:
			for _, item := range value {
				key := MergeKeyName
				if stringKey, ok := item.Key.(string); ok {
					key = stringKey
				}
				nested := make([]string, len(path), len(path)+1)
				copy(nested, path)
				walk(item.Value, append(nested, key))
			}
		case []interface{}:
			for _, item := range value {
				walk(item, path)
			}
		}
	}
	for _, branch := range tree.Branches {
		walk(branch, nil)
	}
	return mismatches
}

// ResolveValue returns a copy of a single value in which anchors, aliases and
// merge keys it defines have been replaced by their contents. It is used when
// emitting a value in a format that cannot express them.
func ResolveValue(value interface{}) (interface{}, error) {
	r := &resolver{scope: anchorScope{}}
	return r.resolve(value)
}

// ResolveValueIn returns a copy of a single value in which aliases and merge
// keys are resolved against the anchors defined anywhere in root. This is what
// extracting a subtree needs: the subtree alone may contain an alias whose
// anchor lives next to it in the source document.
func ResolveValueIn(root TreeBranch, value interface{}) (interface{}, error) {
	r := &resolver{scope: anchorScopeFor(root)}
	return r.resolve(value)
}

// ResolveAliases returns a copy of the branches in which every anchor, alias
// and merge key has been replaced by its value, as a document using those
// features would be understood by a YAML parser. Formats without anchor
// support must resolve the tree before emitting it.
func ResolveAliases(branches TreeBranches) (TreeBranches, error) {
	resolved := make(TreeBranches, len(branches))
	for i, branch := range branches {
		r := &resolver{scope: anchorScope{}, stack: nil}
		value, err := r.resolve(branch)
		if err != nil {
			return nil, err
		}
		branch, ok := value.(TreeBranch)
		if !ok {
			return nil, fmt.Errorf("Internal error: resolving a branch produced %T", value)
		}
		resolved[i] = branch
	}
	return resolved, nil
}

// resolver expands anchors, aliases and merge keys. The stack holds the names
// of the anchors currently being resolved so that self-referencing anchors are
// reported instead of recursing forever.
type resolver struct {
	scope anchorScope
	stack []string
}

func (r *resolver) resolve(value interface{}) (interface{}, error) {
	switch value := value.(type) {
	case Anchor:
		// Defining the anchor before resolving its content lets recursive
		// structures be named consistently. Per YAML semantics an alias refers
		// to the most recent definition, so the scope keeps the new value.
		r.scope[value.Name] = value.Value
		return r.resolve(value.Value)
	case Alias:
		for _, name := range r.stack {
			if name == value.Name {
				return nil, fmt.Errorf("YAML anchor %q refers to itself", value.Name)
			}
		}
		target, ok := r.scope[value.Name]
		if !ok {
			return nil, fmt.Errorf("YAML alias %q refers to an unknown anchor", value.Name)
		}
		previousStack := r.stack
		r.stack = append(append([]string{}, r.stack...), value.Name)
		resolved, err := r.resolve(target)
		r.stack = previousStack
		return resolved, err
	case TreeBranch:
		return r.resolveBranch(value)
	case []interface{}:
		result := make([]interface{}, 0, len(value))
		for _, item := range value {
			resolved, err := r.resolve(item)
			if err != nil {
				return nil, err
			}
			result = append(result, resolved)
		}
		return result, nil
	default:
		return value, nil
	}
}

func (r *resolver) resolveBranch(branch TreeBranch) (TreeBranch, error) {
	// Explicit keys always win over merged ones. Values are resolved in
	// document order so that anchors are registered before anything that may
	// refer to them, whichever entry they appear under.
	explicit := make(map[string]bool)
	result := make(TreeBranch, 0, len(branch))
	var mergedBranches []TreeBranch
	for _, item := range branch {
		if _, isMerge := item.Key.(MergeKey); isMerge {
			merged, err := r.resolveMergeValue(item.Value)
			if err != nil {
				return nil, err
			}
			mergedBranches = append(mergedBranches, merged)
			continue
		}
		value, err := r.resolve(item.Value)
		if err != nil {
			return nil, err
		}
		if key, ok := item.Key.(string); ok {
			explicit[key] = true
		}
		result = append(result, TreeItem{Key: item.Key, Value: value})
	}
	for _, merged := range mergedBranches {
		for _, mergedItem := range merged {
			key, ok := mergedItem.Key.(string)
			if !ok {
				// Comments and other structural entries are not merged.
				continue
			}
			if explicit[key] {
				continue
			}
			explicit[key] = true
			result = append(result, mergedItem)
		}
	}
	return result, nil
}

func (r *resolver) resolveMergeValue(value interface{}) (TreeBranch, error) {
	switch value := value.(type) {
	case Alias, Anchor:
		resolved, err := r.resolve(value)
		if err != nil {
			return nil, err
		}
		branch, ok := resolved.(TreeBranch)
		if !ok {
			return nil, fmt.Errorf("YAML merge key requires a mapping, got %T", resolved)
		}
		return branch, nil
	case TreeBranch:
		return r.resolveBranch(value)
	case []interface{}:
		// Per the YAML merge key specification, mappings earlier in the
		// sequence take precedence over later ones.
		var merged TreeBranch
		seen := make(map[string]bool)
		for _, item := range value {
			resolved, err := r.resolve(item)
			if err != nil {
				return nil, err
			}
			branch, ok := resolved.(TreeBranch)
			if !ok {
				return nil, fmt.Errorf("YAML merge key requires mappings, got %T", resolved)
			}
			for _, branchItem := range branch {
				key, ok := branchItem.Key.(string)
				if !ok {
					continue
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				merged = append(merged, branchItem)
			}
		}
		return merged, nil
	default:
		return nil, fmt.Errorf("YAML merge key requires a mapping or a sequence of mappings, got %T", value)
	}
}
