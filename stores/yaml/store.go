package yaml //import "github.com/getsops/sops/v3/stores/yaml"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/stores"
	"go.yaml.in/yaml/v3"
)

const IndentDefault = 4

// Store handles storage of YAML data
type Store struct {
	config config.YAMLStoreConfig
}

func NewStore(c *config.YAMLStoreConfig) *Store {
	return &Store{config: *c}
}

func (store *Store) Name() string {
	return "yaml"
}

// SupportsAnchors reports that YAML can represent anchors, aliases and merge
// keys, so trees loaded from YAML keep them as references. The CLI uses this to
// decide whether a tree has to be resolved before being written to another
// format.
func (store *Store) SupportsAnchors() bool {
	return true
}

func (store Store) appendCommentToList(comment string, list []interface{}) []interface{} {
	return store.appendCommentToListWithInline(comment, list, false)
}

func (store Store) appendInlineCommentToList(comment string, list []interface{}) []interface{} {
	return store.appendCommentToListWithInline(comment, list, true)
}

func (store Store) appendCommentToListWithInline(comment string, list []interface{}, inline bool) []interface{} {
	if comment != "" {
		for _, commentLine := range strings.Split(comment, "\n") {
			if commentLine != "" {
				list = append(list, sops.Comment{
					Value:  commentLine[1:],
					Inline: inline,
				})
			}
		}
	}
	return list
}

func (store Store) appendCommentToMap(comment string, branch sops.TreeBranch) sops.TreeBranch {
	return store.appendCommentToMapWithInline(comment, branch, false)
}

func (store Store) appendInlineCommentToMap(comment string, branch sops.TreeBranch) sops.TreeBranch {
	return store.appendCommentToMapWithInline(comment, branch, true)
}

func (store Store) appendCommentToMapWithInline(comment string, branch sops.TreeBranch, inline bool) sops.TreeBranch {
	if comment != "" {
		for _, commentLine := range strings.Split(comment, "\n") {
			if commentLine != "" {
				branch = append(branch, sops.TreeItem{
					Key: sops.Comment{
						Value:  commentLine[1:],
						Inline: inline,
					},
					Value: nil,
				})
			}
		}
	}
	return branch
}

// isMergeKeyNode reports whether the node is the unquoted "<<" merge key.
// The YAML parser tags an unquoted "<<" with "!!merge", while a quoted "<<" is
// a regular string key, which is why the tag (and not just the value) matters.
func isMergeKeyNode(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.ShortTag() == "!!merge"
}

func (store Store) nodeToTreeValue(node *yaml.Node, commentsWereHandled bool) (interface{}, error) {
	// An alias is a reference to an anchor defined earlier in the document and
	// must be preserved as such; expanding it here would turn the reference into
	// an independent copy that no longer follows later changes to the anchor.
	if node.Kind == yaml.AliasNode {
		return sops.Alias{Name: node.Value}, nil
	}
	value, err := store.nodeContentToTreeValue(node, commentsWereHandled)
	if err != nil {
		return nil, err
	}
	if node.Anchor != "" {
		return sops.Anchor{Name: node.Anchor, Value: value}, nil
	}
	return value, nil
}

func (store Store) nodeContentToTreeValue(node *yaml.Node, commentsWereHandled bool) (interface{}, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		panic("documents should never be passed here")
	case yaml.SequenceNode:
		var result []interface{}
		if !commentsWereHandled {
			result = store.appendCommentToList(node.HeadComment, result)
			result = store.appendCommentToList(node.LineComment, result)
		}
		for _, item := range node.Content {
			result = store.appendCommentToList(item.HeadComment, result)
			result = store.appendInlineCommentToList(item.LineComment, result)
			val, err := store.nodeToTreeValue(item, true)
			if err != nil {
				return nil, err
			}
			result = append(result, val)
			result = store.appendCommentToList(item.FootComment, result)
		}
		if !commentsWereHandled {
			result = store.appendCommentToList(node.FootComment, result)
		}
		return result, nil
	case yaml.MappingNode:
		branch := make(sops.TreeBranch, 0)
		return store.appendYamlNodeToTreeBranch(node, branch, commentsWereHandled)
	case yaml.ScalarNode:
		var result interface{}
		node.Decode(&result)
		return result, nil
	}
	return nil, nil
}

func (store Store) appendYamlNodeToTreeBranch(node *yaml.Node, branch sops.TreeBranch, commentsWereHandled bool) (sops.TreeBranch, error) {
	var err error
	if !commentsWereHandled {
		branch = store.appendCommentToMap(node.HeadComment, branch)
		branch = store.appendCommentToMap(node.LineComment, branch)
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, item := range node.Content {
			branch, err = store.appendYamlNodeToTreeBranch(item, branch, false)
			if err != nil {
				return nil, err
			}
		}
	case yaml.SequenceNode:
		return nil, fmt.Errorf("YAML documents that are sequences are not supported")
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			branch = store.appendCommentToMap(key.HeadComment, branch)
			branch = store.appendCommentToMap(key.LineComment, branch)
			handleValueComments := value.Kind == yaml.ScalarNode || value.Kind == yaml.AliasNode
			if handleValueComments {
				branch = store.appendCommentToMap(value.HeadComment, branch)
				branch = store.appendInlineCommentToMap(value.LineComment, branch)
			}
			var keyValue interface{}
			if isMergeKeyNode(key) {
				// Keep "<<" distinct from a literal string key so that emitting
				// does not quote it and merge semantics are preserved.
				keyValue = sops.MergeKey{}
			} else {
				key.Decode(&keyValue)
			}
			valueTV, err := store.nodeToTreeValue(value, handleValueComments)
			if err != nil {
				return nil, err
			}
			branch = append(branch, sops.TreeItem{
				Key:   keyValue,
				Value: valueTV,
			})
			if handleValueComments {
				branch = store.appendCommentToMap(value.FootComment, branch)
			}
			branch = store.appendCommentToMap(key.FootComment, branch)
		}
	case yaml.ScalarNode:
		// A empty document with a document start marker without comments results in null
		if node.ShortTag() == "!!null" {
			return branch, nil
		}
		return nil, fmt.Errorf("YAML documents that are values are not supported")
	case yaml.AliasNode:
		// Aliases are handled by nodeToTreeValue before this function is
		// reached, so a document whose root is an alias cannot occur.
		return nil, fmt.Errorf("YAML documents that are aliases are not supported")
	}
	if !commentsWereHandled {
		branch = store.appendCommentToMap(node.FootComment, branch)
	}
	return branch, nil
}

func (store Store) yamlDocumentNodeToTreeBranch(in yaml.Node) (sops.TreeBranch, error) {
	branch := make(sops.TreeBranch, 0)
	return store.appendYamlNodeToTreeBranch(&in, branch, false)
}

func (store *Store) addCommentsHead(node *yaml.Node, comments []string) []string {
	if len(comments) > 0 {
		comment := "#" + strings.Join(comments, "\n#")
		if len(node.HeadComment) > 0 {
			node.HeadComment = comment + "\n" + node.HeadComment
		} else {
			node.HeadComment = comment
		}
	}
	return nil
}

func (store *Store) addCommentsFoot(node *yaml.Node, comments []string) []string {
	if len(comments) > 0 {
		comment := "#" + strings.Join(comments, "\n#")
		if len(node.FootComment) > 0 {
			node.FootComment += "\n" + comment
		} else {
			node.FootComment = comment
		}
	}
	return nil
}

func (store *Store) addCommentsLine(node *yaml.Node, comments []string) []string {
	if len(comments) > 0 {
		comment := "#" + strings.Join(comments, "\n#")
		if len(node.LineComment) > 0 {
			node.LineComment += "\n" + comment
		} else {
			node.LineComment = comment
		}
	}
	return nil
}

func (store *Store) treeValueToNode(in interface{}) *yaml.Node {
	switch in := in.(type) {
	case sops.TreeBranch:
		var mapping = &yaml.Node{}
		mapping.Kind = yaml.MappingNode
		store.appendTreeBranch(in, mapping)
		return mapping
	case []interface{}:
		var sequence = &yaml.Node{}
		sequence.Kind = yaml.SequenceNode
		store.appendSequence(in, sequence)
		return sequence
	case sops.Anchor:
		valueNode := store.treeValueToNode(in.Value)
		valueNode.Anchor = in.Name
		return valueNode
	case sops.Alias:
		var aliasNode = &yaml.Node{}
		aliasNode.Kind = yaml.AliasNode
		aliasNode.Value = in.Name
		return aliasNode
	default:
		var valueNode = &yaml.Node{}
		valueNode.Encode(in)
		return valueNode
	}
}

// keyToNode renders a mapping key. A merge key must be written as a plain
// (unquoted) "<<", whereas a literal string key with the same text has to be
// quoted so YAML does not interpret it as a merge key.
func (store *Store) keyToNode(in interface{}) *yaml.Node {
	var keyNode = &yaml.Node{}
	if _, ok := in.(sops.MergeKey); ok {
		keyNode.Kind = yaml.ScalarNode
		keyNode.Value = "<<"
		return keyNode
	}
	keyNode.Encode(in)
	if s, ok := in.(string); ok && s == "<<" {
		// Encode tags the value as "!!merge"; clear the tag and quote the
		// scalar so the parser reads it back as a literal string key.
		keyNode.Tag = ""
		keyNode.Style = yaml.DoubleQuotedStyle
	}
	return keyNode
}

func (store *Store) appendSequence(in []interface{}, sequence *yaml.Node) {
	var headComments []string
	var inlineComments []string
	var beginning bool = true
	for _, item := range in {
		if comment, ok := item.(sops.Comment); ok {
			if comment.Inline {
				inlineComments = append(inlineComments, comment.Value)
			} else {
				headComments = append(headComments, comment.Value)
			}
		} else {
			if beginning {
				headComments = store.addCommentsHead(sequence, headComments)
				beginning = false
			}
			itemNode := store.treeValueToNode(item)
			headComments = store.addCommentsHead(itemNode, headComments)
			inlineComments = store.addCommentsLine(itemNode, inlineComments)
			sequence.Content = append(sequence.Content, itemNode)
		}
	}
	headComments = append(headComments, inlineComments...)
	if len(headComments) > 0 {
		if beginning {
			store.addCommentsHead(sequence, headComments)
		} else {
			store.addCommentsFoot(sequence.Content[len(sequence.Content)-1], headComments)
		}
	}
}

// validateMergeKeys checks that every merge key holds something YAML accepts:
// a mapping, a reference to one, or a sequence of those. An arbitrary value
// would be written out as invalid YAML that cannot be parsed again, so it is
// rejected before anything is emitted.
func validateMergeKeys(value interface{}) error {
	switch value := value.(type) {
	case sops.Anchor:
		return validateMergeKeys(value.Value)
	case sops.TreeBranch:
		for _, item := range value {
			if _, isMerge := item.Key.(sops.MergeKey); isMerge {
				if err := validateMergeKeyValue(item.Value); err != nil {
					return err
				}
			}
			if err := validateMergeKeys(item.Value); err != nil {
				return err
			}
		}
		return nil
	case []interface{}:
		for _, item := range value {
			if err := validateMergeKeys(item); err != nil {
				return err
			}
		}
		return nil
	default:
		return nil
	}
}

func validateMergeKeyValue(value interface{}) error {
	switch value := value.(type) {
	case sops.Alias:
		return nil
	case sops.Anchor:
		return validateMergeKeyValue(value.Value)
	case sops.TreeBranch:
		return nil
	case []interface{}:
		for _, item := range value {
			switch item.(type) {
			case sops.Alias, sops.Anchor, sops.TreeBranch:
			default:
				return fmt.Errorf("a merge key (<<) requires a mapping or a sequence of mappings, got %T in the sequence", item)
			}
		}
		return nil
	default:
		return fmt.Errorf("a merge key (<<) requires a mapping or a sequence of mappings, got %T", value)
	}
}

func (store *Store) appendTreeBranch(branch sops.TreeBranch, mapping *yaml.Node) {
	var headComments []string
	var inlineComments []string
	var beginning bool = true
	for _, item := range branch {
		if comment, ok := item.Key.(sops.Comment); ok {
			if comment.Inline {
				inlineComments = append(inlineComments, comment.Value)
			} else {
				headComments = append(headComments, comment.Value)
			}
		} else {
			if beginning {
				headComments = store.addCommentsHead(mapping, headComments)
				beginning = false
			}
			var keyNode = store.keyToNode(item.Key)
			headComments = store.addCommentsHead(keyNode, headComments)
			valueNode := store.treeValueToNode(item.Value)
			inlineComments = store.addCommentsLine(valueNode, inlineComments)
			mapping.Content = append(mapping.Content, keyNode, valueNode)
		}
	}
	headComments = append(headComments, inlineComments...)
	if len(headComments) > 0 {
		if beginning {
			store.addCommentsHead(mapping, headComments)
		} else {
			store.addCommentsFoot(mapping.Content[len(mapping.Content)-2], headComments)
		}
	}
}

// LoadEncryptedFile loads the contents of an encrypted yaml file onto a
// sops.Tree runtime object
func (store *Store) LoadEncryptedFile(in []byte) (sops.Tree, error) {
	branches, err := store.LoadPlainFile(in)
	if err != nil {
		return sops.Tree{}, err
	}
	branches, metadata, err := stores.ExtractMetadata(branches, stores.MetadataOpts{
		Flatten: stores.MetadataFlattenNone,
	})
	if err != nil {
		return sops.Tree{}, err
	}
	return sops.Tree{
		Branches: branches,
		Metadata: metadata,
	}, nil
}

// LoadPlainFile loads the contents of a plaintext yaml file onto a
// sops.Tree runtime object
func (store *Store) LoadPlainFile(in []byte) (sops.TreeBranches, error) {
	var branches sops.TreeBranches
	if len(in) > 0 {
		// This is needed to make the yaml-decoder check for uniqueness of keys
		// Can probably be removed when https://github.com/go-yaml/yaml/issues/814 is merged.
		if err := yaml.NewDecoder(bytes.NewReader(in)).Decode(make(map[string]interface{})); err != nil {
			return nil, err
		}
	}
	d := yaml.NewDecoder(bytes.NewReader(in))
	for {
		var data yaml.Node
		err := d.Decode(&data)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Error unmarshaling input YAML: %s", err)
		}

		branch, err := store.yamlDocumentNodeToTreeBranch(data)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshaling input YAML: %s", err)
		}
		branches = append(branches, branch)
	}
	return branches, nil
}

func (store *Store) getIndentation() (int, error) {
	if store.config.Indent > 0 {
		return store.config.Indent, nil
	} else if store.config.Indent < 0 {
		return 0, errors.New("YAML Negative indentation not accepted")
	}
	return IndentDefault, nil
}

// EmitEncryptedFile returns the encrypted bytes of the yaml file corresponding to a
// sops.Tree runtime object
func (store *Store) EmitEncryptedFile(in sops.Tree) ([]byte, error) {
	branches, err := stores.SerializeMetadata(in, stores.MetadataOpts{
		Flatten: stores.MetadataFlattenNone,
	})
	if err != nil {
		return nil, fmt.Errorf("Error marshaling metadata: %s", err)
	}
	return store.EmitPlainFile(branches)
}

// EmitPlainFile returns the plaintext bytes of the yaml file corresponding to a
// sops.TreeBranches runtime object
func (store *Store) EmitPlainFile(branches sops.TreeBranches) ([]byte, error) {
	// An alias with no anchor defined before it produces a document that
	// cannot be parsed again, so refuse to write one. Likewise a merge key
	// holding anything but a mapping would be invalid YAML.
	if err := sops.ValidateAnchors(branches); err != nil {
		return nil, err
	}
	for _, branch := range branches {
		if err := validateMergeKeys(branch); err != nil {
			return nil, err
		}
	}
	var b bytes.Buffer
	e := yaml.NewEncoder(io.Writer(&b))
	indent, err := store.getIndentation()
	if err != nil {
		return nil, err
	}
	e.SetIndent(indent)
	for _, branch := range branches {
		// Document root
		var doc = yaml.Node{}
		doc.Kind = yaml.DocumentNode
		// Add global mapping
		var mapping = yaml.Node{}
		mapping.Kind = yaml.MappingNode
		// Marshal branch to global mapping node
		store.appendTreeBranch(branch, &mapping)
		doc.Content = append(doc.Content, &mapping)
		// Encode YAML
		err := e.Encode(&doc)
		if err != nil {
			return nil, fmt.Errorf("Error marshaling to YAML: %s", err)
		}
	}
	e.Close()
	return b.Bytes(), nil
}

// EmitValue returns bytes corresponding to a single encoded value
// in a generic interface{} object
func (store *Store) EmitValue(v interface{}) ([]byte, error) {
	// An extracted value is written as a standalone document, which cannot hold
	// an alias pointing at an anchor defined elsewhere in the source document.
	// Resolving it here yields the same plaintext the pre-anchor-aware code
	// produced, because aliases used to be expanded while loading.
	value, err := sops.ResolveValue(v)
	if err != nil {
		return nil, fmt.Errorf("Error resolving aliases: %s", err)
	}
	n := store.treeValueToNode(value)
	return yaml.Marshal(n)
}

// EmitExample returns the bytes corresponding to an example complex tree
func (store *Store) EmitExample() []byte {
	bytes, err := store.EmitPlainFile(stores.ExampleComplexTree.Branches)
	if err != nil {
		panic(err)
	}
	return bytes
}

// HasSopsTopLevelKey checks whether a top-level "sops" key exists.
func (store *Store) HasSopsTopLevelKey(branch sops.TreeBranch) bool {
	return stores.HasSopsTopLevelKey(branch)
}
