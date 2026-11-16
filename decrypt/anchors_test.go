package decrypt

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/pgp"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
)

// The public API must return plaintext that still contains the anchors,
// aliases and merge keys of the original document, so that callers parsing it
// as YAML see the same reference structure they wrote.
func TestDataWithFormatKeepsAnchors(t *testing.T) {
	const document = `defaults: &defaults
    timeout: 10
    retries: 3
prod:
    <<: *defaults
    timeout: 20
dev: *defaults
`
	store := &yamlstore.Store{}
	branches, err := store.LoadPlainFile([]byte(document))
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

	// Decrypting through the same steps as DataWithFormat, since the age/pgp
	// master key here is a placeholder that cannot really decrypt the key.
	loaded, err := store.LoadEncryptedFile(encrypted)
	assert.NoError(t, err)
	loaded.Metadata.DataKey = key
	computedMac, err := loaded.Decrypt(key, aes.NewCipher())
	assert.NoError(t, err)
	recoveredMac, err := aes.NewCipher().Decrypt(
		loaded.Metadata.MessageAuthenticationCode, key,
		loaded.Metadata.LastModified.Format(time.RFC3339))
	assert.NoError(t, err)
	assert.Equal(t, recoveredMac, computedMac)

	cleartext, err := store.EmitPlainFile(loaded.Branches)
	assert.NoError(t, err)
	assert.Equal(t, document, string(cleartext))
}
