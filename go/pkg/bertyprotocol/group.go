package bertyprotocol

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/ioutil"

	"berty.tech/go-orbit-db/events"
	"github.com/libp2p/go-libp2p-core/crypto"
	"go.uber.org/zap"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"

	"berty.tech/berty/go/internal/cryptoutil"
	"berty.tech/berty/go/pkg/errcode"
)

const CurrentGroupVersion = 1

func (m *Group) GetSigningPrivKey() (crypto.PrivKey, error) {
	edSK := ed25519.NewKeyFromSeed(m.Secret)

	sk, _, err := crypto.KeyPairFromStdKey(&edSK)
	if err != nil {
		return nil, err
	}

	return sk, nil
}

func (m *Group) GetPubKey() (crypto.PubKey, error) {
	return crypto.UnmarshalEd25519PublicKey(m.PublicKey)
}

func (m *Group) GetSigningPubKey() (crypto.PubKey, error) {
	sk, err := m.GetSigningPrivKey()
	if err != nil {
		return nil, err
	}

	return sk.GetPublic(), nil
}

func (m *Group) IsValid() error {
	pk, err := m.GetPubKey()
	if err != nil {
		return errcode.ErrDeserialization.Wrap(err)
	}

	ok, err := pk.Verify(m.Secret, m.SecretSig)
	if err != nil {
		return errcode.ErrSignatureVerificationFailed.Wrap(err)
	}

	if !ok {
		return errcode.ErrSignatureVerificationFailed
	}

	return nil
}

// GroupIDAsString returns the group pub key as a string
func (m *Group) GroupIDAsString() string {
	return hex.EncodeToString(m.PublicKey)
}

func (m *Group) GetSharedSecret() (*[32]byte, error) {
	sharedSecret := [32]byte{}
	copy(sharedSecret[:], m.Secret[:])

	return &sharedSecret, nil
}

// New creates a new Group object and an invitation to be used by
// the first member of the group
func NewGroupMultiMember() (*Group, crypto.PrivKey, error) {
	priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, nil, errcode.ErrSecretKeyGenerationFailed.Wrap(err)
	}

	pubBytes, err := pub.Raw()
	if err != nil {
		return nil, nil, errcode.ErrSerialization.Wrap(err)
	}

	signing, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, nil, errcode.ErrSecretKeyGenerationFailed.Wrap(err)
	}

	signingBytes, err := cryptoutil.SeedFromEd25519PrivateKey(signing)
	if err != nil {
		return nil, nil, errcode.ErrSerialization.Wrap(err)
	}

	skSig, err := priv.Sign(signingBytes)
	if err != nil {
		return nil, nil, errcode.ErrSignatureFailed.Wrap(err)
	}

	group := &Group{
		PublicKey: pubBytes,
		Secret:    signingBytes,
		SecretSig: skSig,
		GroupType: GroupTypeMultiMember,
	}

	return group, priv, nil
}

func getKeysForGroupOfContact(contactPairSK crypto.PrivKey) (crypto.PrivKey, crypto.PrivKey, error) {
	// Salt length must be equal to hash length (64 bytes for sha256)
	hash := sha256.New

	ck, err := contactPairSK.Raw()
	if err != nil {
		return nil, nil, errcode.ErrSerialization.Wrap(err)
	}

	// Generate Pseudo Random Key using ck as IKM and salt
	prk := hkdf.Extract(hash, ck[:], nil)
	if len(prk) == 0 {
		return nil, nil, errcode.ErrInternal
	}

	// Expand using extracted prk and groupID as info (kind of namespace)
	kdf := hkdf.Expand(hash, prk, nil)

	// Generate next KDF and message keys
	groupSeed, err := ioutil.ReadAll(io.LimitReader(kdf, 32))
	if err != nil {
		return nil, nil, errcode.ErrSecretKeyGenerationFailed.Wrap(err)
	}

	groupSecretSeed, err := ioutil.ReadAll(io.LimitReader(kdf, 32))
	if err != nil {
		return nil, nil, errcode.ErrSecretKeyGenerationFailed.Wrap(err)
	}

	sk1 := ed25519.NewKeyFromSeed(groupSeed)
	groupSK, _, err := crypto.KeyPairFromStdKey(&sk1)
	if err != nil {
		return nil, nil, errcode.ErrSecretKeyGenerationFailed.Wrap(err)
	}

	sk2 := ed25519.NewKeyFromSeed(groupSecretSeed)
	groupSecretSK, _, err := crypto.KeyPairFromStdKey(&sk2)
	if err != nil {
		return nil, nil, errcode.ErrSecretKeyGenerationFailed.Wrap(err)
	}

	return groupSK, groupSecretSK, nil
}

func GetGroupForContact(contactPairSK crypto.PrivKey) (*Group, error) {
	groupSK, groupSecretSK, err := getKeysForGroupOfContact(contactPairSK)
	if err != nil {
		return nil, errcode.ErrSecretKeyGenerationFailed.Wrap(err)
	}
	pubBytes, err := groupSK.GetPublic().Raw()
	if err != nil {
		return nil, errcode.ErrSerialization.Wrap(err)
	}

	signingBytes, err := cryptoutil.SeedFromEd25519PrivateKey(groupSecretSK)
	if err != nil {
		return nil, errcode.ErrSerialization.Wrap(err)
	}

	return &Group{
		PublicKey: pubBytes,
		Secret:    signingBytes,
		SecretSig: nil,
		GroupType: GroupTypeContact,
	}, nil
}

func GetGroupForAccount(priv, signing crypto.PrivKey) (*Group, error) {
	pubBytes, err := priv.GetPublic().Raw()
	if err != nil {
		return nil, errcode.ErrSerialization.Wrap(err)
	}

	signingBytes, err := cryptoutil.SeedFromEd25519PrivateKey(signing)
	if err != nil {
		return nil, errcode.ErrSerialization.Wrap(err)
	}

	return &Group{
		PublicKey: pubBytes,
		Secret:    signingBytes,
		SecretSig: nil,
		GroupType: GroupTypeAccount,
	}, nil
}

func MetadataStoreListSecrets(ctx context.Context, gc ContextGroup) (map[crypto.PubKey]*DeviceSecret, error) {
	publishedSecrets := map[crypto.PubKey]*DeviceSecret{}

	m := gc.MetadataStore()
	ownSK := gc.GetMemberPrivKey()
	g := gc.Group()

	ch := m.ListEvents(ctx)

	for meta := range ch {
		pk, ds, err := OpenDeviceSecret(meta.Metadata, ownSK, g)
		if err != nil {
			// TODO: log
			continue
		}

		publishedSecrets[pk] = ds
	}

	return publishedSecrets, nil
}

func FillMessageKeysHolderUsingNewData(ctx context.Context, gc ContextGroup) error {
	m := gc.MetadataStore()

	for evt := range m.Subscribe(ctx) {
		e, ok := evt.(*GroupMetadataEvent)
		if !ok {
			continue
		}

		pk, ds, err := OpenDeviceSecret(e.Metadata, gc.GetMemberPrivKey(), gc.Group())
		if err != nil {
			continue
		}

		if err = RegisterChainKey(ctx, gc.GetMessageKeys(), gc.Group(), pk, ds, gc.DevicePubKey().Equals(pk)); err != nil {
			// TODO: log
			continue

		}
	}

	return nil
}

func FillMessageKeysHolderUsingPreviousData(ctx context.Context, gc ContextGroup) error {
	publishedSecrets, err := MetadataStoreListSecrets(ctx, gc)

	if err != nil {
		return errcode.TODO.Wrap(err)
	}

	for pk, sec := range publishedSecrets {
		if err := RegisterChainKey(ctx, gc.GetMessageKeys(), gc.Group(), pk, sec, gc.DevicePubKey().Equals(pk)); err != nil {
			return errcode.TODO.Wrap(err)
		}
	}

	return nil
}

func ActivateGroupContext(ctx context.Context, gc ContextGroup) error {
	if _, err := gc.MetadataStore().AddDeviceToGroup(ctx); err != nil {
		return errcode.ErrInternal.Wrap(err)
	}

	if err := FillMessageKeysHolderUsingPreviousData(ctx, gc); err != nil {
		return errcode.ErrInternal.Wrap(err)
	}

	if err := SendSecretsToExistingMembers(ctx, gc); err != nil {
		return errcode.ErrInternal.Wrap(err)
	}
	//
	go func() {
		_ = FillMessageKeysHolderUsingNewData(ctx, gc)
	}()

	go WatchNewMembersAndSendSecrets(ctx, zap.NewNop(), gc)

	return nil
}

func handleNewMember(ctx context.Context, gctx ContextGroup, evt events.Event) error {
	e, ok := evt.(*GroupMetadataEvent)
	if !ok {
		return nil
	}

	if e.Metadata.EventType != EventTypeGroupMemberDeviceAdded {
		return nil
	}

	event := &GroupAddMemberDevice{}
	if err := event.Unmarshal(e.Metadata.Payload); err != nil {
		return errcode.ErrDeserialization.Wrap(err)
	}

	memberPK, err := crypto.UnmarshalEd25519PublicKey(event.MemberPK)
	if err != nil {
		return errcode.ErrDeserialization.Wrap(err)
	}

	if memberPK.Equals(gctx.MemberPubKey()) {
		return nil
	}

	if _, err := gctx.MetadataStore().SendSecret(ctx, memberPK); err != nil {
		if err != errcode.ErrGroupSecretAlreadySentToMember {
			return errcode.ErrInternal.Wrap(err)
		}

		return nil
	}

	return nil
}

func SendSecretsToExistingMembers(ctx context.Context, gctx ContextGroup) error {
	members := gctx.MetadataStore().ListMembers()

	for _, pk := range members {
		if _, err := gctx.MetadataStore().SendSecret(ctx, pk); err != nil {
			if err != errcode.ErrGroupSecretAlreadySentToMember {
				return errcode.ErrInternal.Wrap(err)
			}
		}
	}

	return nil
}

func WatchNewMembersAndSendSecrets(ctx context.Context, logger *zap.Logger, gctx ContextGroup) {
	go func() {
		for evt := range gctx.MetadataStore().Subscribe(ctx) {
			if err := handleNewMember(ctx, gctx, evt); err != nil {
				// TODO: log
				logger.Error("unable to send secrets", zap.Error(err))
			}
		}
	}()
}

func OpenDeviceSecret(m *GroupMetadata, localMemberPrivateKey crypto.PrivKey, group *Group) (crypto.PubKey, *DeviceSecret, error) {
	if m == nil || m.EventType != EventTypeGroupDeviceSecretAdded {
		return nil, nil, errcode.ErrInvalidInput
	}

	s := &GroupAddDeviceSecret{}
	if err := s.Unmarshal(m.Payload); err != nil {
		return nil, nil, errcode.ErrDeserialization.Wrap(err)
	}

	nonce, err := GroupIDToNonce(group)
	if err != nil {
		return nil, nil, errcode.ErrSerialization.Wrap(err)
	}

	senderDevicePubKey, err := crypto.UnmarshalEd25519PublicKey(s.DevicePK)
	if err != nil {
		return nil, nil, errcode.ErrDeserialization.Wrap(err)
	}

	mongPriv, mongPub, err := cryptoutil.EdwardsToMontgomery(localMemberPrivateKey, senderDevicePubKey)
	if err != nil {
		return nil, nil, errcode.ErrCryptoKeyConversion.Wrap(err)
	}

	decryptedSecret := &DeviceSecret{}
	decryptedMessage, ok := box.Open(nil, s.Payload, nonce, mongPub, mongPriv)
	if !ok {
		return nil, nil, errcode.ErrCryptoDecrypt
	}

	err = decryptedSecret.Unmarshal(decryptedMessage)
	if err != nil {
		return nil, nil, errcode.ErrDeserialization
	}

	return senderDevicePubKey, decryptedSecret, nil
}

func GroupIDToNonce(group *Group) (*[24]byte, error) {
	// Nonce doesn't need to be secret, random nor unpredictable, it just needs
	// to be used only once for a given {sender, receiver} set and we will send
	// only one SecretEntryPayload per {localDevicePrivKey, remoteMemberPubKey}
	// So we can reuse groupID as nonce for all SecretEntryPayload and save
	// 24 bytes of storage and bandwidth for each of them.
	//
	// See https://pynacl.readthedocs.io/en/stable/secret/#nonce
	// See Security Model here: https://nacl.cr.yp.to/box.html
	var nonce [24]byte

	gid := group.GetPublicKey()

	copy(nonce[:], gid)

	return &nonce, nil
}
