package crypto

import (
	"crypto"
	"encoding/binary"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const quicVersion1Salt = "afc824ec5fc77eca1e9d36f37fb2d46518c36639"

func newNullAEADAESGCM(connectionID protocol.ConnectionID, pers protocol.Perspective) (AEAD, error) {
	connID := make([]byte, 8)
	binary.BigEndian.PutUint64(connID, uint64(connectionID))
	cleartextSecret := mint.HkdfExtract(crypto.SHA256, []byte(quicVersion1Salt), connID)
	clientSecret := mint.HkdfExpandLabel(crypto.SHA256, cleartextSecret, "QUIC client cleartext Secret", []byte{}, crypto.SHA256.Size())
	serverSecret := mint.HkdfExpandLabel(crypto.SHA256, cleartextSecret, "QUIC server cleartext Secret", []byte{}, crypto.SHA256.Size())

	var mySecret, otherSecret []byte
	if pers == protocol.PerspectiveClient {
		mySecret = clientSecret
		otherSecret = serverSecret
	} else {
		mySecret = serverSecret
		otherSecret = clientSecret
	}

	myKey, myIV := computeNullAEADKeyAndIV(mySecret)
	otherKey, otherIV := computeNullAEADKeyAndIV(otherSecret)

	return NewAEADAESGCM(otherKey, myKey, otherIV, myIV)
}

func computeNullAEADKeyAndIV(secret []byte) (key, iv []byte) {
	key = mint.HkdfExpandLabel(crypto.SHA256, secret, "key", nil, 16)
	iv = mint.HkdfExpandLabel(crypto.SHA256, secret, "iv", nil, 12)
	return
}
