package crypto

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("NullAEAD using AES-GCM", func() {
	It("seals and opens", func() {
		connectionID := protocol.ConnectionID(0x1234567890)
		clientAEAD, err := newNullAEADAESGCM(connectionID, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverAEAD, err := newNullAEADAESGCM(connectionID, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientAEAD.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		m, err := serverAEAD.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("foobar")))
		serverMessage := serverAEAD.Seal(nil, []byte("raboof"), 99, []byte("daa"))
		m, err = clientAEAD.Open(nil, serverMessage, 99, []byte("daa"))
		Expect(err).ToNot(HaveOccurred())
		Expect(m).To(Equal([]byte("raboof")))
	})

	It("doesn't work if initialized with different connection IDs", func() {
		clientAEAD, err := newNullAEADAESGCM(1, protocol.PerspectiveClient)
		Expect(err).ToNot(HaveOccurred())
		serverAEAD, err := newNullAEADAESGCM(2, protocol.PerspectiveServer)
		Expect(err).ToNot(HaveOccurred())

		clientMessage := clientAEAD.Seal(nil, []byte("foobar"), 42, []byte("aad"))
		_, err = serverAEAD.Open(nil, clientMessage, 42, []byte("aad"))
		Expect(err).To(MatchError("cipher: message authentication failed"))
	})
})
