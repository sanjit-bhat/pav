package cryptoShim

type Sig = []byte

const (
	HashLen uint64 = 32
	SigLen  uint64 = 64
)

// Hashing.

func Hash(data []byte) []byte {
	panic("shim")
}

// Signatures.

type SignerT struct{}

type VerifierT struct{}

func MakeKeys() (SignerT, VerifierT) {
	panic("shim")
}

func Sign(sk SignerT, data []byte) Sig {
	panic("shim")
}

func Verify(vk VerifierT, data, sig Sig) bool {
	panic("shim")
}
