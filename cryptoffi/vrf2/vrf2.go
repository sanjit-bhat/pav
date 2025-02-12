package vrf2

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	ed "filippo.io/edwards25519"
	"io"
)

const (
	SUITE      byte = 3
	ZERO       byte = 0
	ONE        byte = 1
	TWO        byte = 2
	THREE      byte = 3
	OUTPUT_LEN int  = 64
	PROOF_LEN  int  = 80
)

type PublicKey struct {
	compressed []byte
	point      *ed.Point
}

type PrivateKey struct {
	sk    *ed.Scalar
	pk    []byte
	nonce []byte
}

type fullProof struct {
	gamma *ed.Point
	c     *ed.Scalar
	s     *ed.Scalar
}

func GenerateKey(rnd io.Reader) (*PublicKey, *PrivateKey) {
	if rnd == nil {
		rnd = rand.Reader
	}

	seed := make([]byte, 32)
	if _, err := io.ReadFull(rnd, seed); err != nil {
		panic(err)
	}
	h := sha512.Sum512(seed)
	s, err := (&ed.Scalar{}).SetBytesWithClamping(h[:32])
	if err != nil {
		panic(err)
	}
	A := (&ed.Point{}).ScalarBaseMult(s)
	ABytes := A.Bytes()
	pk := &PublicKey{compressed: ABytes, point: A}
	sk := &PrivateKey{sk: s, pk: ABytes, nonce: seed}
	return pk, sk
}

func EncodePublicKey(pk *PublicKey) []byte {
	return pk.compressed
}

// DecodePublicKey can take in adversarial input.
func DecodePublicKey(b []byte) (*PublicKey, error) {
	decErr := errors.New("vrf: DecodePublicKey failed")
	if len(b) != 32 {
		return nil, decErr
	}
	y, err := (&ed.Point{}).SetBytes(b)
	if err != nil {
		return nil, err
	}
	// check if point on small sub-group. ECVRF_validate_key from RFC 9381.
	// this should be included in edwards25519, see tracking [issue].
	// [issue]: https://github.com/FiloSottile/edwards25519/issues/33.
	if (&ed.Point{}).MultByCofactor(y).
		Equal(ed.NewIdentityPoint()) == 1 {
		return nil, decErr
	}
	return &PublicKey{compressed: b, point: y}, nil
}

// Verify returns the VRF output, or nil if verification fails.
func (pk *PublicKey) Verify(proof []byte, data []byte) (out []byte, err error) {
	// TODO: not doing pt extraction here.
	decProof, err := decodeProof(proof)
	if err != nil {
		return
	}
	hPoint := encodeToCurve(pk.compressed, data)

	// U = s*B - c*Y
	u := (&ed.Point{}).Subtract(
		(&ed.Point{}).ScalarBaseMult(decProof.s),
		(&ed.Point{}).ScalarMult(decProof.c, pk.point),
	)

	// V = s*H - c*Gamma
	v := (&ed.Point{}).Subtract(
		(&ed.Point{}).ScalarMult(decProof.s, hPoint),
		(&ed.Point{}).ScalarMult(decProof.c, decProof.gamma),
	)

	pts := []*ed.Point{decProof.gamma, u, v}
	cPrime := genChallenge(pk.compressed, hPoint.Bytes(), pts)
	// if not equal, err.
	if decProof.c.Equal(cPrime) == 0 {
		err = errors.New("vrf: verify failed")
		return
	}
	return gammaToOut(decProof.gamma), nil
}

func (sk *PrivateKey) Prove(data []byte) (out, proof []byte) {
	hPoint := encodeToCurve(sk.pk, data)
	hPointBytes := hPoint.Bytes()
	kNonceBytes := nonceGenerationBytes(sk.nonce, hPointBytes)
	kScalar, err := (&ed.Scalar{}).SetUniformBytes(kNonceBytes)
	if err != nil {
		panic(err)
	}
	gamma := (&ed.Point{}).ScalarMult(sk.sk, hPoint)
	pts := []*ed.Point{gamma, (&ed.Point{}).ScalarBaseMult(kScalar), (&ed.Point{}).ScalarMult(kScalar, hPoint)}
	chal := genChallenge(sk.pk, hPointBytes, pts)
	s := ed.NewScalar().Add(kScalar, ed.NewScalar().Multiply(chal, sk.sk))

	// TODO: should we factor out some calls to gamma.Bytes()?
	// maybe after flamegraph.
	out = gammaToOut(gamma)
	proof = encodeProof(&fullProof{gamma: gamma, c: chal, s: s})
	return
}

func encodeProof(p *fullProof) []byte {
	b := make([]byte, 0, PROOF_LEN)
	b = append(b, p.gamma.Bytes()...)
	b = append(b, p.c.Bytes()[:16]...)
	b = append(b, p.s.Bytes()...)
	return b
}

func decodeProof(b []byte) (*fullProof, error) {
	decErr := errors.New("vrf: proof decode")
	if len(b) < PROOF_LEN {
		return nil, decErr
	}
	gamma, err := (&ed.Point{}).SetBytes(b[:32])
	if err != nil {
		return nil, decErr
	}
	cB := make([]byte, 32)
	copy(cB, b[32:48])
	c, err := (&ed.Scalar{}).SetCanonicalBytes(cB)
	if err != nil {
		return nil, decErr
	}
	s, err := (&ed.Scalar{}).SetCanonicalBytes(b[48:80])
	if err != nil {
		return nil, decErr
	}
	return &fullProof{gamma: gamma, c: c, s: s}, nil
}

// TODO: add spec funcs.
func encodeToCurve(pk []byte, alpha []byte) *ed.Point {
	inLen := 1 + 1 + 32 + len(alpha) + 1 + 1
	hashIn := make([]byte, 0, inLen)
	hashIn = append(hashIn, SUITE)
	hashIn = append(hashIn, ONE)
	hashIn = append(hashIn, pk...)
	hashIn = append(hashIn, alpha...)
	hashOut := make([]byte, 0, 64)
	wrappedPoint := &ed.Point{}
	ident := ed.NewIdentityPoint()

	for ctr := 0; ctr < 256; ctr++ {
		hashIn = append(hashIn, byte(ctr))
		hashIn = append(hashIn, ZERO)
		hr := sha512.New()
		if _, err := hr.Write(hashIn); err != nil {
			panic(err)
		}
		hr.Sum(hashOut)
		hashOut = hashOut[:32]

		if _, err := wrappedPoint.SetBytes(hashOut); err == nil {
			res := (&ed.Point{}).MultByCofactor(wrappedPoint)
			// if not equal, return.
			if res.Equal(ident) == 0 {
				return res
			}
		}

		hashIn = hashIn[:inLen-2]
		hashOut = hashOut[:0]
	}
	panic("vrf: unable to find valid ctr value")
}

func gammaToOut(gamma *ed.Point) (out []byte) {
	hr := sha512.New()
	hr.Write([]byte{SUITE, THREE})
	hr.Write((&ed.Point{}).MultByCofactor(gamma).Bytes())
	hr.Write([]byte{ZERO})
	out = hr.Sum(nil)
	return
}

func nonceGenerationBytes(nonce, hPointBytes []byte) []byte {
	hr := sha512.New()
	hr.Write(nonce)
	hr.Write(hPointBytes)
	return hr.Sum(nil)
}

// genChallenge corresponds to ECVRF_challenge_generation.
func genChallenge(pk []byte, hPointBytes []byte, points []*ed.Point) *ed.Scalar {
	hr := sha512.New()
	hr.Write([]byte{SUITE, TWO})
	hr.Write(pk)
	hr.Write(hPointBytes)
	for _, p := range points {
		hr.Write(p.Bytes())
	}
	hr.Write([]byte{ZERO})

	h := hr.Sum(nil)[:32]
	for i := 16; i < 32; i++ {
		h[i] = 0
	}
	s, err := (&ed.Scalar{}).SetCanonicalBytes(h)
	if err != nil {
		panic(err)
	}
	return s
}
