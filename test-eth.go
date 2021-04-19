package main
import (
	// "hash"
	"crypto/rand"
	"crypto/elliptic"
	"reflect"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/crypto/ecies"
	"encoding/hex"
	"fmt"
	"crypto/x509"
	"crypto/sha256"
	"encoding/pem"
	"math/big"
	// "./mypackage"
)

func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
    x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
    pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

    x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
    pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

    return string(pemEncoded), string(pemEncodedPub)
}

func decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
    block, _ := pem.Decode([]byte(pemEncoded))
    x509Encoded := block.Bytes
    privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

    blockPub, _ := pem.Decode([]byte(pemEncodedPub))
    x509EncodedPub := blockPub.Bytes
    genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
    publicKey := genericPublicKey.(*ecdsa.PublicKey)

    return privateKey, publicKey
}

func test() {
    privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    publicKey := &privateKey.PublicKey

    encPriv, encPub := encode(privateKey, publicKey)

    fmt.Println(encPriv)
    fmt.Println(encPub)

    priv2, pub2 := decode(encPriv, encPub)

    if !reflect.DeepEqual(privateKey, priv2) {
        fmt.Println("Private keys do not match.")
    }
    if !reflect.DeepEqual(publicKey, pub2) {
        fmt.Println("Public keys do not match.")
    }
}

func PrivateKeyFromString(str string) (*ecdsa.PrivateKey , error) {
	aKey := new (ecdsa.PrivateKey)
	aKey.Curve = crypto.S256();
	aKey.D = new(big.Int)
	aKey.D.SetString(str, 16)
	
	aKey.PublicKey.X, aKey.PublicKey.Y = aKey.Curve.ScalarBaseMult(aKey.D.Bytes())
	return aKey, nil
}

////test sign for TrustKeys
// privHex:de8fb49e27f70e5a912037230150f95dc5bfb1e5135bc717a109727538cb668d
// pubHex: 03c37b1baa87c40697d168cafdf3812ad2fc001cc86f90ac2b1818be51e0b1a7b5
// Hash of message: fcad023d5674ec97b4ba613cc9795cca96d712c855acb2276566b6830c4dbba3
// sig - btc: 1f456eda1f93b580eda14eaf12a5592c0eb5b7e27ba4f7786a8a398a46dc55b876468671a3974140596c3a1c927641d27969c749075ac1125d6322a0e15f04b83f
// sig-Geth : 456eda1f93b580eda14eaf12a5592c0eb5b7e27ba4f7786a8a398a46dc55b876468671a3974140596c3a1c927641d27969c749075ac1125d6322a0e15f04b83f00

func testTrustKeysSign(){
	privHex := "de8fb49e27f70e5a912037230150f95dc5bfb1e5135bc717a109727538cb668d"
	privKey , _ := crypto.HexToECDSA(privHex);
	
	fmt.Println("Private Key ", hex.EncodeToString(privKey.D.Bytes() ))
	fmt.Println("Compress Pub Key hex: ", hex.EncodeToString(crypto.CompressPubkey(&privKey.PublicKey)) )
	hashHex := "fcad023d5674ec97b4ba613cc9795cca96d712c855acb2276566b6830c4dbba3"
	hashBytes , _ := hex.DecodeString(hashHex)
	sig , _ := crypto.Sign(hashBytes, privKey)
	fmt.Println("Sig: ", hex.EncodeToString(sig));
	fmt.Println("Sig len: ", len(sig) )
}

//ecrypted:     04fcad8f4bc527e29e807b6b997a0485c5226c1651d6db7f40381a7a53b2a54f30477dfa3763d40cbc420c7c98eb9d600e1c40917c441ddfc1c9c784a844993ed830238b53556eb0f59f12799fab52a5907be92a03e427934ca6b199a20e1bdf47381e2a1615705e1b941f5c6fca92984cf01adb6ad87a71f46c82fad4bc872500e078a11c4353a95f
//privated: "95d9284bda62d7248d003b0e0dd9a9f00b42bfd14441d8004fa2d48ebc4ce357"
//pub     : 04db45956f40c15a7319a68ad63402efb6650272c3d7017879d6315af9ce8a0e7645bd4fcffbbdd79a2f92ee63b06d8045d9dca65d6a3df21643745563caa3c059

func testTrustKeysEcies(){
	privHex := "95d9284bda62d7248d003b0e0dd9a9f00b42bfd14441d8004fa2d48ebc4ce357"
	privEcdsa , _ := crypto.HexToECDSA(privHex);
	priveKey := ecies.ImportECDSA(privEcdsa)
	// cryptedHex := "0473b460dbfc83789777e3b284a00589ee1fe830c6e1c907da6bfa9a13efea5246f72ae69c8a298aaaecb07bc56c77c63966e101239e4a91f6c5c554783c6237e4fce9e874756735ed350df19f02d9577c341d93b0a0c82e8f3df76672ca0821fffe2deb83052e077dc877ff26abe4568d0138fd3bb4b8ac5b168cd793d11dc73e53faab61088a9f1d"
	cryptedHex := "04b820ee70ffa7a53d46906b59fbf1a6d563f9a988527567831d56ec9b6a2b2f3744d94f33f46a76ca05a82c57eb3774652b797e66ed473341e656d3c0bcb5c1f0bec84ed0e131431676c3b82e450f5609491caf30bd6321c4324cd5ffbd4ed0202e449323ad2346e45529f6dabbfc2f8eee97d4f8930ca38e5c4dc95fa222994b4bc6cfb2a3cd3ae2"
	cryptedHex = "040a5d2d334602f77c3e0f65c53027dfc70ebf65dda51216426a70242cfcfbc2cbd48092b3fe0ee59edb07550fee58105cc3d5db6a8d5bf0b61030e5f04edf2be201ee3e26f9a8926e1483251518f176f5cf3657a0bbc0f5ce791708c844e8cb076fddfe4655070548d9879a27a5d04edccb56fb88a0c3a9b35d47f89452b219256c6437e4605415c1f30c42c5d9b120ddd443dd4fc298da707a7fe05f26e60a69e2ff05b84337f1657e8803f06b14a148d8bfc168a4a7165ad541620ffcfaea135a340120a1099c79039ddeea05d71d708dc45c75022e89e6e94a9414b1d3a4df1f7638b1557c8345baaf7348a03d4a4aaf1307d83dbed99b818ddc602768408ff07f856f150e31ed7e813212544d1941ad1f0ec92c3196854f7475b4c304f220132dc3f994994d5d"
	cryptedBin, _ :=  hex.DecodeString(cryptedHex)
	m, err := priveKey.Decrypt(cryptedBin, nil, nil)
	if err == nil {
		fmt.Println("decrypted ok: ", string(m) ,)
	}
}

func Hash256Hex(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	var out []byte;
	out = h.Sum(nil);
	return hex.EncodeToString(out);
}

func testSHA256(){
	h := sha256.New()
	h.Write([]byte("hello"))
	var out []byte;
	out = h.Sum(nil);
	fmt.Println("hash of hello :", hex.EncodeToString(out ) );
}

func main(){
	// testTrustKeysSign();
	// testTrustKeysEcies();
	var p *int = nil
	var err error;
	err = nil;
	var x interface{}
	x = p
	if err == nil {
		fmt.Println("err == nil")
	}
	if x == nil {
		fmt.Println("x == nil")
	}

	if p == nil {
		fmt.Println("p == nil")
	}
	testSHA256();
	// // mypackage.Test(100)
	// test();
	// // Create an account
	// key, _ := crypto.GenerateKey()

	// // Get the address
	// address := crypto.PubkeyToAddress(key.PublicKey).Hex()
	// // 0x8ee3333cDE801ceE9471ADf23370c48b011f82a6

	// // Get the private key
	// privateKey := hex.EncodeToString(key.D.Bytes())
	// // 05b14254a1d0c77a49eae3bdf080f926a2df17d8e2ebdf7af941ea001481e57f

	// fmt.Println("key: ",key);
	// fmt.Println("Address: ", address)
	// fmt.Println("PrivateKey: ", privateKey)
	// fmt.Println("PublickKey: ", key.PublicKey);

	// PriKey, _ := PrivateKeyFromString(privateKey)

	// fmt.Println("Org Key", key);
	// fmt.Println("Recoverd Key", PriKey);


	// HP:= hex.EncodeToString(crypto.CompressPubkey(&key.PublicKey))
	// fmt.Println( "PubkeyHex:" , HP )

	// X, _ := hex.DecodeString("03d2aacab851daf2cc072c386ddca9fa379e416141a07aa097a10a165e611191e1")
	// P, _ := crypto.DecompressPubkey(X)
	// fmt.Println("PubkeyDecoded:", P )

}