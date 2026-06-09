// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

const (
	pqPrivateKeyMagic = "ALGOKEY-PQ-PRIVATE"
	pqPublicKeyMagic  = "ALGOKEY-PQ-PUBLIC"

	pqArmorBegin    = "-----BEGIN ALGOKEY PQ PRIVATE KEY-----"
	pqArmorEnd      = "-----END ALGOKEY PQ PRIVATE KEY-----"
	pqArmorEncoding = "Encoding: base64"
	pqArmorLineLen  = 64
)

var (
	errPQKeyWrongType       = errors.New("pq key file has the wrong type")
	errPQKeyUnsupported     = errors.New("pq scheme is not supported")
	errPQKeyMalformed       = errors.New("pq key file is malformed")
	errPQSaltNotCompliant   = errors.New("pq address salt is not compliant")
	errPQTxnAlreadySigned   = errors.New("transaction already has a signature")
	errPQArmorMalformed     = errors.New("pq armored private key is malformed")
	errPQPrivateKeyMismatch = errors.New("pq public/private key pair mismatch")
)

type pqSchemeSpec struct {
	scheme          protocol.PQScheme
	displayName     string
	publicKeySize   int
	privateKeySize  int
	generate        func(crypto.RNG) (pqKeyMaterial, error)
	signTxn         func([]byte, transactions.Transaction) ([]byte, error)
	validateKeyPair func([]byte, []byte) error
}

type pqKeyMaterial struct {
	scheme           protocol.PQScheme
	publicKey        []byte
	privateKey       []byte
	canonicalSalt    basics.PQAddressSalt
	canonicalAddress basics.Address
}

type pqPrivateKeyPayload struct {
	Scheme     protocol.PQScheme `codec:"scheme"`
	PublicKey  []byte            `codec:"public-key"`
	PrivateKey []byte            `codec:"private-key"`
}

type pqPublicKeyPayload struct {
	Scheme    protocol.PQScheme `codec:"scheme"`
	PublicKey []byte            `codec:"public-key"`
}

var pqSchemeSpecs = map[protocol.PQScheme]pqSchemeSpec{
	protocol.PQSchemeFalcon1024: {
		scheme:          protocol.PQSchemeFalcon1024,
		displayName:     "Deterministic Falcon-1024",
		publicKeySize:   crypto.FalconPublicKeySize,
		privateKeySize:  falconPrivateKeySize(),
		generate:        generateFalcon1024Key,
		signTxn:         signFalcon1024Txn,
		validateKeyPair: validateFalcon1024KeyPair,
	},
}

var (
	pqGenerateScheme     = string(protocol.PQSchemeFalcon1024)
	pqGenerateKeyfile    string
	pqGeneratePubkeyfile string

	pqInfoKeyfile string
	pqInfoSalt    = "canonical"

	pqAddressPubkeyfile string
	pqAddressScheme     = string(protocol.PQSchemeFalcon1024)
	pqAddressSalt       = "canonical"

	pqExportKeyfile string
	pqExportOutfile string

	pqImportInfile  string
	pqImportKeyfile string

	pqSignKeyfile   string
	pqSignTxfile    string
	pqSignOutfile   string
	pqSignSalt      = "canonical"
	pqSignOverwrite bool
)

type pqSignOptions struct {
	keyfile   string
	txfile    string
	outfile   string
	salt      string
	overwrite bool
}

var pqCmd = &cobra.Command{
	Use:   "pq",
	Short: "Manage post-quantum account keys",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
	},
}

var pqGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a post-quantum account key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runPQGenerate())
	},
}

var pqInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Print post-quantum key information",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runPQInfo())
	},
}

var pqAddressCmd = &cobra.Command{
	Use:   "address",
	Short: "Derive a post-quantum address from a public key file",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runPQAddress())
	},
}

var pqExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export a post-quantum private key in armored form",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runPQExport())
	},
}

var pqImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import an armored post-quantum private key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runPQImport())
	},
}

var pqSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign transactions with a post-quantum private key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runPQSign())
	},
}

func init() {
	pqCmd.AddCommand(pqGenerateCmd)
	pqCmd.AddCommand(pqInfoCmd)
	pqCmd.AddCommand(pqAddressCmd)
	pqCmd.AddCommand(pqExportCmd)
	pqCmd.AddCommand(pqImportCmd)
	pqCmd.AddCommand(pqSignCmd)

	pqGenerateCmd.Flags().StringVar(&pqGenerateScheme, "scheme", pqGenerateScheme, "Post-quantum signature scheme")
	pqGenerateCmd.Flags().StringVar(&pqGenerateKeyfile, "keyfile", "", "Private key filename")
	pqGenerateCmd.Flags().StringVar(&pqGeneratePubkeyfile, "pubkeyfile", "", "Public key filename")
	mustMarkFlagRequired(pqGenerateCmd, "keyfile")

	pqInfoCmd.Flags().StringVar(&pqInfoKeyfile, "keyfile", "", "Private key filename")
	pqInfoCmd.Flags().StringVar(&pqInfoSalt, "salt", pqInfoSalt, "Address salt: canonical or 0..255")
	mustMarkFlagRequired(pqInfoCmd, "keyfile")

	pqAddressCmd.Flags().StringVar(&pqAddressPubkeyfile, "pubkeyfile", "", "Public key filename")
	pqAddressCmd.Flags().StringVar(&pqAddressScheme, "scheme", pqAddressScheme, "Post-quantum signature scheme")
	pqAddressCmd.Flags().StringVar(&pqAddressSalt, "salt", pqAddressSalt, "Address salt: canonical or 0..255")
	mustMarkFlagRequired(pqAddressCmd, "pubkeyfile")

	pqExportCmd.Flags().StringVar(&pqExportKeyfile, "keyfile", "", "Private key filename")
	pqExportCmd.Flags().StringVar(&pqExportOutfile, "outfile", "", "Armored private key output filename")
	mustMarkFlagRequired(pqExportCmd, "keyfile")
	mustMarkFlagRequired(pqExportCmd, "outfile")

	pqImportCmd.Flags().StringVar(&pqImportInfile, "infile", "", "Armored private key input filename")
	pqImportCmd.Flags().StringVar(&pqImportKeyfile, "keyfile", "", "Private key filename")
	mustMarkFlagRequired(pqImportCmd, "infile")
	mustMarkFlagRequired(pqImportCmd, "keyfile")

	pqSignCmd.Flags().StringVar(&pqSignKeyfile, "keyfile", "", "Private key filename")
	pqSignCmd.Flags().StringVar(&pqSignTxfile, "txfile", "", "Transaction input filename")
	pqSignCmd.Flags().StringVar(&pqSignOutfile, "outfile", "", "Transaction output filename")
	pqSignCmd.Flags().StringVar(&pqSignSalt, "salt", pqSignSalt, "Address salt: canonical or 0..255")
	pqSignCmd.Flags().BoolVar(&pqSignOverwrite, "overwrite", false, "Overwrite any existing signature category")
	mustMarkFlagRequired(pqSignCmd, "keyfile")
	mustMarkFlagRequired(pqSignCmd, "txfile")
	mustMarkFlagRequired(pqSignCmd, "outfile")
}

func mustMarkFlagRequired(cmd *cobra.Command, flagName string) {
	if err := cmd.MarkFlagRequired(flagName); err != nil {
		panic(fmt.Sprintf("failed to mark %s flag %q required: %v", cmd.CommandPath(), flagName, err))
	}
}

func runPQGenerate() error {
	spec, err := parsePQScheme(pqGenerateScheme)
	if err != nil {
		return err
	}

	material, err := spec.generate(crypto.SystemRNG)
	if err != nil {
		return fmt.Errorf("cannot generate %s key: %w", spec.displayName, err)
	}

	if err = writePQPrivateKeyFile(pqGenerateKeyfile, material); err != nil {
		return err
	}
	if pqGeneratePubkeyfile != "" {
		if err = writePQPublicKeyFile(pqGeneratePubkeyfile, material); err != nil {
			return err
		}
	}

	return printPQKeyInfo(os.Stdout, material.scheme, material.publicKey, material.canonicalSalt, material.canonicalAddress, true)
}

func runPQInfo() error {
	material, err := readPQPrivateKeyFile(pqInfoKeyfile)
	if err != nil {
		return err
	}

	salt, addr, _, compliant, err := resolvePQSalt(material.scheme, material.publicKey, pqInfoSalt)
	if err != nil {
		return err
	}
	return printPQKeyInfo(os.Stdout, material.scheme, material.publicKey, salt, addr, compliant)
}

func runPQAddress() error {
	publicMaterial, err := readPQPublicKeyFile(pqAddressPubkeyfile)
	if err != nil {
		return err
	}

	spec, err := parsePQScheme(pqAddressScheme)
	if err != nil {
		return err
	}
	if publicMaterial.scheme != spec.scheme {
		return fmt.Errorf("%w: public key file scheme is %q, requested %q", errPQKeyWrongType, publicMaterial.scheme, spec.scheme)
	}

	salt, addr, _, compliant, err := resolvePQSalt(publicMaterial.scheme, publicMaterial.publicKey, pqAddressSalt)
	if err != nil {
		return err
	}
	return printPQKeyInfo(os.Stdout, publicMaterial.scheme, publicMaterial.publicKey, salt, addr, compliant)
}

func runPQExport() error {
	data, material, err := readPQPrivateKeyFileData(pqExportKeyfile)
	if err != nil {
		return err
	}

	armor := armorPQPrivateKey(material.scheme, data)
	if err = writeFile(pqExportOutfile, []byte(armor), 0600); err != nil {
		return fmt.Errorf("cannot write armored private key to %s: %w", pqExportOutfile, err)
	}
	return nil
}

func runPQImport() error {
	armor, err := readFile(pqImportInfile)
	if err != nil {
		return fmt.Errorf("cannot read armored private key from %s: %w", pqImportInfile, err)
	}

	data, _, err := decodeArmoredPQPrivateKey(string(armor))
	if err != nil {
		return err
	}
	if _, err = decodePQPrivateKeyFileBytes(data); err != nil {
		return err
	}

	if err = writeNewFile(pqImportKeyfile, data, 0600); err != nil {
		return fmt.Errorf("cannot write private key to %s: %w", pqImportKeyfile, err)
	}
	return nil
}

func runPQSign() error {
	return runPQSignWithOptions(pqSignOptions{
		keyfile:   pqSignKeyfile,
		txfile:    pqSignTxfile,
		outfile:   pqSignOutfile,
		salt:      pqSignSalt,
		overwrite: pqSignOverwrite,
	})
}

func runPQSignWithOptions(opts pqSignOptions) error {
	material, err := readPQPrivateKeyFile(opts.keyfile)
	if err != nil {
		return err
	}

	spec, err := specForPQScheme(material.scheme)
	if err != nil {
		return err
	}

	salt, authorizer, _, compliant, err := resolvePQSalt(material.scheme, material.publicKey, opts.salt)
	if err != nil {
		return err
	}
	if !compliant {
		return fmt.Errorf("%w: derived address %s for salt %d", errPQSaltNotCompliant, authorizer, salt)
	}

	txdata, err := readFile(opts.txfile)
	if err != nil {
		return fmt.Errorf("cannot read transactions from %s: %w", opts.txfile, err)
	}

	var outBytes []byte
	dec := protocol.NewMsgpDecoderBytes(txdata)
	for {
		var stxn transactions.SignedTxn
		err = dec.Decode(&stxn)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("cannot decode transaction: %w", err)
		}

		if signedTxnHasSignature(&stxn) {
			if !opts.overwrite {
				return errPQTxnAlreadySigned
			}
			clearSignedTxnSignatures(&stxn)
		}

		signature, signErr := spec.signTxn(material.privateKey, stxn.Txn)
		if signErr != nil {
			return fmt.Errorf("cannot sign transaction: %w", signErr)
		}

		stxn.PQSig = transactions.PQSig{
			Scheme:    material.scheme,
			Salt:      salt,
			PublicKey: append([]byte(nil), material.publicKey...),
			Signature: signature,
		}
		if stxn.Txn.Sender != authorizer {
			stxn.AuthAddr = authorizer
		} else {
			stxn.AuthAddr = basics.Address{}
		}

		outBytes = append(outBytes, protocol.Encode(&stxn)...)
	}

	if err = writeFile(opts.outfile, outBytes, 0600); err != nil {
		return fmt.Errorf("cannot write signed transactions to %s: %w", opts.outfile, err)
	}
	return nil
}

func parsePQScheme(scheme string) (pqSchemeSpec, error) {
	return specForPQScheme(protocol.PQScheme(scheme))
}

func specForPQScheme(scheme protocol.PQScheme) (pqSchemeSpec, error) {
	spec, ok := pqSchemeSpecs[scheme]
	if !ok {
		return pqSchemeSpec{}, fmt.Errorf("%w: %q", errPQKeyUnsupported, scheme)
	}
	return spec, nil
}

func generateFalcon1024Key(rng crypto.RNG) (pqKeyMaterial, error) {
	var seed crypto.FalconSeed
	rng.RandBytes(seed[:])
	defer zeroBytes(seed[:])

	signer, err := crypto.GenerateFalconSigner(seed)
	if err != nil {
		return pqKeyMaterial{}, err
	}

	publicKey := append([]byte(nil), signer.PublicKey[:]...)
	privateKey := append([]byte(nil), signer.PrivateKey[:]...)
	salt, addr, err := basics.CanonicalPQAddressSalt(protocol.PQSchemeFalcon1024, publicKey)
	if err != nil {
		zeroBytes(privateKey)
		return pqKeyMaterial{}, err
	}

	return pqKeyMaterial{
		scheme:           protocol.PQSchemeFalcon1024,
		publicKey:        publicKey,
		privateKey:       privateKey,
		canonicalSalt:    salt,
		canonicalAddress: addr,
	}, nil
}

func signFalcon1024Txn(privateKey []byte, txn transactions.Transaction) ([]byte, error) {
	sk, err := falconPrivateKeyFromBytes(privateKey)
	if err != nil {
		return nil, err
	}

	signer := crypto.FalconSigner{PrivateKey: sk}
	sig, err := signer.Sign(txn)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), sig...), nil
}

func validateFalcon1024KeyPair(publicKey []byte, privateKey []byte) error {
	pk, err := crypto.FalconPublicKeyFromBytes(publicKey)
	if err != nil {
		return err
	}
	sk, err := falconPrivateKeyFromBytes(privateKey)
	if err != nil {
		return err
	}

	signer := crypto.FalconSigner{
		PublicKey:  pk,
		PrivateKey: sk,
	}
	challenge := []byte("algokey-pq-keyfile-self-check")
	sig, err := signer.SignBytes(challenge)
	if err != nil {
		return err
	}

	verifier := crypto.FalconVerifier{PublicKey: pk}
	if err = verifier.VerifyBytes(challenge, sig); err != nil {
		return fmt.Errorf("%w: %w", errPQPrivateKeyMismatch, err)
	}
	return nil
}

func falconPrivateKeyFromBytes(privateKey []byte) (crypto.FalconPrivateKey, error) {
	var sk crypto.FalconPrivateKey
	if len(privateKey) != len(sk) {
		return crypto.FalconPrivateKey{}, fmt.Errorf("%w: got private key size %d, want %d", errPQKeyMalformed, len(privateKey), len(sk))
	}
	copy(sk[:], privateKey)
	return sk, nil
}

func falconPrivateKeySize() int {
	var sk crypto.FalconPrivateKey
	return len(sk)
}

func writePQPrivateKeyFile(filename string, material pqKeyMaterial) error {
	data := encodePQPrivateKeyFileBytes(material)
	if err := writeNewFile(filename, data, 0600); err != nil {
		return fmt.Errorf("cannot write private key to %s: %w", filename, err)
	}
	return nil
}

func writePQPublicKeyFile(filename string, material pqKeyMaterial) error {
	data := encodePQPublicKeyFileBytes(material)
	if err := writeNewFile(filename, data, 0666); err != nil {
		return fmt.Errorf("cannot write public key to %s: %w", filename, err)
	}
	return nil
}

func readPQPrivateKeyFile(filename string) (pqKeyMaterial, error) {
	_, material, err := readPQPrivateKeyFileData(filename)
	return material, err
}

func readPQPrivateKeyFileData(filename string) ([]byte, pqKeyMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return nil, pqKeyMaterial{}, fmt.Errorf("cannot read private key from %s: %w", filename, err)
	}
	material, err := decodePQPrivateKeyFileBytes(data)
	if err != nil {
		return nil, pqKeyMaterial{}, err
	}
	return data, material, nil
}

func readPQPublicKeyFile(filename string) (pqKeyMaterial, error) {
	data, err := readFile(filename)
	if err != nil {
		return pqKeyMaterial{}, fmt.Errorf("cannot read public key from %s: %w", filename, err)
	}
	return decodePQPublicKeyFileBytes(data)
}

func encodePQPrivateKeyFileBytes(material pqKeyMaterial) []byte {
	payload := pqPrivateKeyPayload{
		Scheme:     material.scheme,
		PublicKey:  append([]byte(nil), material.publicKey...),
		PrivateKey: append([]byte(nil), material.privateKey...),
	}
	return encodePQPayload(pqPrivateKeyMagic, payload)
}

func encodePQPublicKeyFileBytes(material pqKeyMaterial) []byte {
	payload := pqPublicKeyPayload{
		Scheme:    material.scheme,
		PublicKey: append([]byte(nil), material.publicKey...),
	}
	return encodePQPayload(pqPublicKeyMagic, payload)
}

func encodePQPayload(magic string, payload interface{}) []byte {
	encoded := protocol.EncodeReflect(payload)
	out := make([]byte, 0, len(magic)+1+len(encoded))
	out = append(out, magic...)
	out = append(out, '\n')
	out = append(out, encoded...)
	return out
}

func decodePQPrivateKeyFileBytes(data []byte) (pqKeyMaterial, error) {
	var payload pqPrivateKeyPayload
	if err := decodePQPayload(data, pqPrivateKeyMagic, &payload); err != nil {
		return pqKeyMaterial{}, err
	}
	return materialFromPrivatePayload(payload)
}

func decodePQPublicKeyFileBytes(data []byte) (pqKeyMaterial, error) {
	var payload pqPublicKeyPayload
	if err := decodePQPayload(data, pqPublicKeyMagic, &payload); err != nil {
		return pqKeyMaterial{}, err
	}
	return materialFromPublicPayload(payload)
}

func decodePQPayload(data []byte, magic string, payload interface{}) error {
	prefix := []byte(magic + "\n")
	if !bytes.HasPrefix(data, prefix) {
		return fmt.Errorf("%w: missing %s magic", errPQKeyWrongType, magic)
	}
	if len(data) == len(prefix) {
		return errPQKeyMalformed
	}
	if err := protocol.DecodeReflect(data[len(prefix):], payload); err != nil {
		return fmt.Errorf("%w: %w", errPQKeyMalformed, err)
	}
	return nil
}

func materialFromPrivatePayload(payload pqPrivateKeyPayload) (pqKeyMaterial, error) {
	material, err := materialFromPublicFields(payload.Scheme, payload.PublicKey)
	if err != nil {
		return pqKeyMaterial{}, err
	}

	spec, err := specForPQScheme(payload.Scheme)
	if err != nil {
		return pqKeyMaterial{}, err
	}
	if len(payload.PrivateKey) != spec.privateKeySize {
		return pqKeyMaterial{}, fmt.Errorf("%w: got private key size %d, want %d", errPQKeyMalformed, len(payload.PrivateKey), spec.privateKeySize)
	}
	material.privateKey = append([]byte(nil), payload.PrivateKey...)
	if spec.validateKeyPair != nil {
		if err = spec.validateKeyPair(material.publicKey, material.privateKey); err != nil {
			return pqKeyMaterial{}, err
		}
	}
	return material, nil
}

func materialFromPublicPayload(payload pqPublicKeyPayload) (pqKeyMaterial, error) {
	return materialFromPublicFields(payload.Scheme, payload.PublicKey)
}

func materialFromPublicFields(scheme protocol.PQScheme, publicKey []byte) (pqKeyMaterial, error) {
	spec, err := specForPQScheme(scheme)
	if err != nil {
		return pqKeyMaterial{}, err
	}
	if len(publicKey) != spec.publicKeySize {
		return pqKeyMaterial{}, fmt.Errorf("%w: got public key size %d, want %d", errPQKeyMalformed, len(publicKey), spec.publicKeySize)
	}
	if err = basics.ValidatePQPublicKey(scheme, publicKey); err != nil {
		return pqKeyMaterial{}, err
	}

	canonicalSalt, canonicalAddress, err := basics.CanonicalPQAddressSalt(scheme, publicKey)
	if err != nil {
		return pqKeyMaterial{}, err
	}
	if !canonicalAddress.IsPQCompliant() {
		return pqKeyMaterial{}, fmt.Errorf("%w: canonical address %s", errPQSaltNotCompliant, canonicalAddress)
	}

	return pqKeyMaterial{
		scheme:           scheme,
		publicKey:        append([]byte(nil), publicKey...),
		canonicalSalt:    canonicalSalt,
		canonicalAddress: canonicalAddress,
	}, nil
}

func resolvePQSalt(scheme protocol.PQScheme, publicKey []byte, saltValue string) (basics.PQAddressSalt, basics.Address, bool, bool, error) {
	if saltValue == "" || strings.EqualFold(saltValue, "canonical") {
		salt, addr, err := basics.CanonicalPQAddressSalt(scheme, publicKey)
		if err != nil {
			return 0, basics.Address{}, true, false, err
		}
		return salt, addr, true, addr.IsPQCompliant(), nil
	}

	n, err := strconv.ParseUint(saltValue, 10, 8)
	if err != nil {
		return 0, basics.Address{}, false, false, fmt.Errorf("invalid pq salt %q: use canonical or 0..255", saltValue)
	}
	if err = basics.ValidatePQPublicKey(scheme, publicKey); err != nil {
		return 0, basics.Address{}, false, false, err
	}
	salt := basics.PQAddressSalt(n)
	addr := basics.PQAddress(scheme, salt, publicKey)
	return salt, addr, false, addr.IsPQCompliant(), nil
}

func armorPQPrivateKey(scheme protocol.PQScheme, data []byte) string {
	var b strings.Builder
	b.WriteString(pqArmorBegin)
	b.WriteByte('\n')
	b.WriteString("Scheme: ")
	b.WriteString(string(scheme))
	b.WriteByte('\n')
	b.WriteString(pqArmorEncoding)
	b.WriteString("\n\n")

	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > pqArmorLineLen {
		b.WriteString(encoded[:pqArmorLineLen])
		b.WriteByte('\n')
		encoded = encoded[pqArmorLineLen:]
	}
	b.WriteString(encoded)
	b.WriteByte('\n')
	b.WriteString(pqArmorEnd)
	b.WriteByte('\n')
	return b.String()
}

func decodeArmoredPQPrivateKey(armor string) ([]byte, protocol.PQScheme, error) {
	lines := strings.Split(strings.ReplaceAll(armor, "\r\n", "\n"), "\n")
	if len(lines) < 6 || strings.TrimSpace(lines[0]) != pqArmorBegin {
		return nil, "", errPQArmorMalformed
	}

	schemeLine := strings.TrimSpace(lines[1])
	if !strings.HasPrefix(schemeLine, "Scheme: ") {
		return nil, "", errPQArmorMalformed
	}
	scheme := protocol.PQScheme(strings.TrimSpace(strings.TrimPrefix(schemeLine, "Scheme: ")))
	if _, err := specForPQScheme(scheme); err != nil {
		return nil, "", err
	}

	if strings.TrimSpace(lines[2]) != pqArmorEncoding {
		return nil, "", errPQArmorMalformed
	}
	if strings.TrimSpace(lines[3]) != "" {
		return nil, "", errPQArmorMalformed
	}

	var encoded strings.Builder
	foundEnd := false
	endIndex := -1
	for i, line := range lines[4:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == pqArmorEnd {
			foundEnd = true
			endIndex = i + 4
			break
		}
		encoded.WriteString(line)
	}
	if !foundEnd {
		return nil, "", errPQArmorMalformed
	}
	for _, line := range lines[endIndex+1:] {
		if strings.TrimSpace(line) != "" {
			return nil, "", errPQArmorMalformed
		}
	}

	data, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", errPQArmorMalformed, err)
	}

	material, err := decodePQPrivateKeyFileBytes(data)
	if err != nil {
		return nil, "", err
	}
	if material.scheme != scheme {
		return nil, "", fmt.Errorf("%w: armor scheme is %q, payload scheme is %q", errPQKeyMalformed, scheme, material.scheme)
	}
	return data, scheme, nil
}

func signedTxnHasSignature(stxn *transactions.SignedTxn) bool {
	return !stxn.Sig.Blank() || !stxn.Msig.Blank() || !stxn.Lsig.Blank() || !stxn.PQSig.Blank()
}

func clearSignedTxnSignatures(stxn *transactions.SignedTxn) {
	stxn.Sig = crypto.Signature{}
	stxn.Msig = crypto.MultisigSig{}
	stxn.Lsig = transactions.LogicSig{}
	stxn.PQSig = transactions.PQSig{}
}

func printPQKeyInfo(w io.Writer, scheme protocol.PQScheme, publicKey []byte, salt basics.PQAddressSalt, addr basics.Address, compliant bool) error {
	_, err := io.WriteString(w, fmt.Sprintf(
		"PQ scheme: %s\nPQ public key: %s\nPQ address salt: %d\nPQ address: %s\nPQ address compliant: %t\n",
		scheme,
		base64.StdEncoding.EncodeToString(publicKey),
		salt,
		addr,
		compliant,
	))
	return err
}

func writeNewFile(filename string, data []byte, perm os.FileMode) error {
	if filename == stdoutFilenameValue {
		return fmt.Errorf("refusing to write key file to stdout")
	}
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return closeErr
}

func exitOnError(err error) {
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func isPQKeyMaterial(data []byte) bool {
	return bytes.HasPrefix(data, []byte(pqPrivateKeyMagic+"\n")) ||
		bytes.HasPrefix(data, []byte(pqPublicKeyMagic+"\n")) ||
		bytes.HasPrefix(data, []byte(pqArmorBegin))
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
