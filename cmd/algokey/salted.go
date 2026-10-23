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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

var (
	errSaltedTxnAlreadySigned  = errors.New("transaction already has a signature")
	errSaltedSchemeRequired    = errors.New("--scheme is required with --mnemonic")
	errSaltedSchemeWithKeyfile = errors.New("--scheme cannot be used with --keyfile, which records its scheme")
)

const (
	schemeUsage         = "Signature scheme: falcon-1024 (f1), falcon-512 (f5), ed25519 (ed)"
	schemeMnemonicUsage = "Scheme key mnemonic"
)

var (
	saltedGenerateScheme  string
	saltedGenerateKeyfile string

	saltedInfoKeyfile string

	saltedImportMnemonic string
	saltedImportScheme   string
	saltedImportKeyfile  string

	saltedSignKeyfile   string
	saltedSignMnemonic  string
	saltedSignScheme    string
	saltedSignTxfile    string
	saltedSignOutfile   string
	saltedSignOverwrite bool

	saltedSignProgramKeyfile  string
	saltedSignProgramMnemonic string
	saltedSignProgramScheme   string
	saltedSignProgramProgram  string
	saltedSignProgramOutfile  string
)

type saltedSignOptions struct {
	keyfile   string
	mnemonic  string
	scheme    string
	txfile    string
	outfile   string
	overwrite bool
}

type saltedSignProgramOptions struct {
	keyfile  string
	mnemonic string
	scheme   string
	program  string
	outfile  string
}

type saltedSigningContext struct {
	ops     sigSchemeOps
	signing saltedSigningMaterial
}

var saltedCmd = &cobra.Command{
	Use: "salted",
	// pq is the name this group shipped with; keep it so existing scripts work.
	Aliases: []string{"pq"},
	Short:   "Manage salted-address account keys",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.HelpFunc()(cmd, args)
	},
}

var saltedGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a salted-address account key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runSaltedGenerate())
	},
}

var saltedInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Print salted-address account key information",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runSaltedInfo())
	},
}

var saltedImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a salted-address account private key from a mnemonic",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runSaltedImport())
	},
}

var saltedSignCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign transactions with a salted-address account private key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runSaltedSign())
	},
}

var saltedSignProgramCmd = &cobra.Command{
	Use:   "sign-program",
	Short: "Sign a LogicSig program with a salted-address account private key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runSaltedSignProgram())
	},
}

var saltedCheckAddressCmd = &cobra.Command{
	Use:   "check-address ADDRESS",
	Short: "Check that an address is off the Ed25519 curve",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		exitOnError(runSaltedCheckAddress(args[0]))
	},
}

func init() {
	saltedCmd.AddCommand(saltedGenerateCmd)
	saltedCmd.AddCommand(saltedInfoCmd)
	saltedCmd.AddCommand(saltedImportCmd)
	saltedCmd.AddCommand(saltedSignCmd)
	saltedCmd.AddCommand(saltedSignProgramCmd)
	saltedCmd.AddCommand(saltedCheckAddressCmd)

	saltedGenerateCmd.Flags().StringVarP(&saltedGenerateScheme, "scheme", "S", "", schemeUsage+"; required")
	saltedGenerateCmd.Flags().StringVarP(&saltedGenerateKeyfile, "keyfile", "k", "", "Private key filename")
	mustMarkFlagRequired(saltedGenerateCmd, "scheme")
	mustMarkFlagRequired(saltedGenerateCmd, "keyfile")

	saltedInfoCmd.Flags().StringVarP(&saltedInfoKeyfile, "keyfile", "k", "", "Private key filename")
	mustMarkFlagRequired(saltedInfoCmd, "keyfile")

	saltedImportCmd.Flags().StringVarP(&saltedImportMnemonic, "mnemonic", "m", "", schemeMnemonicUsage)
	saltedImportCmd.Flags().StringVarP(&saltedImportScheme, "scheme", "S", "", schemeUsage+"; required")
	saltedImportCmd.Flags().StringVarP(&saltedImportKeyfile, "keyfile", "k", "", "Private key filename")
	mustMarkFlagRequired(saltedImportCmd, "mnemonic")
	mustMarkFlagRequired(saltedImportCmd, "scheme")
	mustMarkFlagRequired(saltedImportCmd, "keyfile")

	saltedSignCmd.Flags().StringVarP(&saltedSignKeyfile, "keyfile", "k", "", "Private key filename")
	saltedSignCmd.Flags().StringVarP(&saltedSignMnemonic, "mnemonic", "m", "", schemeMnemonicUsage)
	saltedSignCmd.Flags().StringVarP(&saltedSignScheme, "scheme", "S", "", schemeUsage+"; required with --mnemonic, not allowed with --keyfile")
	saltedSignCmd.Flags().StringVarP(&saltedSignTxfile, "txfile", "t", "", "Transaction input filename")
	saltedSignCmd.Flags().StringVarP(&saltedSignOutfile, "outfile", "o", "", "Transaction output filename")
	saltedSignCmd.Flags().BoolVar(&saltedSignOverwrite, "overwrite", false, "Overwrite any existing signature category")
	mustMarkFlagRequired(saltedSignCmd, "txfile")
	mustMarkFlagRequired(saltedSignCmd, "outfile")

	saltedSignProgramCmd.Flags().StringVarP(&saltedSignProgramKeyfile, "keyfile", "k", "", "Private key filename")
	saltedSignProgramCmd.Flags().StringVarP(&saltedSignProgramMnemonic, "mnemonic", "m", "", schemeMnemonicUsage)
	saltedSignProgramCmd.Flags().StringVarP(&saltedSignProgramScheme, "scheme", "S", "", schemeUsage+"; required with --mnemonic, not allowed with --keyfile")
	saltedSignProgramCmd.Flags().StringVarP(&saltedSignProgramProgram, "program", "p", "", "Compiled LogicSig program input filename")
	saltedSignProgramCmd.Flags().StringVarP(&saltedSignProgramOutfile, "outfile", "o", "", "LogicSig output filename")
	mustMarkFlagRequired(saltedSignProgramCmd, "program")
	mustMarkFlagRequired(saltedSignProgramCmd, "outfile")
}

func mustMarkFlagRequired(cmd *cobra.Command, flagName string) {
	if err := cmd.MarkFlagRequired(flagName); err != nil {
		panic(fmt.Sprintf("failed to mark %s flag %q required: %v", cmd.CommandPath(), flagName, err))
	}
}

func runSaltedGenerate() error {
	scheme, err := parseSigScheme(saltedGenerateScheme)
	if err != nil {
		return fmt.Errorf("cannot generate key: %w", err)
	}
	entropy, signing, err := generateSaltedSigningMaterial(scheme, crypto.SystemRNG)
	if err != nil {
		return fmt.Errorf("cannot generate key: %w", err)
	}

	if err = writeSaltedPrivateKeyFile(saltedGenerateKeyfile, signing); err != nil {
		return err
	}
	if err = printSaltedMnemonic(os.Stdout, entropy); err != nil {
		return err
	}

	return printSaltedKeyInfo(os.Stdout, signing.Public)
}

func runSaltedInfo() error {
	signing, err := readSaltedSigningMaterial(saltedInfoKeyfile)
	if err != nil {
		return err
	}
	return printSaltedKeyInfo(os.Stdout, signing.Public)
}

func runSaltedImport() error {
	return runSaltedImportWithOptions(saltedImportMnemonic, saltedImportScheme, saltedImportKeyfile)
}

func runSaltedImportWithOptions(mnemonic, schemeName, keyfile string) error {
	if schemeName == "" {
		return errSaltedSchemeRequired
	}
	entropy, err := seedFromMnemonic(mnemonic)
	if err != nil {
		return fmt.Errorf("cannot recover key entropy from mnemonic: %w", err)
	}
	scheme, err := parseSigScheme(schemeName)
	if err != nil {
		return err
	}

	signing, err := deriveSaltedSigningMaterialFromEntropy(scheme, entropy)
	if err != nil {
		return err
	}

	if err = writeSaltedPrivateKeyFile(keyfile, signing); err != nil {
		return err
	}
	return printSaltedKeyInfo(os.Stdout, signing.Public)
}

func runSaltedSign() error {
	return runSaltedSignWithOptions(saltedSignOptions{
		keyfile:   saltedSignKeyfile,
		mnemonic:  saltedSignMnemonic,
		scheme:    saltedSignScheme,
		txfile:    saltedSignTxfile,
		outfile:   saltedSignOutfile,
		overwrite: saltedSignOverwrite,
	})
}

func runSaltedSignWithOptions(opts saltedSignOptions) error {
	hctx, err := resolveSaltedSigningContext(opts.keyfile, opts.mnemonic, opts.scheme)
	if err != nil {
		return err
	}
	public := hctx.signing.Public

	txdata, err := readFile(opts.txfile)
	if err != nil {
		return fmt.Errorf("cannot read transactions from %s: %w", opts.txfile, err)
	}

	var outBytes []byte
	decodedTxns := 0
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
		decodedTxns++

		if stxn.HasSignature() {
			if !opts.overwrite {
				return errSaltedTxnAlreadySigned
			}
			clearSignedTxnAuthorization(&stxn)
		}

		hsig, signErr := signSalted(hctx, stxn.Txn)
		if signErr != nil {
			return fmt.Errorf("cannot sign transaction: %w", signErr)
		}

		stxn.Hsig = hsig
		if stxn.Txn.Sender != public.address() {
			stxn.AuthAddr = public.address()
		}

		outBytes = append(outBytes, protocol.Encode(&stxn)...)
	}

	if decodedTxns == 0 {
		return fmt.Errorf("no transactions found in %s", opts.txfile)
	}
	if err = writeFile(opts.outfile, outBytes, 0600); err != nil {
		return fmt.Errorf("cannot write signed transactions to %s: %w", opts.outfile, err)
	}
	return nil
}

func resolveSaltedSigningContext(keyfile, mnemonic, schemeName string) (saltedSigningContext, error) {
	var signing saltedSigningMaterial
	var err error
	switch {
	case keyfile != "" && mnemonic != "":
		return saltedSigningContext{}, errors.New("cannot specify both --keyfile and --mnemonic")
	case mnemonic != "":
		if schemeName == "" {
			return saltedSigningContext{}, errSaltedSchemeRequired
		}
		entropy, seedErr := seedFromMnemonic(mnemonic)
		if seedErr != nil {
			return saltedSigningContext{}, fmt.Errorf("cannot recover key entropy from mnemonic: %w", seedErr)
		}
		scheme, parseErr := parseSigScheme(schemeName)
		if parseErr != nil {
			return saltedSigningContext{}, parseErr
		}
		signing, err = deriveSaltedSigningMaterialFromEntropy(scheme, entropy)
	case keyfile != "":
		if schemeName != "" {
			return saltedSigningContext{}, errSaltedSchemeWithKeyfile
		}
		signing, err = readSaltedSigningMaterial(keyfile)
	default:
		return saltedSigningContext{}, errors.New("must specify --keyfile or --mnemonic")
	}
	if err != nil {
		return saltedSigningContext{}, err
	}

	ops, ok := sigSchemeOpsByScheme[signing.Public.Scheme]
	if !ok {
		return saltedSigningContext{}, fmt.Errorf("%w: %q", transactions.ErrSigSchemeNotSupported, signing.Public.Scheme)
	}

	return saltedSigningContext{
		ops:     ops,
		signing: signing,
	}, nil
}

func signSalted(hctx saltedSigningContext, message crypto.Hashable) (transactions.HashedKeySig, error) {
	signature, err := hctx.ops.sign(hctx.signing.PrivateKey, message)
	if err != nil {
		return transactions.HashedKeySig{}, err
	}

	return transactions.HashedKeySig{
		Scheme:    hctx.signing.Public.Scheme,
		Salt:      hctx.signing.Public.Salt,
		PublicKey: hctx.signing.Public.PublicKey,
		Signature: signature,
	}, nil
}

func runSaltedSignProgram() error {
	return runSaltedSignProgramWithOptions(saltedSignProgramOptions{
		keyfile:  saltedSignProgramKeyfile,
		mnemonic: saltedSignProgramMnemonic,
		scheme:   saltedSignProgramScheme,
		program:  saltedSignProgramProgram,
		outfile:  saltedSignProgramOutfile,
	})
}

func runSaltedSignProgramWithOptions(opts saltedSignProgramOptions) error {
	hctx, err := resolveSaltedSigningContext(opts.keyfile, opts.mnemonic, opts.scheme)
	if err != nil {
		return err
	}

	program, err := readFile(opts.program)
	if err != nil {
		return fmt.Errorf("cannot read program from %s: %w", opts.program, err)
	}
	if len(program) == 0 {
		return errors.New("program is empty")
	}
	if strings.HasSuffix(opts.program, ".teal") {
		return fmt.Errorf("%s looks like TEAL source; compile it first (e.g. goal clerk compile) and don't use the .teal extension", opts.program)
	}
	if looksLikeTealSource(program) {
		return errors.New("program is not compiled bytecode; compile it first (e.g. goal clerk compile) and don't use the .teal extension")
	}
	hsig, err := signSalted(hctx, logic.HsigDelegatedProgram{Addr: hctx.signing.Public.address(), Program: program})
	if err != nil {
		return fmt.Errorf("cannot sign program: %w", err)
	}

	lsig := transactions.LogicSig{
		Logic: program,
		Hsig:  hsig,
	}
	if err = writeFile(opts.outfile, protocol.Encode(&lsig), 0600); err != nil {
		return fmt.Errorf("cannot write LogicSig to %s: %w", opts.outfile, err)
	}
	return nil
}

// looksLikeTealSource reports whether data is entirely printable ASCII and
// whitespace, resembling TEAL source rather than compiled bytecode.
func looksLikeTealSource(data []byte) bool {
	for _, b := range data {
		if (b < ' ' && b != '\t' && b != '\n' && b != '\r') || b > '~' {
			return false
		}
	}
	return true
}

func runSaltedCheckAddress(address string) error {
	addr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return fmt.Errorf("cannot parse address: %w", err)
	}
	if !addr.IsOffEd25519Curve() {
		return fmt.Errorf("address %s is on the Ed25519 curve", addr)
	}
	fmt.Printf("address %s is off the Ed25519 curve\n", addr)
	return nil
}

func clearSignedTxnAuthorization(stxn *transactions.SignedTxn) {
	stxn.Sig = crypto.Signature{}
	stxn.Msig = crypto.MultisigSig{}
	stxn.Lsig = transactions.LogicSig{}
	stxn.Hsig = transactions.HashedKeySig{}
	stxn.AuthAddr = basics.Address{}
}

func printSaltedMnemonic(w io.Writer, entropy crypto.Seed) error {
	mnemonic, err := mnemonicFromSeed(entropy)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "Private key mnemonic: %s\nWrite these words down: they cannot be recovered from the key file.\n", mnemonic)
	return err
}

func printSaltedKeyInfo(w io.Writer, public saltedPublicMaterial) error {
	_, err := io.WriteString(w, fmt.Sprintf(
		"Scheme: %s\nPublic key: %s\nAddress salt: %d\nAddress: %s\n",
		formatSigScheme(public.Scheme),
		base64.StdEncoding.EncodeToString(public.PublicKey),
		public.Salt,
		public.address(),
	))
	return err
}

func exitOnError(err error) {
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
