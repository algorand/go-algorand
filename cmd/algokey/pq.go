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

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/data/transactions/logic"
	"github.com/algorand/go-algorand/protocol"
)

var errPQTxnAlreadySigned = errors.New("transaction already has a signature")

var (
	pqGenerateScheme  = pqSchemeFalcon1024Name
	pqGenerateKeyfile string

	pqInfoKeyfile string

	pqImportMnemonic string
	pqImportScheme   = pqSchemeFalcon1024Name
	pqImportKeyfile  string

	pqSignKeyfile   string
	pqSignMnemonic  string
	pqSignScheme    = pqSchemeFalcon1024Name
	pqSignTxfile    string
	pqSignOutfile   string
	pqSignOverwrite bool

	pqSignProgramKeyfile  string
	pqSignProgramMnemonic string
	pqSignProgramScheme   = pqSchemeFalcon1024Name
	pqSignProgramProgram  string
	pqSignProgramOutfile  string
)

type pqSignOptions struct {
	keyfile   string
	mnemonic  string
	scheme    string
	txfile    string
	outfile   string
	overwrite bool
}

type pqSignProgramOptions struct {
	keyfile  string
	mnemonic string
	scheme   string
	program  string
	outfile  string
}

type pqSigningContext struct {
	ops     pqSchemeOps
	signing pqSigningMaterial
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

var pqImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a post-quantum private key from a mnemonic",
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

var pqSignProgramCmd = &cobra.Command{
	Use:   "sign-program",
	Short: "Sign a LogicSig program with a post-quantum private key",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runPQSignProgram())
	},
}

var pqCheckAddressCmd = &cobra.Command{
	Use:   "check-address ADDRESS",
	Short: "Check that an address is PQ compliant",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		exitOnError(runPQCheckAddress(args[0]))
	},
}

func init() {
	pqCmd.AddCommand(pqGenerateCmd)
	pqCmd.AddCommand(pqInfoCmd)
	pqCmd.AddCommand(pqImportCmd)
	pqCmd.AddCommand(pqSignCmd)
	pqCmd.AddCommand(pqSignProgramCmd)
	pqCmd.AddCommand(pqCheckAddressCmd)

	pqGenerateCmd.Flags().StringVarP(&pqGenerateScheme, "scheme", "S", pqGenerateScheme, "Post-quantum signature scheme: falcon-1024 (f1)")
	pqGenerateCmd.Flags().StringVarP(&pqGenerateKeyfile, "keyfile", "f", "", "Private key filename")
	mustMarkFlagRequired(pqGenerateCmd, "keyfile")

	pqInfoCmd.Flags().StringVarP(&pqInfoKeyfile, "keyfile", "f", "", "Private key filename")
	mustMarkFlagRequired(pqInfoCmd, "keyfile")

	pqImportCmd.Flags().StringVarP(&pqImportMnemonic, "mnemonic", "m", "", "Private key mnemonic")
	pqImportCmd.Flags().StringVarP(&pqImportScheme, "scheme", "S", pqImportScheme, "Post-quantum signature scheme: falcon-1024 (f1)")
	pqImportCmd.Flags().StringVarP(&pqImportKeyfile, "keyfile", "f", "", "Private key filename")
	mustMarkFlagRequired(pqImportCmd, "mnemonic")
	mustMarkFlagRequired(pqImportCmd, "keyfile")

	pqSignCmd.Flags().StringVarP(&pqSignKeyfile, "keyfile", "k", "", "Private key filename")
	pqSignCmd.Flags().StringVarP(&pqSignMnemonic, "mnemonic", "m", "", "Private key mnemonic")
	pqSignCmd.Flags().StringVarP(&pqSignScheme, "scheme", "S", pqSignScheme, "Post-quantum signature scheme: falcon-1024 (f1); used with --mnemonic")
	pqSignCmd.Flags().StringVarP(&pqSignTxfile, "txfile", "t", "", "Transaction input filename")
	pqSignCmd.Flags().StringVarP(&pqSignOutfile, "outfile", "o", "", "Transaction output filename")
	pqSignCmd.Flags().BoolVar(&pqSignOverwrite, "overwrite", false, "Overwrite any existing signature category")
	mustMarkFlagRequired(pqSignCmd, "txfile")
	mustMarkFlagRequired(pqSignCmd, "outfile")

	pqSignProgramCmd.Flags().StringVarP(&pqSignProgramKeyfile, "keyfile", "k", "", "Private key filename")
	pqSignProgramCmd.Flags().StringVarP(&pqSignProgramMnemonic, "mnemonic", "m", "", "Private key mnemonic")
	pqSignProgramCmd.Flags().StringVarP(&pqSignProgramScheme, "scheme", "S", pqSignProgramScheme, "Post-quantum signature scheme: falcon-1024 (f1); used with --mnemonic")
	pqSignProgramCmd.Flags().StringVarP(&pqSignProgramProgram, "program", "p", "", "Compiled LogicSig program input filename")
	pqSignProgramCmd.Flags().StringVarP(&pqSignProgramOutfile, "outfile", "o", "", "LogicSig output filename")
	mustMarkFlagRequired(pqSignProgramCmd, "program")
	mustMarkFlagRequired(pqSignProgramCmd, "outfile")
}

func mustMarkFlagRequired(cmd *cobra.Command, flagName string) {
	if err := cmd.MarkFlagRequired(flagName); err != nil {
		panic(fmt.Sprintf("failed to mark %s flag %q required: %v", cmd.CommandPath(), flagName, err))
	}
}

func runPQGenerate() error {
	scheme, err := parsePQScheme(pqGenerateScheme)
	if err != nil {
		return fmt.Errorf("cannot generate PQ key: %w", err)
	}
	entropy, signing, err := generatePQSigningMaterial(scheme, crypto.SystemRNG)
	if err != nil {
		return fmt.Errorf("cannot generate PQ key: %w", err)
	}

	if err = writePQPrivateKeyFile(pqGenerateKeyfile, signing); err != nil {
		return err
	}
	if err = printPQMnemonic(os.Stdout, entropy); err != nil {
		return err
	}

	return printPQKeyInfo(os.Stdout, signing.Public)
}

func runPQInfo() error {
	signing, err := readPQSigningMaterial(pqInfoKeyfile)
	if err != nil {
		return err
	}
	return printPQKeyInfo(os.Stdout, signing.Public)
}

func runPQImport() error {
	return runPQImportWithOptions(pqImportMnemonic, pqImportScheme, pqImportKeyfile)
}

func runPQImportWithOptions(mnemonic, schemeName, keyfile string) error {
	entropy, err := seedFromMnemonic(mnemonic)
	if err != nil {
		return fmt.Errorf("cannot recover PQ key entropy from mnemonic: %w", err)
	}
	scheme, err := parsePQScheme(schemeName)
	if err != nil {
		return err
	}

	signing, err := derivePQSigningMaterialFromEntropy(scheme, entropy)
	if err != nil {
		return err
	}

	if err = writePQPrivateKeyFile(keyfile, signing); err != nil {
		return err
	}
	return printPQKeyInfo(os.Stdout, signing.Public)
}

func runPQSign() error {
	return runPQSignWithOptions(pqSignOptions{
		keyfile:   pqSignKeyfile,
		mnemonic:  pqSignMnemonic,
		scheme:    pqSignScheme,
		txfile:    pqSignTxfile,
		outfile:   pqSignOutfile,
		overwrite: pqSignOverwrite,
	})
}

func runPQSignWithOptions(opts pqSignOptions) error {
	pqctx, err := resolvePQSigningContext(opts.keyfile, opts.mnemonic, opts.scheme)
	if err != nil {
		return err
	}
	public := pqctx.signing.Public

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
				return errPQTxnAlreadySigned
			}
			clearSignedTxnAuthorization(&stxn)
		}

		pqsig, signErr := signPQ(pqctx, stxn.Txn)
		if signErr != nil {
			return fmt.Errorf("cannot sign transaction: %w", signErr)
		}

		stxn.PQsig = pqsig
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

func resolvePQSigningContext(keyfile, mnemonic, schemeName string) (pqSigningContext, error) {
	var signing pqSigningMaterial
	var err error
	switch {
	case keyfile != "" && mnemonic != "":
		return pqSigningContext{}, errors.New("cannot specify both --keyfile and --mnemonic")
	case mnemonic != "":
		entropy, seedErr := seedFromMnemonic(mnemonic)
		if seedErr != nil {
			return pqSigningContext{}, fmt.Errorf("cannot recover PQ key entropy from mnemonic: %w", seedErr)
		}
		scheme := protocol.PQSchemeFalcon1024
		if schemeName != "" {
			scheme, err = parsePQScheme(schemeName)
			if err != nil {
				return pqSigningContext{}, err
			}
		}
		signing, err = derivePQSigningMaterialFromEntropy(scheme, entropy)
	case keyfile != "":
		signing, err = readPQSigningMaterial(keyfile)
	default:
		return pqSigningContext{}, errors.New("must specify --keyfile or --mnemonic")
	}
	if err != nil {
		return pqSigningContext{}, err
	}

	ops, ok := pqSchemeOpsByScheme[signing.Public.Scheme]
	if !ok {
		return pqSigningContext{}, fmt.Errorf("%w: %q", crypto.ErrPQSchemeNotSupported, signing.Public.Scheme)
	}

	return pqSigningContext{
		ops:     ops,
		signing: signing,
	}, nil
}

func signPQ(pqctx pqSigningContext, message crypto.Hashable) (transactions.PQSig, error) {
	signature, err := pqctx.ops.sign(pqctx.signing.PrivateKey, message)
	if err != nil {
		return transactions.PQSig{}, err
	}

	return transactions.PQSig{
		Scheme:    pqctx.signing.Public.Scheme,
		Salt:      pqctx.signing.Public.Salt,
		PublicKey: pqctx.signing.Public.PublicKey,
		Signature: signature,
	}, nil
}

func runPQSignProgram() error {
	return runPQSignProgramWithOptions(pqSignProgramOptions{
		keyfile:  pqSignProgramKeyfile,
		mnemonic: pqSignProgramMnemonic,
		scheme:   pqSignProgramScheme,
		program:  pqSignProgramProgram,
		outfile:  pqSignProgramOutfile,
	})
}

func runPQSignProgramWithOptions(opts pqSignProgramOptions) error {
	pqctx, err := resolvePQSigningContext(opts.keyfile, opts.mnemonic, opts.scheme)
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
	pqsig, err := signPQ(pqctx, logic.PQDelegatedProgram{Addr: pqctx.signing.Public.address(), Program: program})
	if err != nil {
		return fmt.Errorf("cannot sign program: %w", err)
	}

	lsig := transactions.LogicSig{
		Logic: program,
		PQsig: pqsig,
	}
	if err = writeFile(opts.outfile, protocol.Encode(&lsig), 0600); err != nil {
		return fmt.Errorf("cannot write LogicSig to %s: %w", opts.outfile, err)
	}
	return nil
}

func runPQCheckAddress(address string) error {
	addr, err := basics.UnmarshalChecksumAddress(address)
	if err != nil {
		return fmt.Errorf("cannot parse address: %w", err)
	}
	if !addr.IsPQCompliant() {
		return fmt.Errorf("address %s is not PQ compliant", addr)
	}
	fmt.Printf("address %s is PQ compliant\n", addr)
	return nil
}

func clearSignedTxnAuthorization(stxn *transactions.SignedTxn) {
	stxn.Sig = crypto.Signature{}
	stxn.Msig = crypto.MultisigSig{}
	stxn.Lsig = transactions.LogicSig{}
	stxn.PQsig = transactions.PQSig{}
	stxn.AuthAddr = basics.Address{}
}

func printPQMnemonic(w io.Writer, entropy crypto.Seed) error {
	mnemonic, err := mnemonicFromSeed(entropy)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "PQ private key mnemonic: %s\nWrite these words down: they cannot be recovered from the key file.\n", mnemonic)
	return err
}

func printPQKeyInfo(w io.Writer, public pqPublicMaterial) error {
	_, err := io.WriteString(w, fmt.Sprintf(
		"PQ scheme: %s\nPQ public key: %s\nPQ address salt: %d\nPQ address: %s\n",
		formatPQScheme(public.Scheme),
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
