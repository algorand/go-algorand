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
	"slices"

	"github.com/spf13/cobra"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

var errPQTxnAlreadySigned = errors.New("transaction already has a signature")

var (
	pqGenerateScheme          = pqSchemeFalcon1024Name
	pqGenerateKeyfile         string
	pqGeneratePubkeyfile      string
	pqGenerateDisplayMnemonic bool

	pqInfoKeyfile string
	pqInfoSalt    = "canonical"

	pqAddressPubkeyfile string
	pqAddressScheme     = pqSchemeFalcon1024Name
	pqAddressSalt       = "canonical"

	pqExportKeyfile         string
	pqExportMnemonicFile    string
	pqExportDisplayMnemonic bool

	pqImportMnemonicFile    string
	pqImportKeyfile         string
	pqImportDisplayMnemonic bool

	pqSignKeyfile   string
	pqSignMnemonic  string
	pqSignScheme    = pqSchemeFalcon1024Name
	pqSignTxfile    string
	pqSignOutfile   string
	pqSignSalt      = "canonical"
	pqSignOverwrite bool
)

type pqSignOptions struct {
	keyfile   string
	mnemonic  string
	scheme    string
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
	Short: "Export a post-quantum private key mnemonic to a file",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, _ []string) {
		exitOnError(runPQExport())
	},
}

var pqImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a post-quantum private key from a mnemonic file",
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

	pqGenerateCmd.Flags().StringVarP(&pqGenerateScheme, "scheme", "S", pqGenerateScheme, "Post-quantum signature scheme: falcon-1024 (f1)")
	pqGenerateCmd.Flags().StringVarP(&pqGenerateKeyfile, "keyfile", "f", "", "Private key filename")
	pqGenerateCmd.Flags().StringVarP(&pqGeneratePubkeyfile, "pubkeyfile", "p", "", "Public key filename")
	pqGenerateCmd.Flags().BoolVar(&pqGenerateDisplayMnemonic, "display-mnemonic", false, "Display the private key mnemonic")
	mustMarkFlagRequired(pqGenerateCmd, "keyfile")

	pqInfoCmd.Flags().StringVarP(&pqInfoKeyfile, "keyfile", "f", "", "Private key filename")
	pqInfoCmd.Flags().StringVarP(&pqInfoSalt, "salt", "s", pqInfoSalt, "Address salt: canonical or 0..255")
	mustMarkFlagRequired(pqInfoCmd, "keyfile")

	pqAddressCmd.Flags().StringVarP(&pqAddressPubkeyfile, "pubkeyfile", "p", "", "Public key filename")
	pqAddressCmd.Flags().StringVarP(&pqAddressScheme, "scheme", "S", pqAddressScheme, "Post-quantum signature scheme: falcon-1024 (f1)")
	pqAddressCmd.Flags().StringVarP(&pqAddressSalt, "salt", "s", pqAddressSalt, "Address salt: canonical or 0..255")
	mustMarkFlagRequired(pqAddressCmd, "pubkeyfile")

	pqExportCmd.Flags().StringVarP(&pqExportKeyfile, "keyfile", "f", "", "Private key filename")
	pqExportCmd.Flags().StringVarP(&pqExportMnemonicFile, "mnemonic-file", "m", "", "Mnemonic output filename")
	pqExportCmd.Flags().BoolVar(&pqExportDisplayMnemonic, "display-mnemonic", false, "Display the private key mnemonic")
	mustMarkFlagRequired(pqExportCmd, "keyfile")

	pqImportCmd.Flags().StringVarP(&pqImportMnemonicFile, "mnemonic-file", "m", "", "Mnemonic input filename")
	pqImportCmd.Flags().StringVarP(&pqImportKeyfile, "keyfile", "f", "", "Private key filename")
	pqImportCmd.Flags().BoolVar(&pqImportDisplayMnemonic, "display-mnemonic", false, "Display the private key mnemonic")
	mustMarkFlagRequired(pqImportCmd, "mnemonic-file")
	mustMarkFlagRequired(pqImportCmd, "keyfile")

	pqSignCmd.Flags().StringVarP(&pqSignKeyfile, "keyfile", "k", "", "Private key filename")
	pqSignCmd.Flags().StringVarP(&pqSignMnemonic, "mnemonic", "m", "", "Private key mnemonic")
	pqSignCmd.Flags().StringVarP(&pqSignScheme, "scheme", "S", pqSignScheme, "Post-quantum signature scheme: falcon-1024 (f1); used with --mnemonic")
	pqSignCmd.Flags().StringVarP(&pqSignTxfile, "txfile", "t", "", "Transaction input filename")
	pqSignCmd.Flags().StringVarP(&pqSignOutfile, "outfile", "o", "", "Transaction output filename")
	pqSignCmd.Flags().StringVarP(&pqSignSalt, "salt", "s", pqSignSalt, "Address salt: canonical or 0..255")
	pqSignCmd.Flags().BoolVar(&pqSignOverwrite, "overwrite", false, "Overwrite any existing signature category")
	mustMarkFlagRequired(pqSignCmd, "txfile")
	mustMarkFlagRequired(pqSignCmd, "outfile")
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
	root, err := generatePQRoot(scheme, crypto.SystemRNG)
	if err != nil {
		return fmt.Errorf("cannot generate PQ key: %w", err)
	}

	if err = writePQRootKeyFile(pqGenerateKeyfile, root); err != nil {
		return err
	}
	if pqGeneratePubkeyfile != "" {
		if err = writePQPublicKeyFile(pqGeneratePubkeyfile, root.public); err != nil {
			return err
		}
	}
	if pqGenerateDisplayMnemonic {
		if err = printPQMnemonic(os.Stdout, root.entropy); err != nil {
			return err
		}
	}

	return printPQKeyInfo(os.Stdout, root.public)
}

func runPQInfo() error {
	root, err := readPQRootKeyFile(pqInfoKeyfile)
	if err != nil {
		return err
	}

	public, err := resolvePQSalt(root.public, pqInfoSalt)
	if err != nil {
		return err
	}
	return printPQKeyInfo(os.Stdout, public)
}

func runPQAddress() error {
	publicMaterial, err := readPQPublicKeyFile(pqAddressPubkeyfile)
	if err != nil {
		return err
	}

	scheme, err := parsePQScheme(pqAddressScheme)
	if err != nil {
		return err
	}
	if _, ok := basics.LookupPQScheme(scheme); !ok {
		return fmt.Errorf("%w: %q", basics.ErrPQSchemeNotSupported, scheme)
	}
	if publicMaterial.scheme != scheme {
		return fmt.Errorf("%w: public key file scheme is %q, requested %q", errPQKeyWrongType, publicMaterial.scheme, scheme)
	}

	public, err := resolvePQSalt(publicMaterial, pqAddressSalt)
	if err != nil {
		return err
	}
	return printPQKeyInfo(os.Stdout, public)
}

func runPQExport() error {
	return runPQExportWithOptions(pqExportKeyfile, pqExportMnemonicFile, pqExportDisplayMnemonic)
}

func runPQExportWithOptions(keyfile, mnemonicFile string, displayMnemonic bool) error {
	if mnemonicFile == "" && !displayMnemonic {
		return fmt.Errorf("must specify --mnemonic-file or --display-mnemonic")
	}
	root, err := readPQRootKeyFile(keyfile)
	if err != nil {
		return err
	}

	if mnemonicFile != "" {
		if err = writePQMnemonicFile(mnemonicFile, root.scheme, root.entropy); err != nil {
			return fmt.Errorf("cannot write mnemonic to %s: %w", mnemonicFile, err)
		}
	}
	if displayMnemonic {
		if err = printPQMnemonic(os.Stdout, root.entropy); err != nil {
			return err
		}
	}
	return printPQKeyInfo(os.Stdout, root.public)
}

func runPQImport() error {
	return runPQImportWithOptions(pqImportMnemonicFile, pqImportKeyfile, pqImportDisplayMnemonic)
}

func runPQImportWithOptions(mnemonicFile, keyfile string, displayMnemonic bool) error {
	scheme, entropy, err := readPQMnemonicFile(mnemonicFile)
	if err != nil {
		return fmt.Errorf("cannot read mnemonic from %s: %w", mnemonicFile, err)
	}

	root, err := rootMaterialFromEntropy(scheme, entropy)
	if err != nil {
		return err
	}

	if err = writePQRootKeyFile(keyfile, root); err != nil {
		return fmt.Errorf("cannot write private key to %s: %w", keyfile, err)
	}
	if displayMnemonic {
		if err = printPQMnemonic(os.Stdout, entropy); err != nil {
			return err
		}
	}
	return printPQKeyInfo(os.Stdout, root.public)
}

func runPQSign() error {
	return runPQSignWithOptions(pqSignOptions{
		keyfile:   pqSignKeyfile,
		mnemonic:  pqSignMnemonic,
		scheme:    pqSignScheme,
		txfile:    pqSignTxfile,
		outfile:   pqSignOutfile,
		salt:      pqSignSalt,
		overwrite: pqSignOverwrite,
	})
}

func runPQSignWithOptions(opts pqSignOptions) error {
	var signing pqSigningMaterial
	var err error
	switch {
	case opts.keyfile != "" && opts.mnemonic != "":
		return errors.New("cannot specify both --keyfile and --mnemonic")
	case opts.mnemonic != "":
		entropy, seedErr := seedFromMnemonic(opts.mnemonic)
		if seedErr != nil {
			return fmt.Errorf("cannot recover PQ key entropy from mnemonic: %w", seedErr)
		}
		scheme := protocol.PQSchemeFalcon1024
		if opts.scheme != "" {
			scheme, err = parsePQScheme(opts.scheme)
			if err != nil {
				return err
			}
		}
		signing, err = derivePQSigningMaterialFromEntropy(scheme, entropy[:])
	case opts.keyfile != "":
		signing, err = readPQSigningMaterial(opts.keyfile)
	default:
		return errors.New("must specify --keyfile or --mnemonic")
	}
	if err != nil {
		return err
	}

	ops, ok := pqSchemeOpsByScheme[signing.public.scheme]
	if !ok {
		return fmt.Errorf("%w: %q", basics.ErrPQSchemeNotSupported, signing.public.scheme)
	}

	public, err := resolvePQSalt(signing.public, opts.salt)
	if err != nil {
		return err
	}
	if !public.addr.IsPQCompliant() {
		return fmt.Errorf("%w: derived address %s for salt %d", errPQSaltNotCompliant, public.addr, public.salt)
	}

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

		if signedTxnHasSignature(&stxn) {
			if !opts.overwrite {
				return errPQTxnAlreadySigned
			}
			clearSignedTxnSignatures(&stxn)
		}

		signature, signErr := ops.signTxn(signing.private, stxn.Txn)
		if signErr != nil {
			return fmt.Errorf("cannot sign transaction: %w", signErr)
		}

		stxn.PQsig = transactions.PQSig{
			Scheme:    public.scheme,
			Salt:      public.salt,
			PublicKey: slices.Clone(public.pk),
			Signature: signature,
		}
		if stxn.Txn.Sender != public.addr {
			stxn.AuthAddr = public.addr
		} else {
			stxn.AuthAddr = basics.Address{}
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

func signedTxnHasSignature(stxn *transactions.SignedTxn) bool {
	return !stxn.Sig.Blank() || !stxn.Msig.Blank() || !stxn.Lsig.Blank() || !stxn.PQsig.Blank()
}

func clearSignedTxnSignatures(stxn *transactions.SignedTxn) {
	stxn.Sig = crypto.Signature{}
	stxn.Msig = crypto.MultisigSig{}
	stxn.Lsig = transactions.LogicSig{}
	stxn.PQsig = transactions.PQSig{}
}

func printPQMnemonic(w io.Writer, entropy crypto.Seed) error {
	mnemonic, err := mnemonicFromSeed(entropy)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "PQ private key mnemonic: %s\n", mnemonic)
	return err
}

func printPQKeyInfo(w io.Writer, public pqPublicMaterial) error {
	_, err := io.WriteString(w, fmt.Sprintf(
		"PQ scheme: %s\nPQ public key: %s\nPQ address salt: %d\nPQ address: %s\nPQ address compliant: %t\n",
		formatPQScheme(public.scheme),
		base64.StdEncoding.EncodeToString(public.pk),
		public.salt,
		public.addr,
		public.addr.IsPQCompliant(),
	))
	return err
}

func exitOnError(err error) {
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
