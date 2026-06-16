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
	pqGenerateScheme     = string(protocol.PQSchemeFalcon1024)
	pqGenerateKeyfile    string
	pqGeneratePubkeyfile string

	pqInfoKeyfile string
	pqInfoSalt    = "canonical"

	pqAddressPubkeyfile string
	pqAddressScheme     = string(protocol.PQSchemeFalcon1024)
	pqAddressSalt       = "canonical"

	pqExportKeyfile      string
	pqExportMnemonicFile string

	pqImportMnemonicFile string
	pqImportKeyfile      string

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
	pqExportCmd.Flags().StringVar(&pqExportMnemonicFile, "mnemonic-file", "", "Mnemonic output filename")
	mustMarkFlagRequired(pqExportCmd, "keyfile")
	mustMarkFlagRequired(pqExportCmd, "mnemonic-file")

	pqImportCmd.Flags().StringVar(&pqImportMnemonicFile, "mnemonic-file", "", "Mnemonic input filename")
	pqImportCmd.Flags().StringVar(&pqImportKeyfile, "keyfile", "", "Private key filename")
	mustMarkFlagRequired(pqImportCmd, "mnemonic-file")
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
	root, err := generatePQRoot(protocol.PQScheme(pqGenerateScheme), crypto.SystemRNG)
	if err != nil {
		return fmt.Errorf("cannot generate PQ key: %w", err)
	}
	defer wipePQRootMaterial(&root)

	if err = writePQRootKeyFile(pqGenerateKeyfile, root); err != nil {
		return err
	}
	if pqGeneratePubkeyfile != "" {
		if err = writePQPublicKeyFile(pqGeneratePubkeyfile, root.public); err != nil {
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
	defer wipePQRootMaterial(&root)

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

	scheme := protocol.PQScheme(pqAddressScheme)
	if _, err = lookupPQScheme(scheme); err != nil {
		return err
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
	return runPQExportWithOptions(pqExportKeyfile, pqExportMnemonicFile)
}

func runPQExportWithOptions(keyfile, mnemonicFile string) error {
	root, err := readPQRootKeyFile(keyfile)
	if err != nil {
		return err
	}
	defer wipePQRootMaterial(&root)

	if err = writePQMnemonicFile(mnemonicFile, root.scheme, root.entropy); err != nil {
		return fmt.Errorf("cannot write mnemonic to %s: %w", mnemonicFile, err)
	}
	return printPQKeyInfo(os.Stdout, root.public)
}

func runPQImport() error {
	return runPQImportWithOptions(pqImportMnemonicFile, pqImportKeyfile)
}

func runPQImportWithOptions(mnemonicFile, keyfile string) error {
	scheme, entropy, err := readPQMnemonicFile(mnemonicFile)
	if err != nil {
		return fmt.Errorf("cannot read mnemonic from %s: %w", mnemonicFile, err)
	}
	defer zeroBytes(entropy[:])

	root, err := rootMaterialFromEntropy(scheme, entropy)
	if err != nil {
		return err
	}
	defer wipePQRootMaterial(&root)

	if err = writePQRootKeyFile(keyfile, root); err != nil {
		return fmt.Errorf("cannot write private key to %s: %w", keyfile, err)
	}
	return printPQKeyInfo(os.Stdout, root.public)
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
	signing, err := readPQSigningMaterial(opts.keyfile)
	if err != nil {
		return err
	}
	defer wipePQSigningMaterial(&signing)

	ops, err := opsForPQScheme(signing.public.scheme)
	if err != nil {
		return err
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

		signature, signErr := ops.signTxn(signing.private, stxn.Txn)
		if signErr != nil {
			return fmt.Errorf("cannot sign transaction: %w", signErr)
		}

		stxn.PQSig = transactions.PQSig{
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

	if err = writeFile(opts.outfile, outBytes, 0600); err != nil {
		return fmt.Errorf("cannot write signed transactions to %s: %w", opts.outfile, err)
	}
	return nil
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

func printPQKeyInfo(w io.Writer, public pqPublicMaterial) error {
	_, err := io.WriteString(w, fmt.Sprintf(
		"PQ scheme: %s\nPQ public key: %s\nPQ address salt: %d\nPQ address: %s\nPQ address compliant: %t\n",
		public.scheme,
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
