package generator

import (
	"fmt"
	"math/rand"

	"github.com/spf13/cobra"
)

// DaemonCmd starts a block generator daemon.
var DaemonCmd *cobra.Command

func init() {
	rand.Seed(12345)

	var configFile string
	var port uint64

	DaemonCmd = &cobra.Command{
		Use:   "daemon",
		Short: "Start the generator daemon in standalone mode.",
		Run: func(cmd *cobra.Command, args []string) {
			addr := fmt.Sprintf(":%d", port)
			srv, _ := MakeServer(configFile, addr)
			srv.ListenAndServe()
		},
	}

	DaemonCmd.Flags().StringVarP(&configFile, "config", "c", "", "Specify the block configuration yaml file.")
	DaemonCmd.Flags().Uint64VarP(&port, "port", "p", 4010, "Port to start the server at.")

	DaemonCmd.MarkFlagRequired("config")
}
