package nodecontrol

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStopAlgodErrorAlreadyStopped(t *testing.T) {
	nodeController := MakeNodeController("", ".")
	err := nodeController.StopAlgod()
	var e *NodeAlreadyStoppedError
	require.True(t, errors.As(err, &e))
}

func TestStopAlgodErrorInvalidDirectory(t *testing.T) {
	nodeController := MakeNodeController("", "[][]")
	err := nodeController.StopAlgod()
	var e *InvalidDataDirError
	require.True(t, errors.As(err, &e))
}
