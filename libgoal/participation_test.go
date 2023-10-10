package libgoal

import (
	"github.com/algorand/go-algorand/data/account"
	"reflect"
	"testing"
)

func TestGenParticipationKeysTo(t *testing.T) {
	type args struct {
		address     string
		firstValid  uint64
		lastValid   uint64
		keyDilution uint64
		outDir      string
		installFunc func(keyPath string) error
	}
	tests := []struct {
		name         string
		args         args
		wantPart     account.Participation
		wantFilePath string
		wantErr      bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPart, gotFilePath, err := GenParticipationKeysTo(tt.args.address, tt.args.firstValid, tt.args.lastValid, tt.args.keyDilution, tt.args.outDir, tt.args.installFunc)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenParticipationKeysTo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPart, tt.wantPart) {
				t.Errorf("GenParticipationKeysTo() gotPart = %v, want %v", gotPart, tt.wantPart)
			}
			if gotFilePath != tt.wantFilePath {
				t.Errorf("GenParticipationKeysTo() gotFilePath = %v, want %v", gotFilePath, tt.wantFilePath)
			}
		})
	}
}