// Copyright (C) 2019-2023 Algorand, Inc.
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

package catchpointdb

import (
	"context"
	"database/sql"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type reader struct {
	q db.Queryable
}

func makeReader(q db.Queryable) Reader {
	return &reader{q}
}

// Version implements Reader
func (r *reader) GetVersion(ctx context.Context, staging bool) (version uint64, err error) {
	if staging {
		// writing the version of the catchpoint file start only on ver >= CatchpointFileVersionV7.
		// in case the catchpoint version does not exists ReadCatchpointStateUint64 returns 0
		version, err = r.ReadCatchpointStateUint64(context.Background(), CatchpointStateCatchupVersion)
		if err != nil {
			return 0, err
		}
		return version, err
	}

	versionAsInt32, err := db.GetUserVersion(ctx, r.q)
	if err != nil {
		return 0, err
	}
	version = uint64(versionAsInt32)

	return
}

// GetCatchpoint implements Reader
func (r *reader) GetCatchpoint(ctx context.Context, round basics.Round) (fileName string, catchpoint string, fileSize int64, err error) {
	err = r.q.QueryRowContext(ctx, "SELECT filename, catchpoint, filesize FROM storedcatchpoints WHERE round=?", int64(round)).Scan(&fileName, &catchpoint, &fileSize)
	return
}

// GetOldestCatchpointFiles implements Reader
func (r *reader) GetOldestCatchpointFiles(ctx context.Context, fileCount int, filesToKeep int) (fileNames map[basics.Round]string, err error) {
	err = db.Retry(func() (err error) {
		query := "SELECT round, filename FROM storedcatchpoints WHERE pinned = 0 and round <= COALESCE((SELECT round FROM storedcatchpoints WHERE pinned = 0 ORDER BY round DESC LIMIT ?, 1),0) ORDER BY round ASC LIMIT ?"
		rows, err := r.q.QueryContext(ctx, query, filesToKeep, fileCount)
		if err != nil {
			return err
		}
		defer rows.Close()

		fileNames = make(map[basics.Round]string)
		for rows.Next() {
			var fileName string
			var round basics.Round
			err = rows.Scan(&round, &fileName)
			if err != nil {
				return err
			}
			fileNames[round] = fileName
		}

		return rows.Err()
	})
	if err != nil {
		fileNames = nil
	}
	return
}

// ReadCatchpointStateString implements Reader
func (r *reader) ReadCatchpointStateString(ctx context.Context, stateName CatchpointState) (val string, err error) {
	err = db.Retry(func() (err error) {
		query := "SELECT strval FROM catchpointstate WHERE id=?"
		var v sql.NullString
		err = r.q.QueryRowContext(ctx, query, stateName).Scan(&v)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}

		if v.Valid {
			val = v.String
		}
		return nil
	})
	return val, err
}

// ReadCatchpointStateUint64 implements Reader
func (r *reader) ReadCatchpointStateUint64(ctx context.Context, stateName CatchpointState) (val uint64, err error) {
	err = db.Retry(func() (err error) {
		query := "SELECT intval FROM catchpointstate WHERE id=?"
		var v sql.NullInt64
		err = r.q.QueryRowContext(ctx, query, stateName).Scan(&v)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if v.Valid {
			val = uint64(v.Int64)
		}
		return nil
	})
	return val, err
}

// SelectUnfinishedCatchpoints implements Reader
func (r *reader) SelectUnfinishedCatchpoints(ctx context.Context) ([]UnfinishedCatchpointRecord, error) {
	var res []UnfinishedCatchpointRecord

	f := func() error {
		query := "SELECT round, blockhash FROM unfinishedcatchpoints ORDER BY round"
		rows, err := r.q.QueryContext(ctx, query)
		if err != nil {
			return err
		}

		// Clear `res` in case this function is repeated.
		res = res[:0]
		for rows.Next() {
			var record UnfinishedCatchpointRecord
			var blockHash []byte
			err = rows.Scan(&record.Round, &blockHash)
			if err != nil {
				return err
			}
			copy(record.BlockHash[:], blockHash)
			res = append(res, record)
		}

		return nil
	}
	err := db.Retry(f)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// SelectCatchpointFirstStageInfo implements Reader
func (r *reader) SelectCatchpointFirstStageInfo(ctx context.Context, round basics.Round) (CatchpointFirstStageInfo, bool, error) {
	var data []byte
	f := func() error {
		query := "SELECT info FROM catchpointfirststageinfo WHERE round=?"
		err := r.q.QueryRowContext(ctx, query, round).Scan(&data)
		if err == sql.ErrNoRows {
			data = nil
			return nil
		}
		return err
	}
	err := db.Retry(f)
	if err != nil {
		return CatchpointFirstStageInfo{}, false, err
	}

	if data == nil {
		return CatchpointFirstStageInfo{}, false, nil
	}

	var res CatchpointFirstStageInfo
	err = protocol.Decode(data, &res)
	if err != nil {
		return CatchpointFirstStageInfo{}, false, err
	}

	return res, true, nil
}

// SelectOldCatchpointFirstStageInfoRounds implements Reader
func (r *reader) SelectOldCatchpointFirstStageInfoRounds(ctx context.Context, maxRound basics.Round) ([]basics.Round, error) {
	var res []basics.Round

	f := func() error {
		query := "SELECT round FROM catchpointfirststageinfo WHERE round <= ?"
		rows, err := r.q.QueryContext(ctx, query, maxRound)
		if err != nil {
			return err
		}

		// Clear `res` in case this function is repeated.
		res = res[:0]
		for rows.Next() {
			var r basics.Round
			err = rows.Scan(&r)
			if err != nil {
				return err
			}
			res = append(res, r)
		}

		return nil
	}
	err := db.Retry(f)
	if err != nil {
		return nil, err
	}

	return res, nil
}
