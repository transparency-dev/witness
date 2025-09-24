// Copyright 2021 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package omniwitness

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/rfc6962"
	sclient "github.com/transparency-dev/serverless-log/client"
	"github.com/transparency-dev/serverless-log/testdata"
	"github.com/transparency-dev/witness/internal/feeder"
	"github.com/transparency-dev/witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
)

func TestFeedOnce(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		desc     string
		submitCP []byte
		update   UpdateFn
		wantErr  bool
	}{
		{
			desc:     "works",
			submitCP: testdata.Checkpoint(t, 2),
			update: (&fakeWitness{
				latestCP: testdata.Checkpoint(t, 1),
			}).Update,
		}, {
			desc:     "works after a few failures",
			submitCP: testdata.Checkpoint(t, 2),
			update: (&slowWitness{
				fakeWitness: &fakeWitness{
					latestCP: testdata.Checkpoint(t, 1),
				},
				times: 2,
			}).Update,
		}, {
			desc:     "works - TOFU feed",
			submitCP: testdata.Checkpoint(t, 2),
			update:   (&fakeWitness{}).Update,
		}, {
			desc:     "works - submitCP == latest",
			submitCP: testdata.Checkpoint(t, 1),
			update: (&fakeWitness{
				latestCP: testdata.Checkpoint(t, 1),
			}).Update,
		},
	} {
		sCP := mustOpenCheckpoint(t, test.submitCP, testdata.TestLogOrigin, testdata.LogSigVerifier(t))
		f := testdata.HistoryFetcher(sCP.Size)
		fetchProof := func(ctx context.Context, from uint64, to log.Checkpoint) ([][]byte, error) {
			if from == 0 {
				return [][]byte{}, nil
			}
			pb := sclient.NewProofBuilderForSize(ctx, to.Size, rfc6962.DefaultHasher.HashChildren, f.Fetcher())

			conP, err := pb.ConsistencyProof(ctx, from, to.Size)
			if err != nil {
				return nil, fmt.Errorf("failed to create proof for (%d -> %d): %v", from, to.Size, err)
			}
			return conP, nil
		}

		src := feeder.Source{
			FetchProof:     fetchProof,
			LogOrigin:      testdata.TestLogOrigin,
			LogSigVerifier: testdata.LogSigVerifier(t),
		}
		t.Run(test.desc, func(t *testing.T) {
			_, err := feedOnce(ctx, 0, test.update, test.submitCP, src)
			gotErr := err != nil
			if test.wantErr != gotErr {
				t.Fatalf("Got err %v, want err %t", err, test.wantErr)
			}
		})
	}
}

type slowWitness struct {
	*fakeWitness
	times int
}

func (sw *slowWitness) Update(_ context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error) {
	if sw.times > 0 {
		sw.times = sw.times - 1
		return nil, oldSize, fmt.Errorf("will fail for %d more calls (%w)", sw.times, witness.ErrCheckpointStale)
	}
	sw.latestCP = newCP

	return []byte("sig"), 0, nil
}

type fakeWitness struct {
	latestCP     []byte
	rejectUpdate bool
}

func (fw *fakeWitness) Update(_ context.Context, oldSize uint64, newCP []byte, proof [][]byte) ([]byte, uint64, error) {
	if fw.rejectUpdate {
		return nil, 0, errors.New("computer says 'no'")
	}

	fw.latestCP = newCP

	return fw.latestCP, 0, nil
}

func mustOpenCheckpoint(t *testing.T, cp []byte, origin string, v note.Verifier) log.Checkpoint {
	t.Helper()
	c, _, _, err := log.ParseCheckpoint(cp, origin, v)
	if err != nil {
		t.Fatalf("Failed to open checkpoint: %v", err)
	}
	return *c
}
