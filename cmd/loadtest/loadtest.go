// Copyright 2024 Google LLC. All Rights Reserved.
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

// loadtest is an executable that connects to a witness and determines how many
// updates it can handle before it is unable to maintain a given latency.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	wit_client "github.com/transparency-dev/witness/client/http"
	"github.com/transparency-dev/witness/internal/witness"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	logCount     = flag.Int("log_count", 50, "The number of logs to use")
	numExtraSigs = flag.Uint("num_extra_sigs", 0, "The number of additional signatures to put on each checkpoint sent to the witness")
	target       = flag.String("target", "", "Base URL of the witness to load test")
	timeout      = flag.Duration("timeout", time.Second, "How much witness latency terminates the load test")
	startQPS     = flag.Uint("start_qps", 5, "Starting QPS")
	maxQPS       = flag.Uint("max_qps", 0, "Max QPS, set to zero for no maximum")
	successQPS   = flag.Uint("success_qps", 32000, "If the witness can take this much QPS then the load test ends")
	ignorePushback = flag.Bool("ignore_pushback", false, "Whether to ignore 429 errors from the witness")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx := context.Background()

	logs := newInMemoryLogs(*logCount)
	klog.Infof("Log config stanza:\n%s", logs.config())

	if *target == "" {
		klog.Info("--target not provided, exiting")
		os.Exit(0)
	}

	u, err := url.Parse(*target)
	if err != nil {
		klog.Exitf("--target not a URL: %v", err)
	}

	hc := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConnsPerHost:   5,
			MaxIdleConns:          5,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: *timeout,
	}

	c := wit_client.NewWitness(u, hc)

	updateLatencyChan := make(chan time.Duration, *logCount)
	thr := newThrottle(*startQPS, *maxQPS)
	go thr.run(ctx)

	for _, l := range logs.logs {
		go func(ctx context.Context, l *inMemoryLog) {
			for {
				select {
				case <-ctx.Done():
					return
				case <-thr.tokenChan:
					nextCP, nextSize, proof := l.next()
					startTime := time.Now()
					oldSize := l.witnessedSize
					if _, curSize, err := c.Update(ctx, oldSize, nextCP, proof); err != nil {
						if !errors.Is(err, witness.ErrCheckpointStale) {
							switch {
							case errors.Is(err, witness.ErrPushback) && *ignorePushback:
								klog.V(1).Infof("Got pushback, ignoring.")
								continue
							default:
								klog.Exitf("Failed to update to checkpoint: %v\n%s", err, nextCP)
							}
						}
						l.syncToSize(curSize)
						continue
					}
					l.witnessedSize = nextSize
					klog.V(1).Infof("Updated %s from %d → %d", l.o, oldSize, nextSize)
					elapsed := time.Since(startTime)
					updateLatencyChan <- elapsed
				}
			}
		}(ctx, l)
	}

	const samples = 25
	for {
		var totalDuration time.Duration
		for range samples {
			select {
			case <-ctx.Done():
				return
			case l := <-updateLatencyChan:
				klog.V(1).Infof("Single update: %s", l)
				totalDuration += l
			}
		}
		avgDuration := totalDuration / samples
		klog.Infof("Average update time is %s with throttle %s", avgDuration, thr)
		if avgDuration < *timeout && thr.oversupply == 0 {
			if thr.opsPerSecond > *successQPS {
				klog.Infof("Exiting successfully: QPS reached %d", thr.opsPerSecond)
				os.Exit(0)
			}
			thr.increase()
		}
		if avgDuration > *timeout {
			klog.Exitf("Witness took %s on average to handle last %d requests with throttle: %s", avgDuration, samples, thr)
		}
	}
}

func newInMemoryLogs(n int) inMemoryLogs {
	logs := make([]*inMemoryLog, n)
	for i := range n {
		logs[i] = newInMemoryLog(i)
	}
	return inMemoryLogs{
		logs: logs,
	}
}

type inMemoryLogs struct {
	logs []*inMemoryLog
}

func (ls inMemoryLogs) config() string {
	s := "- Logs\n"
	for _, l := range ls.logs {
		s += l.config()
	}
	return s
}

// newInMemoryLog creates a new in memory log that is initially empty. Given a particular
// seed, the log will act deterministically in all parts of its behaviour, including signing
// key generation, and leaf contents.
func newInMemoryLog(seed int) *inMemoryLog {
	origin := fmt.Sprintf("example.com/inmemorylog/%d", seed)

	var cha8seed [32]byte
	cha8seed[0] = byte(seed)
	cha8 := rand.NewChaCha8(cha8seed)

	signers := make([]note.Signer, 0, *numExtraSigs+1)
	skey, vkey, err := note.GenerateKey(cha8, origin)
	if err != nil {
		klog.Exitf("Failed to generate keys: %v", err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		klog.Exitf("Failed to generate signer: %v", err)
	}
	signers = append(signers, s)
	for range *numExtraSigs {
		skey, _, err := note.GenerateKey(cha8, origin)
		if err != nil {
			klog.Exitf("Failed to generate keys: %v", err)
		}
		s, err := note.NewSigner(skey)
		if err != nil {
			klog.Exitf("Failed to generate signer: %v", err)
		}
		signers = append(signers, s)
	}
	genLeaf := func(i uint64) []byte {
		return []byte(fmt.Sprintf("log %d, leaf %d", seed, i))
	}
	rf := compact.RangeFactory{
		Hash: rfc6962.DefaultHasher.HashChildren,
	}
	return &inMemoryLog{
		o:       origin,
		s:       signers,
		vkey:    vkey,
		genLeaf: genLeaf,
		state:   rf.NewEmptyRange(0),
		store:   make(map[string][]byte),
	}
}

// inMemoryLog determinstically generates log contents using genLeaf
// and stores all of the hashes in memory. This may need rewriting as
// memory usage is likely to be a concern for large logs.
//
// Anything using the hashes field was taken from
// https://github.com/transparency-dev/merkle/blob/main/testonly/tree.go
type inMemoryLog struct {
	o       string
	s       []note.Signer
	vkey    string
	genLeaf func(uint64) []byte

	mu            sync.Mutex
	size          uint64
	witnessedSize uint64
	state         *compact.Range
	store         map[string][]byte // Node hashes, indexed by node (level, index).
	hasSynced     bool              // Set to true if this log has been clocked forward to synchronise with witness state - this should happen at most once.
}

func (l *inMemoryLog) appendLocked(hash []byte) {
	err := l.state.Append(hash, func(id compact.NodeID, h []byte) {
		l.store[fmt.Sprintf("%x/%x", id.Level, id.Index)] = h
	})
	if err != nil {
		klog.Exit(err)
	}
	l.size++
}

// syncToSize sets the state of this log to the given witness size.
//
// This is to allow for external long-running/persisted witnesses to be tested
// with this loadtest command. Since the underlying in-memory logs are built
// deterministically, the tree state from previous loadtest runs can be recreated.
func (l *inMemoryLog) syncToSize(witSize uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.hasSynced {
		klog.Exitf("Log %s of size %d asked to re-sync to %d", l.o, l.size, witSize)
	}
	l.hasSynced = true

	klog.V(1).Infof("Log %s sync'd to witness size %d", l.o, witSize)

	for l.size < witSize {
		leaf := l.genLeaf(l.size)
		leafHash := rfc6962.DefaultHasher.HashLeaf(leaf)
		l.appendLocked(leafHash)
	}
	l.witnessedSize = witSize
}

// Hash returns the current root hash of the tree.
func (l *inMemoryLog) Hash() []byte {
	r, err := l.state.GetRootHash(nil)
	if err != nil {
		klog.Fatal(err)
	}
	return r
}

func (l *inMemoryLog) getNodes(ids []compact.NodeID) [][]byte {
	hashes := make([][]byte, len(ids))
	for i, id := range ids {
		hashes[i] = l.store[fmt.Sprintf("%x/%x", id.Level, id.Index)]
	}
	return hashes
}

// next grows the tree by one leaf and returns a new checkpoint, and a consistency
// proof from the previous size.
func (l *inMemoryLog) next() (cpSigned []byte, cpSize uint64, consProof [][]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()

	leaf := l.genLeaf(l.size)
	leafHash := rfc6962.DefaultHasher.HashLeaf(leaf)
	l.appendLocked(leafHash)

	cp := log.Checkpoint{
		Origin: l.o,
		Size:   l.size,
		Hash:   l.Hash(),
	}
	cpRaw := cp.Marshal()
	cpSigned, err := note.Sign(&note.Note{Text: string(cpRaw)}, l.s...)
	if err != nil {
		klog.Exitf("Failed to sign checkpoint: %v", err)
	}

	nodes, err := proof.Consistency(l.witnessedSize, l.size)
	if err != nil {
		klog.Exitf("Failed to determine consistency proof: %v", err)
	}
	consProof, err = nodes.Rehash(l.getNodes(nodes.IDs), rfc6962.DefaultHasher.HashChildren)
	if err != nil {
		klog.Exitf("Failed to build consistency proof: %v", err)
	}
	return cpSigned, l.size, consProof
}

func (l *inMemoryLog) config() string {
	stanza := `
  - Origin: %s
    URL: http://%s/
    PublicKey: %s
    Feeder: none
`
	return fmt.Sprintf(stanza, l.o, l.o, l.vkey)
}

func newThrottle(opsPerSecond, maxOpsPerSecond uint) *throttle {
	return &throttle{
		opsPerSecond:    opsPerSecond,
		maxOpsPerSecond: maxOpsPerSecond,
		tokenChan:       make(chan bool, opsPerSecond),
	}
}

type throttle struct {
	opsPerSecond    uint
	maxOpsPerSecond uint
	tokenChan       chan bool

	oversupply int
}

func (t *throttle) increase() {
	tokenCount := t.opsPerSecond
	delta := float64(tokenCount) * 0.1
	if delta < 1 {
		delta = 1
	}
	t.opsPerSecond = min(t.maxOpsPerSecond, tokenCount+uint(delta))
}

func (t *throttle) run(ctx context.Context) {
	interval := time.Second
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-ctx.Done(): //context cancelled
			return
		case <-ticker.C:
			tokenCount := int(t.opsPerSecond)
			timeout := time.After(interval)
			dribble := time.Second / time.Duration(t.opsPerSecond)
		Loop:
			for i := uint(0); i < t.opsPerSecond; i++ {
				select {
				case t.tokenChan <- true:
					tokenCount--
					select {
					case <-time.After(dribble):
					case <-timeout:
						break Loop
					}
				case <-timeout:
					break Loop
				}
			}
			t.oversupply = tokenCount
		}
	}
}

func (t *throttle) String() string {
	return fmt.Sprintf("Current max: %d/s. Oversupply in last second: %d", t.opsPerSecond, t.oversupply)
}
