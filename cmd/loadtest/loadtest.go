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
	"flag"
	"fmt"
	"math/rand/v2"
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
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	logCount   = flag.Int("log_count", 50, "The number of logs to use")
	target     = flag.String("target", "", "Base URL of the witness to load test")
	timeout    = flag.Duration("timeout", time.Second, "How much witness latency terminates the load test")
	startQPS   = flag.Uint("start_qps", 5, "Starting QPS")
	successQPS = flag.Uint("success_qps", 32000, "If the witness can take this much QPS then the load test ends")
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
	c := wit_client.NewWitness(u, http.DefaultClient)

	// Ensure all log sizes match the size that witnesses expect
	for _, l := range logs.logs {
		logID := log.ID(l.o)
		var witSize uint64
		if rawCP, err := c.GetLatestCheckpoint(ctx, logID); err != nil {
			if err != os.ErrNotExist {
				klog.Exitf("Failed to get latest checkpoint: %v", err)
			}
		} else {
			v, err := note.NewVerifier(l.vkey)
			if err != nil {
				klog.Exitf("Failed to create verifier: %v", err)
			}
			cp, _, _, err := log.ParseCheckpoint(rawCP, l.o, v)
			if err != nil {
				klog.Exitf("Failed to parse checkpoint: %v", err)
			}
			witSize = cp.Size
		}
		l.init(witSize)
	}

	updateLatencyChan := make(chan time.Duration, *logCount)
	thr := newThrottle(*startQPS)
	go thr.run(ctx)

	for _, l := range logs.logs {
		go func(ctx context.Context, l *inMemoryLog) {
			for {
				select {
				case <-ctx.Done():
					return
				case <-thr.tokenChan:
					nextCP, proof := l.next()
					startTime := time.Now()
					if _, err := c.Update(ctx, log.ID(l.o), nextCP, proof); err != nil {
						klog.Exitf("Failed to update to checkpoint: %v\n%s", err, nextCP)
					}
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

	skey, vkey, err := note.GenerateKey(cha8, origin)
	if err != nil {
		klog.Exitf("Failed to generate keys: %v", err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		klog.Exitf("Failed to generate signer: %v", err)
	}
	genLeaf := func(i uint64) []byte {
		return []byte(fmt.Sprintf("log %d, leaf %d", seed, i))
	}
	return &inMemoryLog{
		o:       origin,
		s:       s,
		vkey:    vkey,
		genLeaf: genLeaf,
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
	s       note.Signer
	vkey    string
	genLeaf func(uint64) []byte

	mu     sync.Mutex
	size   uint64
	hashes [][][]byte // Node hashes, indexed by node (level, index).
}

func (l *inMemoryLog) appendLocked(hash []byte) {
	level := 0
	for ; (l.size>>level)&1 == 1; level++ {
		row := append(l.hashes[level], hash)
		hash = rfc6962.DefaultHasher.HashChildren(row[len(row)-2], hash)
		l.hashes[level] = row
	}
	if level > len(l.hashes) {
		panic("gap in tree appends")
	} else if level == len(l.hashes) {
		l.hashes = append(l.hashes, nil)
	}

	l.hashes[level] = append(l.hashes[level], hash)
	l.size++
}

// init sets the initial state of this log to the size from the witness.
func (l *inMemoryLog) init(witSize uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()

	klog.Infof("%s initializing to size %d", l.o, witSize)

	for i := uint64(0); i < witSize; i++ {
		leaf := l.genLeaf(i)
		leafHash := rfc6962.DefaultHasher.HashLeaf(leaf)
		l.appendLocked(leafHash)
	}
}

// Hash returns the current root hash of the tree.
func (l *inMemoryLog) Hash() []byte {
	return l.HashAt(l.size)
}

// HashAt returns the root hash at the given size.
// Requires 0 <= size <= Size(), otherwise panics.
func (l *inMemoryLog) HashAt(size uint64) []byte {
	if size == 0 {
		return rfc6962.DefaultHasher.EmptyRoot()
	}
	hashes := l.getNodes(compact.RangeNodes(0, size, nil))

	hash := hashes[len(hashes)-1]
	for i := len(hashes) - 2; i >= 0; i-- {
		hash = rfc6962.DefaultHasher.HashChildren(hashes[i], hash)
	}
	return hash
}

func (l *inMemoryLog) getNodes(ids []compact.NodeID) [][]byte {
	hashes := make([][]byte, len(ids))
	for i, id := range ids {
		hashes[i] = l.hashes[id.Level][id.Index]
	}
	return hashes
}

// next grows the tree by one leaf and returns a new checkpoint, and a consistency
// proof from the previous size.
func (l *inMemoryLog) next() (cpSigned []byte, consProof [][]byte) {
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
	cpSigned, err := note.Sign(&note.Note{Text: string(cpRaw)}, l.s)
	if err != nil {
		klog.Exitf("Failed to sign checkpoint: %v", err)
	}

	nodes, err := proof.Consistency(l.size-1, l.size)
	if err != nil {
		klog.Exitf("Failed to determine consistency proof: %v", err)
	}
	consProof, err = nodes.Rehash(l.getNodes(nodes.IDs), rfc6962.DefaultHasher.HashChildren)
	if err != nil {
		klog.Exitf("Failed to build consistency proof: %v", err)
	}
	return cpSigned, consProof
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

func newThrottle(opsPerSecond uint) *throttle {
	return &throttle{
		opsPerSecond: opsPerSecond,
		tokenChan:    make(chan bool, opsPerSecond),
	}
}

type throttle struct {
	opsPerSecond uint
	tokenChan    chan bool

	oversupply int
}

func (t *throttle) increase() {
	tokenCount := t.opsPerSecond
	delta := float64(tokenCount) * 0.1
	if delta < 1 {
		delta = 1
	}
	t.opsPerSecond = tokenCount + uint(delta)
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
		Loop:
			for i := uint(0); i < t.opsPerSecond; i++ {
				select {
				case t.tokenChan <- true:
					tokenCount--
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
