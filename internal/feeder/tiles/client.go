// Copyright 2026 The Tessera authors. All Rights Reserved.
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

// This file contains a stripped down version of the client implementation from Tessera.

package tiles

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/sync/errgroup"
)

const (
	// checkpointPath is the location of the file containing the log checkpoint.
	checkpointPath = "checkpoint"
	// tileHeight is the maximum number of levels Merkle tree levels a tile represents.
	// This is fixed at 8 by tlog-tile spec.
	tileHeight = 8
	// tileWidth is the maximum number of hashes which can be present in the bottom row of a tile.
	tileWidth = 1 << tileHeight
)

type tileFetcherFunc func(ctx context.Context, level, index uint64, p uint8) ([]byte, error)

// newHTTPFetcher creates a new HTTPFetcher for the log rooted at the given URL, using
// the provided HTTP client.
//
// rootURL should end in a trailing slash.
// c may be nil, in which case http.DefaultClient will be used.
func newHTTPFetcher(rootURL *url.URL, c *http.Client) (*httpFetcher, error) {
	if !strings.HasSuffix(rootURL.String(), "/") {
		rootURL.Path += "/"
	}
	if c == nil {
		c = http.DefaultClient
	}
	return &httpFetcher{
		c:       c,
		rootURL: rootURL,
	}, nil
}

// httpFetcher knows how to fetch log artifacts from a log being served via HTTP.
type httpFetcher struct {
	c          *http.Client
	rootURL    *url.URL
	authHeader string
}

// SetAuthorizationHeader sets the value to be used with an Authorization: header
// for every request made by this fetcher.
func (h *httpFetcher) SetAuthorizationHeader(v string) {
	h.authHeader = v
}

func (h httpFetcher) fetch(ctx context.Context, p string) ([]byte, error) {
	u, err := h.rootURL.Parse(p)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("NewRequestWithContext(%q): %v", u.String(), err)
	}
	if h.authHeader != "" {
		req.Header.Add("Authorization", h.authHeader)
	}
	r, err := h.c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get(%q): %v", u.String(), err)
	}
	switch r.StatusCode {
	case http.StatusOK:
		// All good, continue below
	case http.StatusNotFound:
		// Need to return ErrNotExist here, by contract.
		return nil, fmt.Errorf("get(%q): %w", u.String(), os.ErrNotExist)
	default:
		return nil, fmt.Errorf("get(%q): %v", u.String(), r.StatusCode)
	}

	defer func() {
		_ = r.Body.Close()
	}()
	return io.ReadAll(r.Body)
}

func (h httpFetcher) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	return h.fetch(ctx, checkpointPath)
}

// partialOrFullResource calls the provided function with the provided partial resource size value in order to fetch and return a static resource.
// If p is non-zero, and f returns os.ErrNotExist, this function will try to fetch the corresponding full resource by calling f a second time passing
// zero.
func partialOrFullResource(ctx context.Context, p uint8, f func(context.Context, uint8) ([]byte, error)) ([]byte, error) {
	sRaw, err := f(ctx, p)
	switch {
	case errors.Is(err, os.ErrNotExist) && p == 0:
		return sRaw, fmt.Errorf("resource not found: %w", err)
	case errors.Is(err, os.ErrNotExist) && p > 0:
		// It could be that the partial resource was removed as the tree has grown and a full resource is now present, so try
		// falling back to that.
		sRaw, err = f(ctx, 0)
		if err != nil {
			return sRaw, fmt.Errorf("neither partial nor full resource found: %w", err)
		}
		return sRaw, nil
	case err != nil:
		return sRaw, fmt.Errorf("failed to fetch resource: %w", err)
	default:
		return sRaw, nil
	}
}

func (h httpFetcher) ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
	return partialOrFullResource(ctx, p, func(ctx context.Context, p uint8) ([]byte, error) {
		return h.fetch(ctx, tilePath(l, i, p))
	})
}

// proofBuilder knows how to build inclusion and consistency proofs from tiles.
// Since the tiles commit only to immutable nodes, the job of building proofs is slightly
// more complex as proofs can touch "ephemeral" nodes, so these need to be synthesized.
// This object constructs a cache internally to make it efficient for multiple operations
// at a given tree size.
type proofBuilder struct {
	treeSize  uint64
	nodeCache *nodeCache
}

// newProofBuilder creates a new proofBuilder object for a given tree size.
// The returned proofBuilder can be re-used for proofs related to a given tree size, and is
// thread-safe.
func newProofBuilder(ctx context.Context, treeSize uint64, f func(context.Context, uint64, uint64, uint8) ([]byte, error)) (*proofBuilder, error) {
	pb := &proofBuilder{
		treeSize:  treeSize,
		nodeCache: newNodeCache(f, treeSize),
	}
	return pb, nil
}

// InclusionProof constructs an inclusion proof for the leaf at index in a tree of
// the given size.
func (pb *proofBuilder) InclusionProof(ctx context.Context, index uint64) ([][]byte, error) {
	nodes, err := proof.Inclusion(index, pb.treeSize)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate inclusion proof node list: %v", err)
	}
	return pb.materialiseProof(ctx, nodes)
}

// ConsistencyProof constructs a consistency proof between the provided tree sizes.
func (pb *proofBuilder) ConsistencyProof(ctx context.Context, smaller, larger uint64) ([][]byte, error) {
	if m := max(smaller, larger); m > pb.treeSize {
		return nil, fmt.Errorf("requested consistency proof to %d which is larger than tree size %d", m, pb.treeSize)
	}

	nodes, err := proof.Consistency(smaller, larger)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate consistency proof node list: %v", err)
	}
	return pb.materialiseProof(ctx, nodes)
}

// SubtreeConsistencyProof constructs a subtree consistency proof for the specified range [start, end) in a tree of the proof builder's size.
func (pb *proofBuilder) SubtreeConsistencyProof(ctx context.Context, start, end uint64) ([][]byte, error) {
	if end > pb.treeSize {
		return nil, fmt.Errorf("requested subtree consistency proof to %d which is larger than tree size %d", end, pb.treeSize)
	}

	nodes, err := proof.SubtreeConsistency(start, end, pb.treeSize)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate subtree consistency proof node list: %v", err)
	}
	return pb.materialiseProof(ctx, nodes)
}

// SubtreeInclusionProof constructs a subtree inclusion proof for index in the specified range [start, end).
func (pb *proofBuilder) SubtreeInclusionProof(ctx context.Context, index, start, end uint64) ([][]byte, error) {
	if end > pb.treeSize {
		return nil, fmt.Errorf("requested subtree inclusion proof to %d which is larger than tree size %d", end, pb.treeSize)
	}

	nodes, err := proof.SubtreeInclusion(index, start, end)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate subtree consistency proof node list: %v", err)
	}
	return pb.materialiseProof(ctx, nodes)
}

// materialiseProof retrieves the specified proof nodes via pb's nodeCache, recreating ephemeral nodes if necessary.
func (pb *proofBuilder) materialiseProof(ctx context.Context, nodes proof.Nodes) ([][]byte, error) {
	hashes, err := pb.nodeCache.GetNodes(ctx, nodes.IDs)
	if err != nil {
		return nil, err
	}
	if hashes, err = nodes.Rehash(hashes, rfc6962.DefaultHasher.HashChildren); err != nil {
		return nil, fmt.Errorf("failed to rehash proof: %v", err)
	}
	return hashes, nil
}

type nodeCache struct {
	logSize   uint64
	nodes     *lru.Cache[compact.NodeID, []byte]
	getTile   tileFetcherFunc
	tileLocks *shardedMutex[compact.NodeID]
}

// newNodeCache creates a new nodeCache instance for a given log size.
func newNodeCache(f tileFetcherFunc, logSize uint64) *nodeCache {
	c, err := lru.New[compact.NodeID, []byte](64 << 10)
	if err != nil {
		panic(fmt.Errorf("lru.New: %v", err))
	}
	return &nodeCache{
		logSize:   logSize,
		nodes:     c,
		getTile:   f,
		tileLocks: newShardedMutex[compact.NodeID](),
	}
}

// GetNode returns the internal log tree node hash for the specified node ID.
// The tile containing the node will be fetched if necessary.
func (n *nodeCache) GetNode(ctx context.Context, id compact.NodeID) ([]byte, error) {
	// Fast-path: check to see we have this node in the cache and return it directly if so, otherwise we'll need to fetch it.
	if e, ok := n.nodes.Get(id); ok {
		return e, nil
	}

	// No dice, so we need to fetch the tile and use the contents to populate the cache.
	// We only want to do this once per tile, so lock keyed by the _tile_ ID here.
	tileLevel, tileIndex, _, _ := nodeCoordsToTileAddress(uint64(id.Level), uint64(id.Index))
	k := compact.NodeID{Level: uint(tileLevel), Index: tileIndex}
	n.tileLocks.Lock(k)
	defer n.tileLocks.Unlock(k)
	// Re-check if we have the node cached - since we're under lock here it's possible that another goroutine
	// managed to get into this section before us and populate the cache.
	if e, ok := n.nodes.Get(id); ok {
		return e, nil
	}

	p := partialTileSize(tileLevel, tileIndex, n.logSize)
	nodes, err := n.fetchTileNodes(ctx, tileLevel, tileIndex, p)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch and populate node cache: %v", err)
	}
	for k, v := range nodes {
		n.nodes.Add(k, v)
	}
	if e, ok := nodes[id]; ok {
		return e, nil
	}
	return nil, fmt.Errorf("internal error: missing node %+v", id)
}

// GetNodes returns the tree hashes at the provided locations.
func (n *nodeCache) GetNodes(ctx context.Context, nIDs []compact.NodeID) ([][]byte, error) {
	hashes := make([][]byte, len(nIDs))
	g, ctx := errgroup.WithContext(ctx)
	for i, id := range nIDs {
		g.Go(func() error {
			h, err := n.GetNode(ctx, id)
			if err != nil {
				return err
			}
			hashes[i] = h
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return hashes, nil
}

// fetchTileNodes retrieves the specified tile, parses it, and returns a map of tree-space-coordinate to node hash.
func (n *nodeCache) fetchTileNodes(ctx context.Context, tileLevel, tileIndex uint64, p uint8) (map[compact.NodeID][]byte, error) {
	tileRaw, err := n.getTile(ctx, tileLevel, tileIndex, p)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tile: %v", err)
	}

	var tile hashTile
	if err := tile.UnmarshalText(tileRaw); err != nil {
		return nil, fmt.Errorf("failed to parse tile: %v", err)
	}

	ret := make(map[compact.NodeID][]byte, 256*2-1)
	// visitFn is a visitor callback which populates the nodes cache.
	// Used by the calls to compact range below.
	visitFn := func(intID compact.NodeID, h []byte) {
		// Figure out the "global" nodeID for the node intID in the requested tile.
		i := compact.NodeID{
			Level: uint(tileLevel*tileHeight) + intID.Level,
			Index: (tileIndex*tileWidth)>>intID.Level + intID.Index,
		}
		ret[i] = h
	}
	rf := compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	r := rf.NewEmptyRange(0)
	for _, l := range tile.Nodes {
		if err := r.Append(l, visitFn); err != nil {
			return nil, fmt.Errorf("failed to Append: %v", err)
		}
	}
	if _, err := r.GetRootHash(visitFn); err != nil {
		return nil, fmt.Errorf("failed to visit all nodes: %v", err)
	}
	return ret, nil
}

// cLock is a mutex which keeps track of the number of goroutines attempting to acquire a lock.
type cLock struct {
	sync.Mutex
	n int64
}

// shardedMutex is a set of mutexes sharded by key.
//
// For a given key, it acts as a regular mutex with the exception that it also tracks the number
// of blocked goroutines waiting to acquire the lock.
//
// If a mutex doesn't exist for a given key at the point that Lock is called, one will be created.
// To help guard against unbounded growth, mutexes with zero pending waiters at the point they're unlocked are deleted.
type shardedMutex[K comparable] struct {
	// m protects the locks map and the waiter counts it contains.
	m     *sync.Mutex
	locks map[K]*cLock
}

// newShardedMutex creates a new shardedLock instance.
func newShardedMutex[K comparable]() *shardedMutex[K] {
	return &shardedMutex[K]{
		m:     &sync.Mutex{},
		locks: make(map[K]*cLock),
	}
}

// Lock locks the given key.
func (sl *shardedMutex[K]) Lock(k K) {
	sl.m.Lock()
	l, ok := sl.locks[k]
	if !ok {
		l = &cLock{}
		sl.locks[k] = l
	}
	l.n++
	sl.m.Unlock()

	l.Lock()
}

// Unlock unlocks the given key.
func (sl *shardedMutex[K]) Unlock(k K) {
	sl.m.Lock()
	l, ok := sl.locks[k]
	if !ok {
		panic("unlock on non-existent key")
	}
	l.n--
	if l.n == 0 {
		delete(sl.locks, k)
	}
	sl.m.Unlock()

	l.Unlock()
}

// nWithSuffix returns a tiles-spec "N" path, with a partial suffix if p > 0.
func nWithSuffix(l, n uint64, p uint8) string {
	suffix := ""
	if p > 0 {
		suffix = fmt.Sprintf(".p/%d", p)
	}
	return fmt.Sprintf("%s%s", fmtN(n), suffix)
}

// tilePath builds the relative path to the subtree tile with the given level and index in tile space.
// If p > 0 the path represents a partial tile.
func tilePath(tileLevel, tileIndex uint64, p uint8) string {
	return fmt.Sprintf("tile/%d/%s", tileLevel, nWithSuffix(tileLevel, tileIndex, p))
}

// fmtN returns the "N" part of a Tiles-spec path.
//
// N is grouped into chunks of 3 decimal digits, starting with the most significant digit, and
// padding with zeroes as necessary.
// Digit groups are prefixed with "x", except for the least-significant group which has no prefix,
// and separated with slashes.
//
// See https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md#:~:text=index%201234067%20will%20be%20encoded%20as%20x001/x234/067
func fmtN(N uint64) string {
	n := fmt.Sprintf("%03d", N%1000)
	N /= 1000
	for N > 0 {
		n = fmt.Sprintf("x%03d/%s", N%1000, n)
		N /= 1000
	}
	return n
}

// hashTile represents a tile within the Merkle hash tree.
// Leaf HashTiles will have a corresponding EntryBundle, where each
// entry in the EntryBundle slice hashes to the value at the same
// index in the Nodes slice.
type hashTile struct {
	// Nodes stores the leaf hash nodes in this tile.
	// Note that only non-ephemeral nodes are stored.
	Nodes [][]byte
}

// UnmarshalText implements encoding/TextUnmarshaler and reads HashTiles
// which are encoded using the tlog-tiles spec.
func (t *hashTile) UnmarshalText(raw []byte) error {
	if len(raw)%sha256.Size != 0 {
		return fmt.Errorf("%d is not a multiple of %d", len(raw), sha256.Size)
	}
	nodes := make([][]byte, 0, len(raw)/sha256.Size)
	for index := 0; index < len(raw); index += sha256.Size {
		data := raw[index : index+sha256.Size]
		nodes = append(nodes, data)
	}
	t.Nodes = nodes
	return nil
}

// partialTileSize returns the expected number of leaves in a tile at the given tile level and index
// within a tree of the specified logSize, or 0 if the tile is expected to be fully populated.
func partialTileSize(level, index, logSize uint64) uint8 {
	sizeAtLevel := logSize >> (level * tileHeight)
	fullTiles := sizeAtLevel / tileWidth
	if index < fullTiles {
		return 0
	}
	return uint8(sizeAtLevel % tileWidth)
}

// nodeCoordsToTileAddress returns the (TileLevel, TileIndex) in tile-space, and the
// (NodeLevel, NodeIndex) address within that tile of the specified tree node co-ordinates.
func nodeCoordsToTileAddress(treeLevel, treeIndex uint64) (uint64, uint64, uint, uint64) {
	tileRowWidth := uint64(1 << (tileHeight - treeLevel%tileHeight))
	tileLevel := treeLevel / tileHeight
	tileIndex := treeIndex / tileRowWidth
	nodeLevel := uint(treeLevel % tileHeight)
	nodeIndex := uint64(treeIndex % tileRowWidth)

	return tileLevel, tileIndex, nodeLevel, nodeIndex
}
