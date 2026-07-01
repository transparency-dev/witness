// Copyright 2026 Google LLC. All Rights Reserved.
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

// Package config holds code related to configuring witnesses.
package config

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strconv"
	"strings"

	"github.com/transparency-dev/formats/note"
)

// PublicFetchOpts holds options to be used when fetching the public witness network config.
type PublicFetchOpts struct {
	// Client is the HTTP client to be used, if unset uses http.DefaultClient.
	Client *http.Client
	// URL is the URL of the config file.
	URL string
}

func FetchPublicConfig(ctx context.Context, opts PublicFetchOpts) ([]Log, error) {
	if opts.Client == nil {
		opts.Client = http.DefaultClient
	}

	req, err := http.NewRequest(http.MethodGet, opts.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest: %w", err)
	}
	req = req.WithContext(ctx)
	resp, err := opts.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.Do: %w", err)
	}
	defer func() {
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}()

	return ParsePublicWitnessConfig(resp.Body)
}

// ParsePublicWitnessConfig implements a parser for the public witness config format.
//
// The format is described here: https://github.com/transparency-dev/witness-network/blob/main/log-list-format.md
func ParsePublicWitnessConfig(r io.Reader) ([]Log, error) {
	ret := []Log{}
	foundHeader := false
	var candidate *Log
	scanner := bufio.NewScanner(r)
	for l := range filteringScan(scanner) {
		bits := strings.SplitN(l, " ", 2)
		switch keyword := strings.ToLower(strings.TrimSpace(bits[0])); keyword {
		case "logs/v0":
			if foundHeader {
				return nil, fmt.Errorf("invalid config, multiple 'logs/v0' headers found")
			}
			foundHeader = true
			continue
		case "vkey":
			// vkey introduces a new log in the config file.
			// The argument is a note-compliant vkey string.
			//
			// Since vkey is always the first keyword in a new log, we can use this as a trigger to "flush" the
			// previous log config, if any, and start a new one.
			if candidate != nil {
				ret = append(ret, *candidate)
			}
			candidate = &Log{}
			if len(bits) != 2 {
				return nil, fmt.Errorf("invalid vkey line %q", l)
			}
			candidate.VKey = strings.TrimSpace(bits[1])
			v, err := note.NewVerifier(candidate.VKey)
			if err != nil {
				return nil, fmt.Errorf("note.NewVerifier: %v", err)
			}
			candidate.Verifier = v
			candidate.Origin = v.Name()
		case "origin":
			// origin is an optional keyword which can be used to set a log origin which is different to the log's
			// vkey name.
			if candidate == nil {
				return nil, fmt.Errorf("invalid config")
			}
			if len(bits) != 2 {
				return nil, fmt.Errorf("invalid origin line %q", l)
			}
			candidate.Origin = strings.TrimSpace(bits[1])
		case "qpd":
			// qpd is the number of queries the log is permitted to send to the witness per dat.
			// The value is interpreted as a float64.
			if candidate == nil {
				return nil, fmt.Errorf("invalid config")
			}
			if len(bits) != 2 {
				return nil, fmt.Errorf("invalid qps line %q", l)
			}
			v := strings.TrimSpace(bits[1])
			qpd, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid qps value %q: %v", v, err)
			}
			candidate.QPD = qpd
		case "contact":
			// contact is a free-form text field which contains some sort of contact information for the log operator.
			if candidate == nil {
				return nil, fmt.Errorf("invalid config")
			}
			if len(bits) != 2 {
				return nil, fmt.Errorf("invalid contact line %q", l)
			}
			candidate.Contact = strings.TrimSpace(bits[1])
		default:
			return nil, fmt.Errorf("unexpected keyword %q", keyword)
		}
	}
	// Include the final entry, if any.
	if candidate != nil {
		ret = append(ret, *candidate)
		candidate = nil
	}
	if !foundHeader {
		return nil, fmt.Errorf("invalid config, no 'logs/v0' header found")
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %v", err)
	}
	return ret, nil
}

func filteringScan(s *bufio.Scanner) iter.Seq[string] {
	return func(yield func(string) bool) {
		for s.Scan() {
			l := strings.TrimSpace(s.Text())
			if l == "" {
				continue
			}
			if l[0] == '#' {
				continue
			}
			if !yield(l) {
				return
			}
		}
	}
}
