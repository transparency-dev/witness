// Copyright 2023 Google LLC. All Rights Reserved.
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

package omniwitness_test

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/transparency-dev/witness/omniwitness"
)

var (
	// TestConfigLogs is the testing config logs file, useful for when checking
	// features which are not yet used by the prod config.
	// Its schema is LogConfig
	//go:embed logs_test.yaml
	testConfigLogs []byte
)

func testConfig(t *testing.T, cfg []byte) {
	t.Helper()
	logCfg, err := omniwitness.NewStaticLogConfig(cfg)
	if err != nil {
		t.Fatal("failed to unmarshal config", err)
	}
	{
		c := 0
		for l, err := range logCfg.Logs(t.Context()) {
			if err != nil {
				t.Fatalf("Failed to iterate over logs: %v", err)
			}
			c++
			if len(l.URL) == 0 {
				t.Errorf("log %q has no URL", l.URL)
			}
		}
		if c == 0 {
			t.Fatal("no logs defined in config")
		}
	}

	{
		for f, err := range logCfg.Feeders(t.Context()) {
			if err != nil {
				t.Fatalf("Failed to iterate over feeders: %v", err)
			}
			if f.Feeder == omniwitness.None {
				t.Errorf("log %q has unknown feeder", f.Log.Origin)
			}
		}
	}
}

func TestProdConfig(t *testing.T) {
	testConfig(t, omniwitness.DefaultConfigLogs)
}

func TestConfig(t *testing.T) {
	testConfig(t, testConfigLogs)
}

func TestMerge(t *testing.T) {
	base, err := omniwitness.NewStaticLogConfig([]byte(`
Logs:
  - Origin: go.sum database tree
    URL: https://sum.golang.org
    PublicKey: sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8
    Feeder: sumdb
`))
	if err != nil {
		t.Fatalf("Failed to parse base config: %v", err)
	}

	extra, err := omniwitness.NewStaticLogConfig([]byte(`
Logs:
  - Origin: Armory Drive Prod 2
    URL: https://raw.githubusercontent.com/f-secure-foundry/armory-drive-log/master/log/
    PublicKey: armory-drive-log+16541b8f+AYDPmG5pQp4Bgu0a1mr5uDZ196+t8lIVIfWQSPWmP+Jv
    Feeder: serverless
`))
	if err != nil {
		t.Fatalf("Failed to parse extra config: %v", err)
	}

	base.Merge(extra)
	want := map[string]struct{}{
		"go.sum database tree": {},
		"Armory Drive Prod 2":  {},
	}
	for l, err := range base.Logs(t.Context()) {
		if err != nil {
			t.Fatalf("Failed to iterate over logs: %v", err)
		}
		if _, ok := want[l.Origin]; ok {
			delete(want, l.Origin)
		} else {
			t.Errorf("Did not find expected log with origin %q in merged config", l.Origin)
		}
	}
	if l := len(want); l != 0 {
		t.Fatalf("Found %d unexpected extra logs in merged config", l)
	}
}

func TestParsePublicWitnessConfig(t *testing.T) {
	for _, test := range []struct {
		name    string
		config  string
		want    []omniwitness.PublicWitnessConfigLog
		wantErr bool
	}{
		{
			name: "working example",
			config: `
					#
					# List:      10qps-100klogs
					# Revision:  123
					# Generated: YYYY-MM-DD HH:MM:SS UTC
					# Other undefined debug information.
					#
					logs/v0

					# 1st list item -- foo's log
					vkey sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8
					qpd 86400
					contact https://tlog.foo.org/contact

					# 2nd list item -- log with custom origin
					vkey sigsum.org/v1/tree/44ad38f8226ff9bd27629a41e55df727308d0a1cd8a2c31d3170048ac1dd22a1+682b49db+AQ7H4WhDEZsSA3enOROsasvC0D2CQy4sNrhBsJqVhB8l
					origin something-not-equal-to-vkey-keyname
					qpd 24
					contact sysadmin (at) bar.org
					
					# 3rd list item - minimal log config
					vkey tlog.andxor.it+d5e6b3d0+AU6uJ3h8tb+RRMdGjHV4KCrrHoKfIYGbhL2A46thEhKQ
					qpd 1
					
					# Some trailing comments
					`,
			want: []omniwitness.PublicWitnessConfigLog{
				{
					VKey:    "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
					Origin:  "sum.golang.org",
					QPD:     86400,
					Contact: "https://tlog.foo.org/contact",
				}, {
					VKey:    "sigsum.org/v1/tree/44ad38f8226ff9bd27629a41e55df727308d0a1cd8a2c31d3170048ac1dd22a1+682b49db+AQ7H4WhDEZsSA3enOROsasvC0D2CQy4sNrhBsJqVhB8l",
					Origin:  "something-not-equal-to-vkey-keyname",
					QPD:     24,
					Contact: "sysadmin (at) bar.org",
				}, {
					VKey:   "tlog.andxor.it+d5e6b3d0+AU6uJ3h8tb+RRMdGjHV4KCrrHoKfIYGbhL2A46thEhKQ",
					Origin: "tlog.andxor.it",
					QPD:    1,
				},
			},
		}, {
			name:   "empty config",
			config: "logs/v0",
			want:   []omniwitness.PublicWitnessConfigLog{},
		}, {
			name: "broken: no header",
			config: `
					# 1st list item -- foo's log
					vkey sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8
					qpd 86400
					contact https://tlog.foo.org/contact
					`,
			wantErr: true,
		}, {
			name: "broken: bad ordering, vkey not first",
			config: `
					logs/v0
					# 1st list item -- foo's log
					qpd 86400
					vkey sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8
					contact https://tlog.foo.org/contact
					`,
			wantErr: true,
		}, {
			name: "broken: not a vkey",
			config: `
					logs/v0
					vkey BANANAS
					# 1st list item -- foo's log
					qpd 86400
					contact https://tlog.foo.org/contact
					`,
			wantErr: true,
		}, {
			name: "broken: qpd not numeric",
			config: `
					logs/v0
					vkey sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8
					# 1st list item -- foo's log
					qpd toast
					contact https://tlog.foo.org/contact
					`,
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := omniwitness.ParsePublicWitnessConfig(strings.NewReader(test.config))
			if gotErr := err != nil; gotErr != test.wantErr {
				t.Fatalf("Got %v, want error %t", err, test.wantErr)
			}
			for i := range got {
				got[i].Verifier = nil
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Got unexpected difference: %v", diff)
			}
		})
	}
}
