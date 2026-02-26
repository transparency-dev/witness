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

// Package main provides a command line tool for creating witness cosigning keys
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	origin  = flag.String("origin", "", "Witness origin for the key.")
	outPriv = flag.String("out_priv", "", "Output file for private key.")
	outPub  = flag.String("out_pub", "", "Output file for public key.")
	print   = flag.Bool("print", false, "Print private key, then public key, over 2 lines, to stdout.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if len(*origin) == 0 {
		klog.Exit("--origin required")
	}

	if !(*print) {
		if len(*outPriv) == 0 || len(*outPub) == 0 {
			klog.Exit("--print and/or --out_priv and --out_pub required.")
		}
	}

	skey, vkey, err := note.GenerateKey(rand.Reader, *origin)
	if err != nil {
		klog.Exitf("Unable to create key: %q", err)
	}

	vkey, err = f_note.VKeyToCosignatureV1(vkey)
	if err != nil {
		klog.Exitf("Failed to convert ed25519 vkey to Cosig/V1 vkey: %v", err)
	}

	if *print {
		fmt.Println(skey)
		fmt.Println(vkey)
	}

	if len(*outPriv) > 0 && len(*outPub) > 0 {
		if err := writeFileIfNotExists(*outPriv, skey); err != nil {
			klog.Exit(err)
		}
		if err := writeFileIfNotExists(*outPub, vkey); err != nil {
			klog.Exit(err)
		}
	}
}

// writeFileIfNotExists writes key files. Ensures files do not already exist to avoid accidental overwriting.
func writeFileIfNotExists(filename string, key string) error {
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("unable to create new key file %q: %w", filename, err)
	}
	_, err = file.WriteString(key)
	if err != nil {
		return fmt.Errorf("unable to write new key file %q: %w", filename, err)
	}
	return file.Close()
}
