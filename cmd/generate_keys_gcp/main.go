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
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"
)

var (
	origin         = flag.String("origin", "", "Witness origin for the key.")
	resourceSuffix = flag.String("resource_suffix", "", "Suffix to be used when naming Secret Manager resources.")
	projectID      = flag.String("project_id", os.Getenv("GOOGLE_CLOUD_PROJECT"), "GCP Project ID in which to store the generated secret & public keys.")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if *origin == "" {
		exit("--origin must be provided.\n")
	}
	if *projectID == "" {
		exit("--project_id must be provided, or GOOGLE_CLOUD_PROJECT env var set.")
	}
	if *resourceSuffix == "" {
		exit("--resource_suffix must be provided.\n")
	}

	ctx := context.Background()
	// Create a Secret Manager client.
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		exit("Failed to create Secret Manager client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			exit("Error closing secret manager client: %v", err)
		}
	}()

	// Generate key pair
	sec, pub, err := note.GenerateKey(rand.Reader, *origin)
	if err != nil {
		klog.Exitf("Unable to create key: %q", err)
	}

	// Convert pubk to a cosig/v1 key.
	pub, err = f_note.VKeyToCosignatureV1(pub)
	if err != nil {
		klog.Exitf("Failed to convert ed25519 vkey to Cosig/V1 vkey: %v", err)
	}

	// Store keys in Secret Manager.
	pubKName := fmt.Sprintf("witness-verifier-%s", safeResource(*resourceSuffix))
	if err := createSecret(ctx, *projectID, client, pubKName, pub); err != nil {
		exit("Failed to create secret %q: %v", pubKName, err)
	}
	secKName := fmt.Sprintf("witness-secret-%s", safeResource(*resourceSuffix))
	if err := createSecret(ctx, *projectID, client, secKName, sec); err != nil {
		exit("Failed to create secret %q: %v", secKName, err)
	}

	// All done!
	fmt.Printf("Created new witness keypair:\n  Secret name: %s\n  Public name: %v\n\nPublic Key:\n%s\n", secKName, pubKName, pub)
}

// safeResource attempts to derive a safe GCP resource name from the provided origin string.
func safeResource(o string) string {
	return strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') ||
			(r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			r == '-' {
			return r
		}
		return '-'
	}, o)
}

func createSecret(ctx context.Context, projectID string, client *secretmanager.Client, name string, value string) error {
	createSecretReq := &secretmanagerpb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", projectID),
		SecretId: name,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	}
	secret, err := client.CreateSecret(ctx, createSecretReq)
	if err != nil {
		return err
	}

	addSecretVersionReq := &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: []byte(value),
		},
	}
	_, err = client.AddSecretVersion(ctx, addSecretVersionReq)
	return err
}

func exit(m string, args ...any) {
	fmt.Fprintf(os.Stderr, m+"\n", args...)
	os.Exit(1)
}
