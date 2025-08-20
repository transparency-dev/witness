// Copyright 2024 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	f_note "github.com/transparency-dev/formats/note"
	"k8s.io/klog/v2"
)

// NewSecretManagerSigner creates a new signer that uses a note-formated Ed25519 signer stored in
// Google Cloud Secret Manager.
func NewSecretManagerSigner(ctx context.Context, privateKeySecretName string) (*f_note.Signer, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			klog.Warningf("Failed to close secret manager client: %v", err)
		}
	}()

	secK, err := secret(ctx, client, privateKeySecretName)
	if err != nil {
		return nil, fmt.Errorf("failed to access %q: %v", privateKeySecretName, err)
	}

	return f_note.NewSignerForCosignatureV1(string(secK))
}

func secret(ctx context.Context, client *secretmanager.Client, secretName string) ([]byte, error) {
	resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}
	if resp.Name != secretName {
		return nil, errors.New("request corrupted in-transit")
	}
	// Verify the data checksum.
	crc32c := crc32.MakeTable(crc32.Castagnoli)
	checksum := int64(crc32.Checksum(resp.Payload.Data, crc32c))
	if checksum != *resp.Payload.DataCrc32C {
		return nil, errors.New("data corruption detected")
	}

	return resp.Payload.Data, nil
}
