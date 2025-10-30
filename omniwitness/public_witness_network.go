// Copyright 2025 Google LLC. All Rights Reserved.
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
	"net/http"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

// provisionFromPublicConfig is a long-running function which will periodically attempt to merge log
// configs from the provided urls into the provided LogConfig implementation.
//
// This function will only return if the provided list of URLs is empty, or the context becomes done.
func provisionFromPublicConfig(ctx context.Context, httpClient *http.Client, urls []string, p LogConfig, interval time.Duration) error {
	if len(urls) == 0 {
		return nil
	}
	klog.Infof("Started public witness network auto-provision process updating every %v from urls:\n%s", interval, strings.Join(urls, "\n"))

	i := time.Duration(1)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(i):
			i = interval
		}
		klog.V(1).Infof("Provisioning from public witness network...")
		for _, u := range urls {
			opts := PublicFetchOpts{
				Client: httpClient,
				URL:    u,
			}
			klog.V(2).Infof("Provisioning from %q...", u)
			logs, err := FetchPublicConfig(ctx, opts)
			if err != nil {
				klog.Warningf("Failed to fetch public witness network config from %q: %v", u, err)
				continue
			}

			klog.V(2).Infof("Adding %d logs...", len(logs))
			if err := p.AddLogs(ctx, logs); err != nil {
				klog.Warningf("Failed to update list of logs: %v", err)
				continue
			}
			klog.Infof("Successfully merged public witness config from %q...", u)
		}
		klog.V(1).Infof("Provisioning from public witness network complete.")
	}
}
