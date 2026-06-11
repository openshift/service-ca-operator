package cabundleinjector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"k8s.io/utils/clock"

	"github.com/openshift/library-go/pkg/operator/events"
)

func newTestRecorder() events.InMemoryRecorder {
	return events.NewInMemoryRecorder("BundlesWatcher", clock.RealClock{})
}

const testPollingInterval = 100 * time.Millisecond

func newTestWatcher(readFile func(string) ([]byte, error)) *bundlesWatcher {
	return &bundlesWatcher{
		CABundle:            &bundleCache{},
		CABundleLegacy:      &bundleCache{},
		saTokenCA:           &bundleCache{},
		caBundlePath:        "/ca-bundle.crt",
		saTokenCABundlePath: "/sa-ca.crt",
		pollingInterval:     testPollingInterval,
		readFile:            readFile,
		recorder:            newTestRecorder(),
	}
}

func TestBundlesWatcher_Start_PopulatesCaches(t *testing.T) {
	caContent := []byte("ca-bundle")
	saContent := []byte("sa-token")

	w := newTestWatcher(func(path string) ([]byte, error) {
		switch path {
		case "/ca-bundle.crt":
			return caContent, nil
		case "/sa-ca.crt":
			return saContent, nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))
	require.Equal(t, caContent, w.CABundle.Load())
	require.Equal(t, []byte("ca-bundlesa-token\n"), w.CABundleLegacy.Load())
}

func TestBundlesWatcher_Start_FailsOnCABundleReadError(t *testing.T) {
	w := newTestWatcher(func(path string) ([]byte, error) {
		switch path {
		case "/ca-bundle.crt":
			return nil, errors.New("ca disk error")
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := w.Start(ctx)
	require.ErrorContains(t, err, "ca disk error")
	require.Nil(t, w.CABundle.Load())
	require.Nil(t, w.CABundleLegacy.Load())
}

func TestBundlesWatcher_Start_FailsOnSATokenCAReadError(t *testing.T) {
	w := newTestWatcher(func(path string) ([]byte, error) {
		switch path {
		case "/ca-bundle.crt":
			return []byte("ca-data"), nil
		case "/sa-ca.crt":
			return nil, errors.New("sa disk error")
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := w.Start(ctx)
	require.ErrorContains(t, err, "sa disk error")
	require.Equal(t, []byte("ca-data"), w.CABundle.Load(), "CA cache should be populated before SA failure")
	require.Nil(t, w.CABundleLegacy.Load(), "legacy cache should not be built when SA read fails")
}

func TestBundlesWatcher_ReloadCABundle(t *testing.T) {
	w := newTestWatcher(func(path string) ([]byte, error) {
		switch path {
		case "/ca-bundle.crt":
			return []byte("ca-bundle-data"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	w.saTokenCA.Store([]byte("sa-token-data"))

	require.NoError(t, w.reloadCABundle())
	require.Equal(t, []byte("ca-bundle-data"), w.CABundle.Load())
	require.Equal(t, []byte("ca-bundle-datasa-token-data\n"), w.CABundleLegacy.Load())
}

func TestBundlesWatcher_ReloadCABundle_ReadError(t *testing.T) {
	recorder := newTestRecorder()
	w := newTestWatcher(func(path string) ([]byte, error) {
		return nil, errors.New("disk error")
	})
	w.recorder = recorder
	w.CABundle.Store([]byte("old-ca"))
	w.CABundleLegacy.Store([]byte("old-legacy"))

	w.reloadCABundleLogged()

	require.Equal(t, []byte("old-ca"), w.CABundle.Load(), "CA cache should be preserved")
	require.Equal(t, []byte("old-legacy"), w.CABundleLegacy.Load(), "legacy cache should be preserved")

	require.Len(t, recorder.Events(), 1)
	require.Equal(t, "CABundleReloadFailed", recorder.Events()[0].Reason)
	require.Contains(t, recorder.Events()[0].Message, "disk error")
}

func TestBundlesWatcher_ReloadSATokenCA(t *testing.T) {
	w := newTestWatcher(func(path string) ([]byte, error) {
		switch path {
		case "/sa-ca.crt":
			return []byte("sa-token-data"), nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})
	w.CABundle.Store([]byte("ca-bundle-data"))

	require.NoError(t, w.reloadSATokenCA())
	require.Equal(t, []byte("sa-token-data"), w.saTokenCA.Load())
	require.Equal(t, []byte("ca-bundle-datasa-token-data\n"), w.CABundleLegacy.Load())
}

func TestBundlesWatcher_ReloadSATokenCA_ReadError(t *testing.T) {
	recorder := newTestRecorder()
	w := newTestWatcher(func(path string) ([]byte, error) {
		return nil, errors.New("sa error")
	})
	w.recorder = recorder
	w.saTokenCA.Store([]byte("old-sa"))
	w.CABundleLegacy.Store([]byte("old-legacy"))

	w.reloadSATokenCALogged()

	require.Equal(t, []byte("old-sa"), w.saTokenCA.Load(), "SA token cache should be preserved")
	require.Equal(t, []byte("old-legacy"), w.CABundleLegacy.Load(), "legacy cache should be preserved")

	require.Len(t, recorder.Events(), 1)
	require.Equal(t, "CABundleReloadFailed", recorder.Events()[0].Reason)
	require.Contains(t, recorder.Events()[0].Message, "sa error")
}

func TestBundlesWatcher_RebuildLegacyBundle_SkipsWhenIncomplete(t *testing.T) {
	w := newTestWatcher(nil)

	w.CABundle.Store([]byte("ca"))
	w.rebuildLegacyBundle()
	require.Nil(t, w.CABundleLegacy.Load(), "legacy bundle should not be built when SA token CA is missing")

	w.CABundle.Store(nil)
	w.saTokenCA.Store([]byte("sa"))
	w.rebuildLegacyBundle()
	require.Nil(t, w.CABundleLegacy.Load(), "legacy bundle should not be built when CA bundle is missing")
}

func TestBundlesWatcher_Integration_ReloadsOnFileChange(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca-bundle.crt")
	saPath := filepath.Join(dir, "sa-ca.crt")
	require.NoError(t, os.WriteFile(caPath, []byte("initial-ca"), 0644))
	require.NoError(t, os.WriteFile(saPath, []byte("initial-sa"), 0644))

	w := newBundlesWatcher(caPath, saPath, 100*time.Millisecond, newTestRecorder())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))
	require.Equal(t, []byte("initial-ca"), w.CABundle.Load())
	require.Equal(t, []byte("initial-cainitial-sa\n"), w.CABundleLegacy.Load())

	require.NoError(t, os.WriteFile(caPath, []byte("updated-ca"), 0644))
	require.NoError(t, os.WriteFile(saPath, []byte("updated-sa"), 0644))

	require.Eventually(t, func() bool {
		return string(w.CABundle.Load()) == "updated-ca" &&
			string(w.CABundleLegacy.Load()) == "updated-caupdated-sa\n"
	}, 5*time.Second, 50*time.Millisecond, "both caches should reflect updated files")
}
