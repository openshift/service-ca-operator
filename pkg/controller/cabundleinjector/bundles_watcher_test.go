package cabundleinjector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newTestWatcher creates a bundlesWatcher with sensible defaults for testing.
// The readFile function is required; other fields can be overridden after creation.
func newTestWatcher(readFile func(string) ([]byte, error)) *bundlesWatcher {
	return &bundlesWatcher{
		CABundle:            &bundleCache{},
		CABundleLegacy:      &bundleCache{},
		caBundlePath:        "/ca-bundle.crt",
		saTokenCABundlePath: "/sa-ca.crt",
		maxReadAttempts:     1,
		readFile:            readFile,
	}
}

// suppressErrors is an OnReadFailed hook that swallows all errors.
func suppressErrors(_ context.Context, _ error) error { return nil }

func TestBundlesWatcher_ReadBundles(t *testing.T) {
	caContent := []byte("ca-bundle-data")
	saContent := []byte("sa-token-data")

	w := newTestWatcher(func(path string) ([]byte, error) {
		switch path {
		case "/ca-bundle.crt":
			return caContent, nil
		case "/sa-ca.crt":
			return saContent, nil
		}
		return nil, fmt.Errorf("unexpected path: %s", path)
	})

	caBundle, saToken, legacy, err := w.readBundles()
	require.NoError(t, err)
	require.Equal(t, caContent, caBundle)
	require.Equal(t, saContent, saToken)
	require.Equal(t, []byte("ca-bundle-datasa-token-data\n"), legacy)
}

func TestBundlesWatcher_ReadBundles_CABundleNotFound(t *testing.T) {
	w := newTestWatcher(func(path string) ([]byte, error) {
		return nil, os.ErrNotExist
	})

	caBundle, saToken, legacy, err := w.readBundles()
	require.NoError(t, err, "not-found should not be an error")
	require.Nil(t, caBundle)
	require.Nil(t, saToken)
	require.Nil(t, legacy)
}

func TestBundlesWatcher_ReadBundles_SATokenNotFound(t *testing.T) {
	caContent := []byte("ca-bundle-data")

	w := newTestWatcher(func(path string) ([]byte, error) {
		if path == "/ca-bundle.crt" {
			return caContent, nil
		}
		return nil, os.ErrNotExist
	})

	caBundle, saToken, legacy, err := w.readBundles()
	require.NoError(t, err)
	require.Equal(t, caContent, caBundle)
	require.Nil(t, saToken)
	require.Equal(t, caContent, legacy, "legacy bundle should equal CA bundle when SA token CA bundle is missing")
}

func TestBundlesWatcher_ReadBundles_CABundleReadFails(t *testing.T) {
	w := newTestWatcher(func(path string) ([]byte, error) {
		return nil, fmt.Errorf("read error")
	})

	_, _, _, err := w.readBundles()
	require.Error(t, err)
	require.Equal(t, err.Error(), `failed to read "/ca-bundle.crt": read error`)
}

func TestBundlesWatcher_ReadFileWithRetries_SucceedsAfterFailures(t *testing.T) {
	var attempts atomic.Int32

	w := newTestWatcher(func(path string) ([]byte, error) {
		n := attempts.Add(1)
		if n < 3 {
			return nil, fmt.Errorf("attempt %d failed", n)
		}
		return []byte("data"), nil
	})
	w.maxReadAttempts = 3

	content, err := w.readFileWithRetries("/some-path")
	require.NoError(t, err)
	require.Equal(t, []byte("data"), content)
	require.Equal(t, int32(3), attempts.Load())
}

func TestBundlesWatcher_ReadFileWithRetries_AllAttemptsFail(t *testing.T) {
	var attempts atomic.Int32

	w := newTestWatcher(func(path string) ([]byte, error) {
		attempts.Add(1)
		return nil, fmt.Errorf("always fails")
	})
	w.maxReadAttempts = 3

	_, err := w.readFileWithRetries("/some-path")
	require.Error(t, err)
	require.Equal(t, int32(3), attempts.Load())
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

func TestBundlesWatcher_Start_FailsOnInitialReadError(t *testing.T) {
	w := newTestWatcher(func(path string) ([]byte, error) {
		return nil, fmt.Errorf("disk error")
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := w.Start(ctx)
	require.Error(t, err)
	require.Nil(t, w.CABundle.Load(), "bundle cache should remain empty on failure")
}

func TestBundlesWatcher_Start_InitialReadSucceedsAfterRetries(t *testing.T) {
	var attempts atomic.Int32
	caContent := []byte("ca-bundle")

	w := newTestWatcher(func(path string) ([]byte, error) {
		if path == "/sa-ca.crt" {
			return nil, os.ErrNotExist
		}
		n := attempts.Add(1)
		if n < 3 {
			return nil, fmt.Errorf("transient error")
		}
		return caContent, nil
	})
	w.maxReadAttempts = 3

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))
	require.Equal(t, caContent, w.CABundle.Load())
}

func TestBundlesWatcher_Start_InitialReadIgnoresOnReadFailed(t *testing.T) {
	hookCalled := false

	w := newTestWatcher(func(path string) ([]byte, error) {
		return nil, fmt.Errorf("disk error")
	})
	w.OnReadFailed = func(_ context.Context, _ error) error {
		hookCalled = true
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := w.Start(ctx)
	require.Error(t, err, "initial read should fail even with OnReadFailed set")
	require.False(t, hookCalled, "OnReadFailed should not be called during initial read")
}

func TestBundlesWatcher_Resync_UpdatesCaches(t *testing.T) {
	var caContent atomic.Value
	caContent.Store([]byte("initial-ca"))

	w := newTestWatcher(func(path string) ([]byte, error) {
		if path == "/sa-ca.crt" {
			return nil, os.ErrNotExist
		}
		return caContent.Load().([]byte), nil
	})
	w.pollingInterval = time.Hour
	w.resyncInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))
	require.Equal(t, []byte("initial-ca"), w.CABundle.Load())

	// Change what readFile returns; resync should pick it up.
	caContent.Store([]byte("resynced-ca"))

	require.Eventually(t, func() bool {
		return string(w.CABundle.Load()) == "resynced-ca"
	}, 5*time.Second, 10*time.Millisecond, "resync should update the CA bundle cache")
}

func TestBundlesWatcher_Resync_CallsOnReadFailed(t *testing.T) {
	var failReads atomic.Bool
	var hookCalls atomic.Int32

	w := newTestWatcher(func(path string) ([]byte, error) {
		if path == "/sa-ca.crt" {
			return nil, os.ErrNotExist
		}
		if failReads.Load() {
			return nil, fmt.Errorf("disk error")
		}
		return []byte("ca-data"), nil
	})
	w.pollingInterval = time.Hour
	w.resyncInterval = 50 * time.Millisecond
	w.OnReadFailed = func(_ context.Context, _ error) error {
		hookCalls.Add(1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))

	// Start failing reads; resync should call OnReadFailed.
	failReads.Store(true)

	require.Eventually(t, func() bool {
		return hookCalls.Load() > 0
	}, 5*time.Second, 10*time.Millisecond, "resync should call OnReadFailed when reload fails")
}

func TestBundlesWatcher_Resync_StopsOnContextCancel(t *testing.T) {
	var readCalls atomic.Int32

	w := newTestWatcher(func(path string) ([]byte, error) {
		readCalls.Add(1)
		if path == "/sa-ca.crt" {
			return nil, os.ErrNotExist
		}
		return []byte("ca-data"), nil
	})
	w.pollingInterval = time.Hour
	w.resyncInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())

	require.NoError(t, w.Start(ctx))

	// Wait for at least one resync tick.
	require.Eventually(t, func() bool {
		return readCalls.Load() > 2 // initial read counts too
	}, 5*time.Second, 10*time.Millisecond)

	// Cancel context and record the count.
	cancel()
	time.Sleep(100 * time.Millisecond)
	countAfterCancel := readCalls.Load()

	// Verify no more resyncs happen.
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, countAfterCancel, readCalls.Load(), "resync should stop after context is cancelled")
}

func writeTempBundle(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, content, 0644))
	return path
}

func TestBundlesWatcher_Observer_ReloadsOnFileChange(t *testing.T) {
	dir := t.TempDir()
	caPath := writeTempBundle(t, dir, "ca-bundle.crt", []byte("initial-ca"))
	saPath := writeTempBundle(t, dir, "sa-ca.crt", []byte("initial-sa"))

	w := newBundlesWatcher(caPath, saPath, 100*time.Millisecond, 0, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))
	require.Equal(t, []byte("initial-ca"), w.CABundle.Load())

	// Change the CA bundle file on disk.
	require.NoError(t, os.WriteFile(caPath, []byte("updated-ca"), 0644))

	require.Eventually(t, func() bool {
		return string(w.CABundle.Load()) == "updated-ca"
	}, 5*time.Second, 50*time.Millisecond, "CA bundle cache should reflect updated file")
}

func TestBundlesWatcher_Observer_ReloadsLegacyBundle(t *testing.T) {
	dir := t.TempDir()
	caPath := writeTempBundle(t, dir, "ca-bundle.crt", []byte("ca"))
	saPath := writeTempBundle(t, dir, "sa-ca.crt", []byte("sa"))

	w := newBundlesWatcher(caPath, saPath, 100*time.Millisecond, 0, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))
	require.Equal(t, []byte("casa\n"), w.CABundleLegacy.Load())

	// Change the SA token file on disk.
	require.NoError(t, os.WriteFile(saPath, []byte("sa-updated"), 0644))

	require.Eventually(t, func() bool {
		return string(w.CABundleLegacy.Load()) == "casa-updated\n"
	}, 5*time.Second, 50*time.Millisecond, "legacy bundle cache should reflect updated SA token file")
}

func TestBundlesWatcher_Observer_ResetsCachesOnFileRemoval(t *testing.T) {
	dir := t.TempDir()
	caPath := writeTempBundle(t, dir, "ca-bundle.crt", []byte("initial-ca"))
	saPath := writeTempBundle(t, dir, "sa-ca.crt", []byte("initial-sa"))

	w := newBundlesWatcher(caPath, saPath, 100*time.Millisecond, 0, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))
	require.NotNil(t, w.CABundle.Load())

	// Remove the CA file; observer should detect and reset caches.
	require.NoError(t, os.Remove(caPath))

	require.Eventually(t, func() bool {
		return w.CABundle.Load() == nil
	}, 5*time.Second, 50*time.Millisecond, "CA bundle cache should be reset when file is removed")
}

func TestBundlesWatcher_Reload_ResetsCachesOnNotFound(t *testing.T) {
	var returnNotFound atomic.Bool

	w := newTestWatcher(func(path string) ([]byte, error) {
		if path == "/sa-ca.crt" {
			return nil, os.ErrNotExist
		}
		if returnNotFound.Load() {
			return nil, os.ErrNotExist
		}
		return []byte("initial-ca"), nil
	})
	w.pollingInterval = time.Hour
	w.resyncInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))
	require.Equal(t, []byte("initial-ca"), w.CABundle.Load())

	// Simulate file removal.
	returnNotFound.Store(true)

	require.Eventually(t, func() bool {
		return w.CABundle.Load() == nil
	}, 5*time.Second, 10*time.Millisecond, "cache should be reset to nil when file is not found")
	require.Nil(t, w.CABundleLegacy.Load(), "legacy cache should also be reset")
}

func TestBundlesWatcher_Reload_KeepsCachesOnOtherErrors(t *testing.T) {
	var returnError atomic.Bool

	w := newTestWatcher(func(path string) ([]byte, error) {
		if path == "/sa-ca.crt" {
			return nil, os.ErrNotExist
		}
		if returnError.Load() {
			return nil, fmt.Errorf("permission denied")
		}
		return []byte("ca-data"), nil
	})
	w.pollingInterval = time.Hour
	w.resyncInterval = 50 * time.Millisecond
	w.OnReadFailed = suppressErrors

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, w.Start(ctx))
	require.Equal(t, []byte("ca-data"), w.CABundle.Load())

	// Start returning a non-not-found error.
	returnError.Store(true)

	// Wait long enough for several resync ticks.
	time.Sleep(300 * time.Millisecond)

	require.Equal(t, []byte("ca-data"), w.CABundle.Load(),
		"cache should retain old value on non-not-found errors")
}
