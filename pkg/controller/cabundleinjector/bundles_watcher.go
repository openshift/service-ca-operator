package cabundleinjector

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/fileobserver"
)

type bundleCache struct {
	v atomic.Pointer[[]byte]
}

func (c *bundleCache) Load() []byte {
	if dataPtr := c.v.Load(); dataPtr != nil {
		return *dataPtr
	}
	return nil
}

func (c *bundleCache) Store(data []byte) {
	if data == nil {
		c.v.Store(nil)
	} else {
		c.v.Store(&data)
	}
}

type bundlesWatcher struct {
	// caBundle contains the signing CA bundle.
	CABundle *bundleCache
	// caBundleLegacy is constructed so that it matches what the old KCM used to do.
	// The signing CA bundle is appended to the service account ca.crt.
	CABundleLegacy *bundleCache

	// OnReadFailed can be set for custom read error handling.
	// When the hook returns the original error, it is logged.
	// Logging happens automatically when no hook is set.
	OnReadFailed func(context.Context, error) error

	caBundlePath        string
	saTokenCABundlePath string
	pollingInterval     time.Duration
	resyncInterval      time.Duration
	maxReadAttempts     int

	// readFile is used to read files from disk.
	// Used for mocking during tests mostly.
	readFile func(string) ([]byte, error)
}

func newBundlesWatcher(
	caBundlePath string, saTokenCABundlePath string,
	pollingInterval time.Duration,
	resyncInterval time.Duration,
	maxReadAttempts int,
) *bundlesWatcher {
	return &bundlesWatcher{
		CABundle:            &bundleCache{},
		CABundleLegacy:      &bundleCache{},
		caBundlePath:        caBundlePath,
		saTokenCABundlePath: saTokenCABundlePath,
		pollingInterval:     pollingInterval,
		resyncInterval:      resyncInterval,
		maxReadAttempts:     maxReadAttempts,
		readFile:            os.ReadFile,
	}
}

func (w *bundlesWatcher) Start(ctx context.Context) error {
	// Read the files initially. This is how the previous implementation worked, so we retain that.
	caBundleData, saTokenCAData, legacyCABundleData, err := w.readBundles()
	if err != nil {
		return fmt.Errorf("failed to read bundles on startup: %w", err)
	}

	w.CABundle.Store(caBundleData)
	w.CABundleLegacy.Store(legacyCABundleData)

	// Start watching.
	observer, err := fileobserver.NewObserver(w.pollingInterval)
	if err != nil {
		return fmt.Errorf("failed to start CA bundles observer: %w", err)
	}

	observer.AddReactor(func(_ string, _ fileobserver.ActionType) error {
		return w.reloadBundles(ctx)
	}, map[string][]byte{
		w.caBundlePath:        caBundleData,
		w.saTokenCABundlePath: saTokenCAData,
	}, w.caBundlePath, w.saTokenCABundlePath)

	go observer.Run(ctx.Done())

	// Periodically re-read the bundles as a safety net
	// in case the file observer reactor callback fails.
	if w.resyncInterval > 0 {
		go func() {
			ticker := time.NewTicker(w.resyncInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := w.reloadBundles(ctx); err != nil {
						klog.Errorf("Failed to resync CA bundles: %v", err)
					}
				}
			}
		}()
	}

	return nil
}

func (w *bundlesWatcher) reloadBundles(ctx context.Context) error {
	caBundleData, _, legacyCABundleData, err := w.readBundles()
	if err != nil {
		// On read errors, keep existing cached content
		// until the next successful read.
		if w.OnReadFailed != nil {
			err = w.OnReadFailed(ctx, err)
		}
		return err
	}

	w.CABundle.Store(caBundleData)
	w.CABundleLegacy.Store(legacyCABundleData)
	return nil
}

func (w *bundlesWatcher) readBundles() ([]byte, []byte, []byte, error) {
	caBundleContent, err := w.readFileWithRetries(w.caBundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil, nil
		}
		return nil, nil, nil, fmt.Errorf("failed to read %q: %w", w.caBundlePath, err)
	}

	// This construction matches what the old KCM used to do.
	// It added the entire ca.crt to the service account ca.crt.
	vulnerableLegacyCABundleContent := append([]byte{}, caBundleContent...)
	saTokenCABundleContent, err := w.readFileWithRetries(w.saTokenCABundlePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, nil, fmt.Errorf("failed to read %q: %w", w.saTokenCABundlePath, err)
	}
	if len(saTokenCABundleContent) > 0 {
		vulnerableLegacyCABundleContent = append(vulnerableLegacyCABundleContent, saTokenCABundleContent...)
		vulnerableLegacyCABundleContent = append(vulnerableLegacyCABundleContent, []byte("\n")...)
	}

	return caBundleContent, saTokenCABundleContent, vulnerableLegacyCABundleContent, nil
}

func (w *bundlesWatcher) readFileWithRetries(path string) ([]byte, error) {
	numAttempts := w.maxReadAttempts
	if numAttempts <= 0 {
		numAttempts = 1
	}

	var lastErr error
	for range numAttempts {
		content, err := w.readFile(path)
		if err == nil {
			return content, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
