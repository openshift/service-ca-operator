package cabundleinjector

import (
	"context"
	"fmt"
	"os"
	"slices"
	"sync/atomic"
	"time"

	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/util/filesystem"

	"github.com/openshift/library-go/pkg/operator/events"
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
		return
	}
	c.v.Store(&data)
}

type bundlesWatcher struct {
	// CABundle contains the signing CA bundle.
	CABundle *bundleCache
	// CABundleLegacy is constructed so that it matches what the old KCM used to do.
	// The signing CA bundle is appended to the service account ca.crt.
	CABundleLegacy *bundleCache

	saTokenCA *bundleCache

	caBundlePath        string
	saTokenCABundlePath string
	pollingInterval     time.Duration
	recorder            events.Recorder

	// readFile is used to read files from disk.
	readFile func(string) ([]byte, error)
}

func newBundlesWatcher(
	caBundlePath string, saTokenCABundlePath string,
	pollingInterval time.Duration,
	recorder events.Recorder,
) *bundlesWatcher {
	return &bundlesWatcher{
		CABundle:            &bundleCache{},
		CABundleLegacy:      &bundleCache{},
		saTokenCA:           &bundleCache{},
		caBundlePath:        caBundlePath,
		saTokenCABundlePath: saTokenCABundlePath,
		pollingInterval:     pollingInterval,
		recorder:            recorder,
		readFile:            os.ReadFile,
	}
}

func (w *bundlesWatcher) Start(ctx context.Context) error {
	if err := w.reloadCABundle(); err != nil {
		return err
	}
	if err := w.reloadSATokenCA(); err != nil {
		return err
	}

	watchErrorHandler := func(path string) func(error) {
		return func(err error) {
			klog.Errorf("Error watching %q: %v", path, err)
		}
	}
	go filesystem.WatchUntil(ctx, w.pollingInterval, w.caBundlePath,
		w.reloadCABundleLogged, watchErrorHandler(w.caBundlePath))
	go filesystem.WatchUntil(ctx, w.pollingInterval, w.saTokenCABundlePath,
		w.reloadSATokenCALogged, watchErrorHandler(w.saTokenCABundlePath))

	return nil
}

func (w *bundlesWatcher) reloadCABundle() error {
	data, err := w.readFile(w.caBundlePath)
	if err != nil {
		return fmt.Errorf("failed to read %q: %w", w.caBundlePath, err)
	}

	w.CABundle.Store(data)
	w.rebuildLegacyBundle()
	return nil
}

func (w *bundlesWatcher) reloadSATokenCA() error {
	data, err := w.readFile(w.saTokenCABundlePath)
	if err != nil {
		return fmt.Errorf("failed to read %q: %w", w.saTokenCABundlePath, err)
	}

	w.saTokenCA.Store(data)
	w.rebuildLegacyBundle()
	return nil
}

func (w *bundlesWatcher) reloadCABundleLogged() {
	if err := w.reloadCABundle(); err != nil {
		klog.Errorf("Failed to reload CA bundle: %v", err)
		w.recorder.Warningf("CABundleReloadFailed", "Failed to reload CA bundle: %v", err)
	}
}

func (w *bundlesWatcher) reloadSATokenCALogged() {
	if err := w.reloadSATokenCA(); err != nil {
		klog.Errorf("Failed to reload SA token CA bundle: %v", err)
		w.recorder.Warningf("CABundleReloadFailed", "Failed to reload SA token CA bundle: %v", err)
	}
}

func (w *bundlesWatcher) rebuildLegacyBundle() {
	ca := w.CABundle.Load()
	sa := w.saTokenCA.Load()
	if ca == nil || sa == nil {
		return
	}

	w.CABundleLegacy.Store(constructLegacyBundle(ca, sa))
}

func constructLegacyBundle(caBundle, saTokenCA []byte) []byte {
	return slices.Concat(caBundle, saTokenCA, []byte("\n"))
}
