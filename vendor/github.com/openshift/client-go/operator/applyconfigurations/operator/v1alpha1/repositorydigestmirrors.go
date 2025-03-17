// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1alpha1

// RepositoryDigestMirrorsApplyConfiguration represents a declarative configuration of the RepositoryDigestMirrors type for use
// with apply.
type RepositoryDigestMirrorsApplyConfiguration struct {
	Source  *string  `json:"source,omitempty"`
	Mirrors []string `json:"mirrors,omitempty"`
}

// RepositoryDigestMirrorsApplyConfiguration constructs a declarative configuration of the RepositoryDigestMirrors type for use with
// apply.
func RepositoryDigestMirrors() *RepositoryDigestMirrorsApplyConfiguration {
	return &RepositoryDigestMirrorsApplyConfiguration{}
}

// WithSource sets the Source field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Source field is set to the value of the last call.
func (b *RepositoryDigestMirrorsApplyConfiguration) WithSource(value string) *RepositoryDigestMirrorsApplyConfiguration {
	b.Source = &value
	return b
}

// WithMirrors adds the given value to the Mirrors field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Mirrors field.
func (b *RepositoryDigestMirrorsApplyConfiguration) WithMirrors(values ...string) *RepositoryDigestMirrorsApplyConfiguration {
	for i := range values {
		b.Mirrors = append(b.Mirrors, values[i])
	}
	return b
}
