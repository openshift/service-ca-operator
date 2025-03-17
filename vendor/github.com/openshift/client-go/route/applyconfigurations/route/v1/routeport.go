// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	intstr "k8s.io/apimachinery/pkg/util/intstr"
)

// RoutePortApplyConfiguration represents a declarative configuration of the RoutePort type for use
// with apply.
type RoutePortApplyConfiguration struct {
	TargetPort *intstr.IntOrString `json:"targetPort,omitempty"`
}

// RoutePortApplyConfiguration constructs a declarative configuration of the RoutePort type for use with
// apply.
func RoutePort() *RoutePortApplyConfiguration {
	return &RoutePortApplyConfiguration{}
}

// WithTargetPort sets the TargetPort field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TargetPort field is set to the value of the last call.
func (b *RoutePortApplyConfiguration) WithTargetPort(value intstr.IntOrString) *RoutePortApplyConfiguration {
	b.TargetPort = &value
	return b
}
