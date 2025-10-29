package test

import (
	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
)

var _ = g.Describe("[Jira:service-ca][sig-api-machinery] Service CA Operator", func() {
	defer g.GinkgoRecover()

	g.It("should always pass [Suite:openshift/service-ca-operator/conformance/parallel]", func() {
		// This is a fake test that always passes
		o.Expect(true).To(o.BeTrue())
	})
})
