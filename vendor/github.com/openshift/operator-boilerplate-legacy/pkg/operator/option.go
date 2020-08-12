package operator

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openshift/operator-boilerplate-legacy/pkg/controller"
)

type Option func(*operator)

func WithInformer(getter controller.InformerGetter, filter controller.Filter, opts ...controller.InformerOption) Option {
	return func(o *operator) {
		o.opts = append(o.opts,
			controller.WithInformer(getter, controller.FilterFuncs{
				ParentFunc: func(obj v1.Object) (namespace, name string) {
					return o.name, o.name // return our singleton key for all events
				},
				AddFunc:    filter.Add,
				UpdateFunc: filter.Update,
				DeleteFunc: filter.Delete,
			}, opts...),
		)
	}
}
