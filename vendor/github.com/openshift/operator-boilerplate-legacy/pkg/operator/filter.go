package operator

import "github.com/openshift/operator-boilerplate-legacy/pkg/controller"

func FilterByNames(names ...string) controller.Filter {
	return controller.FilterByNames(nil, names...)
}
