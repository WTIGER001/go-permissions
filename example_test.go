package permissions

import (
	"context"
	"fmt"
)

type exampleChecker struct{}

func (exampleChecker) HasPermission(_ context.Context, req Request) (bool, error) {
	if req.Perm == "finops.system-cost-report.view" {
		return true, nil
	}

	if req.Perm == "user.user.view" && req.Object == "user-1" {
		return true, nil
	}

	if req.Perm == "folders.file.read" && req.Object == "file-1/folder-2/workspace-9" {
		return true, nil
	}

	return false, nil
}

func ExampleSystemPermission() {
	checker := exampleChecker{}
	p := NewSystemPermission(
		"finops.system-cost-report.view",
		"Finops",
		"View System Cost Report",
		"Allows viewing system-wide cost reporting.",
		true,
	).WithChecker(checker)

	ok, err := p.Can(context.Background(), "user-123")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(ok)
	// Output: true
}

func ExampleObjectPermission_batch() {
	checker := exampleChecker{}
	p := NewObjectPermission(
		"user.user.view",
		"User",
		"View User",
		"Allows reading a user profile.",
		true,
	).WithChecker(checker)

	any, _ := p.Any(context.Background(), "user-123", "user-2", "user-1")
	all, _ := p.All(context.Background(), "user-123", "user-2", "user-1")
	filtered, _ := p.Filter(context.Background(), "user-123", "user-2", "user-1")

	fmt.Println(any)
	fmt.Println(all)
	fmt.Println(filtered)
	// Output:
	// true
	// false
	// [user-1]
}

func ExampleObjectPermission_hierarchicalFilter() {
	checker := exampleChecker{}
	p := NewObjectPermission(
		"folders.file.read",
		"Folders",
		"Read File Contents",
		"Allows reading files in a hierarchy.",
		true,
	).WithChecker(checker)

	allowed, _ := p.HierarchicalFilter(
		context.Background(),
		"user-123",
		[]string{"file-2", "file-1"},
		[]string{"folder-2", "workspace-9"},
	)

	fmt.Println(allowed)
	// Output: [file-1]
}
