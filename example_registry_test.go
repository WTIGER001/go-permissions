package permissions

import "fmt"

func ExamplePermissionRegistry() {
	r := NewPermissionRegistry()

	r.MustRegister(
		NewTeamPermission(
			"billing.invoice.read",
			"Billing",
			"Read Invoice",
			"Allows reading invoice records.",
		).WithFields([]string{"id", "amount", "currency"}).Definition(),
	)

	def, ok := r.Get("billing.invoice.read")
	if !ok {
		fmt.Println("missing")
		return
	}

	fmt.Println(def.Scope)
	fmt.Println(def.ID)
	fmt.Println(def.Namespace)
	fmt.Println(len(def.Fields))
	// Output:
	// team
	// billing.invoice.read
	// Billing
	// 3
}
