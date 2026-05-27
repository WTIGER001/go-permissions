package shared

import (
	"context"
	"fmt"
	"sort"

	"github.com/wtiger001/go-permissions"
)

func Must(err error) {
	if err != nil {
		panic(err)
	}
}

func StrPtr(v string) *string {
	return &v
}

func PrintSystemCheck(ctx context.Context, svc *permissions.Service, userID, permission, label string) {
	ok, err := svc.HasSystemPermission(ctx, userID, permission)
	if err != nil {
		fmt.Printf("%s: error=%v\n", label, err)
		return
	}
	fmt.Printf("%s: %t\n", label, ok)
}

func PrintObjectCheck(ctx context.Context, svc *permissions.Service, userID, objectID, permission, label string) {
	ok, err := svc.HasPermission(ctx, permissions.Request{UserID: userID, Object: objectID, Perm: permission})
	if err != nil {
		fmt.Printf("%s: error=%v\n", label, err)
		return
	}
	fmt.Printf("%s: %t\n", label, ok)
}

func PrintTeamCheck(ctx context.Context, svc *permissions.Service, userID string, teamID int64, permission, label string) {
	ok, err := svc.HasTeamPermission(ctx, userID, teamID, "", permission)
	if err != nil {
		fmt.Printf("%s: error=%v\n", label, err)
		return
	}
	fmt.Printf("%s: %t\n", label, ok)
}

func PrintPrincipalHits(hits []permissions.PrincipalHit) {
	labels := make([]string, 0, len(hits))
	for _, hit := range hits {
		labels = append(labels, string(hit.Kind)+":"+hit.ID)
	}
	sort.Strings(labels)
	for _, label := range labels {
		fmt.Printf("- %s\n", label)
	}
}
