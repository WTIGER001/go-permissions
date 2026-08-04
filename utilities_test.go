package permissions

import (
	"context"
	"testing"
)

type customTestUser struct {
	dbID string
}

type mockSimpleChecker struct {
	lastUserID string
}

func (m *mockSimpleChecker) HasPermission(ctx context.Context, req Request) (bool, error) {
	m.lastUserID = req.UserID
	return true, nil
}

func TestUtilities_DefaultSubjectID(t *testing.T) {
	ctx := context.Background()
	checker := &mockSimpleChecker{}

	sysPerm := NewSystemPermission("test.sys", "test", "test", "test").WithChecker(checker)

	// Test standard string
	if !sysPerm.Can(ctx, "user-1") {
		t.Errorf("expected Can to return true")
	}
	if checker.lastUserID != "user-1" {
		t.Errorf("expected lastUserID to be user-1, got %q", checker.lastUserID)
	}

	// Test StringSubject
	if !sysPerm.Can(ctx, StringSubject("user-2")) {
		t.Errorf("expected Can to return true")
	}
	if checker.lastUserID != "user-2" {
		t.Errorf("expected lastUserID to be user-2, got %q", checker.lastUserID)
	}

	// Test fallback error for unhandled type
	if sysPerm.Can(ctx, 12345) {
		t.Errorf("expected Can to return false for unhandled type")
	}
}

func TestUtilities_CustomSubjectFunc(t *testing.T) {
	ctx := context.Background()

	// Create a real service to test the integration
	svc := New()

	// Configure the custom subject function
	svc.SetSubjectFunc(func(ctx context.Context, subject any) (string, error) {
		if u, ok := subject.(customTestUser); ok {
			return u.dbID, nil
		}
		// Fallback
		return DefaultSubjectID(subject)
	})

	// Grant the permission so HasPermission returns true
	svc.AllowUser(ctx, "custom-id-99", "test.custom", nil)
	svc.AllowUser(ctx, "standard-id", "test.custom", nil)

	sysPerm := NewSystemPermission("test.custom", "test", "test", "test").WithChecker(svc)

	// 1. Test the custom type
	u := customTestUser{dbID: "custom-id-99"}
	if !sysPerm.Can(ctx, u) {
		t.Errorf("expected Can to return true using custom subject func")
	}

	// 2. Test the fallback to standard string
	if !sysPerm.Can(ctx, "standard-id") {
		t.Errorf("expected Can to return true using fallback")
	}

	// 3. Test ungranted custom user
	ungranted := customTestUser{dbID: "unknown"}
	if sysPerm.Can(ctx, ungranted) {
		t.Errorf("expected Can to return false for ungranted user")
	}
}
