//go:build windows

package creds

// Windows ACLs for the SERVICE data directory (audit finding ACL-1).
//
// Go's 0o700 / 0o600 mode bits are ignored on Windows, so everything the
// --system service wrote under %ProgramData%\Calabi inherited that folder's
// DACL: BUILTIN\Users could READ config.json (access + refresh token, api key),
// local_token and mesh.key, and could CREATE files inside the directory. Any
// non-admin account on the machine could therefore take over the account, drive
// the :7400 console with the stolen local token, or impersonate the device on
// the mesh with mesh.key (which satisfies the v2 registration proof).
//
// The fix is an explicit, PROTECTED DACL — inheritance from ProgramData is cut,
// and only SYSTEM and Administrators are granted access. Inheritable, so files
// created in the directory afterwards get the same treatment.

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// currentUserSID is the SID of the account this process runs as.
func currentUserSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}

func secureDataDir(dir string) error {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("creds: SYSTEM sid: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("creds: Administrators sid: %w", err)
	}
	// The account this process actually runs as. LocalSystem for the installed
	// service — already covered — but a daemon pointed at an explicit data dir
	// may be running as an ordinary user, and then neither of the SIDs above
	// applies: it could create this directory and immediately fail to write the
	// files it came to write. An Administrators ACE does not help there either,
	// because UAC hands non-elevated processes a filtered token.
	//
	// Granting the owner still closes the finding: OTHER local users are the
	// ones excluded.
	self, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("creds: current user sid: %w", err)
	}
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(system),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(admins),
			},
		},
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(self),
			},
		},
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("creds: build dacl: %w", err)
	}
	// PROTECTED_DACL_SECURITY_INFORMATION is the half that matters: without it
	// the inherited BUILTIN\Users ACEs stay on the object.
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		return fmt.Errorf("creds: set dacl on %s: %w", dir, err)
	}
	return nil
}
