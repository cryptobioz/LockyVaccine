#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

void DisplayError(DWORD error_message){
    char message[1024];
    sprintf(message, "Error : %d", error_message);
    MessageBox(0, message, "LockyVaccine", MB_OK);
}

int main(int argc, char *argv[]){
    SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
    PSID pInteractiveSid = NULL;
    PSID pAdministratorsSid = NULL;
    SECURITY_DESCRIPTOR sd;
    PACL pDacl = NULL;
    DWORD dwAclSize;
    HKEY hKey;
    LONG lRetCode;
    BOOL bSuccess = FALSE;
    DWORD disp;


    DWORD createError = RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Locky", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ, NULL, &hKey, &disp);
    RegCloseKey(hKey);

    if(RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Locky"), 0, WRITE_DAC, &hKey) != ERROR_SUCCESS){
      MessageBox(0, "An error occured, please try again.", "LockyVaccine", MB_OK);
      return 0;
    }

    if(!AllocateAndInitializeSid(&sia, 1, SECURITY_INTERACTIVE_RID, 0, 0, 0, 0, 0, 0, 0, &pInteractiveSid)) {
        DisplayError(GetLastError());
        goto cleanup;
    }

    if(!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsSid)) {
        DisplayError(GetLastError());
        goto cleanup;
    }

    dwAclSize = sizeof(ACL) + 2 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(pInteractiveSid) + GetLengthSid(pAdministratorsSid);

    pDacl = (PACL)HeapAlloc(GetProcessHeap(), 0, dwAclSize);
    if(pDacl == NULL){
      goto cleanup;
    }

    if(!InitializeAcl(pDacl, dwAclSize, ACL_REVISION)) {
        DisplayError(GetLastError());
        goto cleanup;
    }

    if(!AddAccessAllowedAce(pDacl, ACL_REVISION, STANDARD_RIGHTS_READ, pInteractiveSid)) {
        DisplayError(GetLastError());
        goto cleanup;
    }

    if(!AddAccessAllowedAce(pDacl, ACL_REVISION, STANDARD_RIGHTS_READ, pAdministratorsSid)) {
        DisplayError(GetLastError());
        goto cleanup;
    }


    if(!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
        DisplayError(GetLastError());
        goto cleanup;
    }

    if(!SetSecurityDescriptorDacl(&sd, TRUE, pDacl, FALSE)) {
        DisplayError(GetLastError());
        goto cleanup;
    }

    if(RegSetKeySecurity(hKey, (SECURITY_INFORMATION)DACL_SECURITY_INFORMATION, &sd) != ERROR_SUCCESS){
        MessageBox(0, "An error occured, please try again.", "LockyVaccine", MB_OK);
    }

    bSuccess = TRUE;


cleanup:

    RegCloseKey(hKey);
    RegCloseKey(HKEY_LOCAL_MACHINE);

    if(pDacl != NULL)
        HeapFree(GetProcessHeap(), 0, pDacl);

    if(pInteractiveSid != NULL)
        FreeSid(pInteractiveSid);

    if(pAdministratorsSid != NULL)
        FreeSid(pAdministratorsSid);

    if(bSuccess) {
        MessageBox(0, "Vaccination finished successfully.", "LockyVaccine", MB_OK);
        return 0;
    } else {
        MessageBox(0, "An error occured, please try again.", "LockyVaccine", MB_OK);
        return 1;
    }
}
