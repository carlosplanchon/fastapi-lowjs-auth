// Logic of templates/login.html. It lives in a static file so the page's Content
// Security Policy can forbid inline scripts.

// fastapi-users error codes, as messages for people.
const ERROR_MESSAGES = {
  LOGIN_BAD_CREDENTIALS: "Incorrect email or password.",
  REGISTER_USER_ALREADY_EXISTS: "An account with this email already exists.",
  RESET_PASSWORD_BAD_TOKEN: "This reset link is invalid or has expired. Please request a new one.",
  VERIFY_USER_BAD_TOKEN: "This verification link is invalid or has expired.",
  CHANGE_PASSWORD_BAD_CREDENTIALS: "Your current password is incorrect.",
  // From the Google callback, which redirects back here with #error=...
  GOOGLE_CANCELLED: "Google sign-in was cancelled.",
  GOOGLE_FAILED: "Google sign-in failed. Please try again.",
};

function errorMessage(error) {
  const detail = error.detail;
  if (typeof detail === "string" && ERROR_MESSAGES[detail]) return ERROR_MESSAGES[detail];
  // e.g. {"code": "REGISTER_INVALID_PASSWORD", "reason": "Password should be ..."}
  if (detail && detail.reason) return detail.reason;
  if (error.status === 429) {
    const minutes = Math.max(1, Math.ceil((error.retryAfter || 60) / 60));
    return `Too many attempts. Please try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`;
  }
  if (error.status === 422) return "Please enter a valid email address.";
  return "Something went wrong. Please try again.";
}

document.addEventListener("alpine:init", () => {
  // Alpine's CSP build can't run full JavaScript from the attributes (no arrow
  // functions, no globals like fetch), so the logic lives here: x-data="authApp".
  Alpine.data("authApp", () => {
    // Set by FastAPI on <html data-base-url="...">.
    const BASE_URL = document.documentElement.dataset.baseUrl;

    return {
      /* state ----------------------------------------------------------- */
      view: "login",
      email: "", password: "", password2: "", currentPassword: "",
      error: "", notice: "", user: {}, resetToken: "", busy: false,

      /* lifecycle ---------------------------------------------------- */
      async init() {
        // Sessions live in an HttpOnly cookie now; drop the token older versions kept here.
        localStorage.removeItem("token");
        // A link opened in a tab already showing this page only changes the
        // fragment, so the page doesn't reload: handle it here too.
        window.addEventListener("hashchange", () => this.openLink());
        await this.openLink();
      },

      async openLink() {
        // Links carry their data in the URL fragment, which is never sent to the
        // server: #error (Google sign-in), #reset_token and #verify_token (emails).
        const params = new URLSearchParams(window.location.hash.slice(1));
        if (window.location.hash) history.replaceState({}, "", window.location.pathname);

        if (params.get("error")) this.error = errorMessage({ detail: params.get("error") });
        if (params.get("reset_token")) {
          this.resetToken = params.get("reset_token");
          this.show("reset");
          return;
        }
        if (params.get("verify_token")) await this.verifyEmail(params.get("verify_token"));

        // JavaScript can't see the session cookie: ask the server.
        await this.fetchMe();
      },

      /* helpers ---------------------------------------------------------- */
      async api(path, opts={}) {
        const headers = {};
        // JSON bodies are strings; URLSearchParams sets its own Content-Type.
        if (typeof opts.body === "string") headers["Content-Type"] = "application/json";
        // Same-origin requests carry the session cookie on their own.
        const res = await fetch(BASE_URL + path, { headers, ...opts });
        const data = await res.json().catch(() => null);
        if (!res.ok) {
          const error = new Error(`HTTP ${res.status}`);
          error.status = res.status;
          error.detail = data && data.detail;
          error.retryAfter = Number(res.headers.get("Retry-After"));
          throw error;
        }
        return data;
      },

      show(view) {
        this.view = view;
        this.error = this.notice = "";
        // Every form starts with empty password fields: after signing in, the
        // sign-in password would otherwise show up in the change-password form.
        this.currentPassword = this.password = this.password2 = "";
      },

      /* actions --------------------------------------------------------- */
      async register() {
        this.error = this.notice = "";
        if (this.password !== this.password2) {
          this.error = "Passwords don't match.";
          return;
        }
        try {
          await this.api("/auth/register", {
            method: "POST",
            body: JSON.stringify({ email: this.email, password: this.password })
          });
          await this.login();            // login automático
          if (this.view === "dashboard") this.notice = "We've sent you a link to verify your email.";
        } catch (e) {
          this.error = errorMessage(e);
        }
      },

      async login() {
        this.error = this.notice = "";
        try {
          // fastapi-users' login route expects an OAuth2 form, not JSON. It answers
          // with the session cookie.
          await this.api("/auth/cookie/login", {
            method: "POST",
            body: new URLSearchParams({ username: this.email, password: this.password })
          });
          await this.fetchMe();
        } catch (e) {
          this.error = errorMessage(e);
        }
      },

      async fetchMe() {
        try {
          this.user = await this.api("/me");
          this.view = "dashboard";
        } catch (e) {
          // 401 just means there's no session; anything else is a real error.
          if (e.status !== 401) this.error = errorMessage(e);
          this.view = "login";
        }
      },

      async verifyEmail(token) {
        this.error = this.notice = "";
        try {
          await this.api("/auth/verify", { method: "POST", body: JSON.stringify({ token }) });
          this.notice = "Your email is verified.";
        } catch (e) {
          if (e.detail === "VERIFY_USER_ALREADY_VERIFIED") this.notice = "Your email is already verified.";
          else this.error = errorMessage(e);
        }
      },

      async resendVerification() {
        this.error = this.notice = "";
        try {
          await this.api("/auth/request-verify-token", {
            method: "POST",
            body: JSON.stringify({ email: this.user.email })
          });
          this.notice = "We've sent you a new verification link.";
        } catch (e) {
          this.error = errorMessage(e);
        }
      },

      async forgotPassword() {
        this.error = this.notice = "";
        try {
          await this.api("/auth/forgot-password", {
            method: "POST",
            body: JSON.stringify({ email: this.email })
          });
          // Same answer whether the account exists or not.
          this.notice = "If an account exists for that email, we've sent a link to reset your password.";
        } catch (e) {
          this.error = errorMessage(e);
        }
      },

      async resetPassword() {
        this.error = this.notice = "";
        if (this.password !== this.password2) {
          this.error = "Passwords don't match.";
          return;
        }
        try {
          await this.api("/auth/reset-password", {
            method: "POST",
            body: JSON.stringify({ token: this.resetToken, password: this.password })
          });
          this.password = this.password2 = this.resetToken = "";
          this.show("login");
          this.notice = "Your password has been updated. You can sign in now.";
        } catch (e) {
          this.error = errorMessage(e);
        }
      },

      async changePassword() {
        // A second submit would race the first with the old cookie and could
        // leave this browser signed out.
        if (this.busy) return;
        this.error = this.notice = "";
        if (this.password !== this.password2) {
          this.error = "Passwords don't match.";
          return;
        }
        this.busy = true;
        try {
          // The server ends the other sessions and sets a new cookie for this one.
          await this.api("/auth/change-password", {
            method: "POST",
            body: JSON.stringify({ current_password: this.currentPassword, new_password: this.password })
          });
          this.show("dashboard");
          this.notice = "Your password has been changed. Other devices have been signed out.";
        } catch (e) {
          this.sessionActionFailed(e);
        } finally {
          this.busy = false;
        }
      },

      async logoutOthers() {
        // Like changePassword: a second click would race the first with the old cookie.
        if (this.busy) return;
        this.error = this.notice = "";
        this.busy = true;
        try {
          // The server ends every session, this one too, and sets a new cookie here.
          await this.api("/auth/cookie/logout-others", { method: "POST" });
          this.notice = "Other devices have been signed out.";
        } catch (e) {
          this.sessionActionFailed(e);
        } finally {
          this.busy = false;
        }
      },

      sessionActionFailed(e) {
        // The session may have ended meanwhile, e.g. signed out from another device.
        if (e.status === 401) {
          this.show("login");
          this.error = "Your session has ended. Please sign in again.";
        } else {
          this.error = errorMessage(e);
        }
      },

      async emailResetLink() {
        // For accounts without a known password, e.g. created by signing in with Google.
        this.error = this.notice = "";
        try {
          await this.api("/auth/forgot-password", {
            method: "POST",
            body: JSON.stringify({ email: this.user.email })
          });
          this.notice = "We've emailed you a link to choose a new password. Using it signs you out everywhere, here too.";
        } catch (e) {
          this.error = errorMessage(e);
        }
      },

      async logout() {
        try {
          // Ends the session in the database and clears the cookie.
          await this.api("/auth/cookie/logout", { method: "POST" });
        } catch (e) {
          // Already signed out (401): nothing left to end.
          if (e.status !== 401) {
            this.error = errorMessage(e);
            return;
          }
        }
        this.email = "";
        this.show("login");  // also clears the password fields
      },

      google() {
        window.location.href = BASE_URL + "/auth/google/login";
      }
    };
  });
});
