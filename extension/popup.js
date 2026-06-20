document.addEventListener("DOMContentLoaded", () => {
  const API_KEY = "AIzaSyBx1bf2BXEr9ue4AnHTnegmbWSNy08IJDA";
  const BACKEND = "http://127.0.0.1:8000";

  const MAX_FAILED_ATTEMPTS = 3;
  const LOCK_TIME_MS = 5 * 60 * 1000;

  const statusEl = document.getElementById("status");
  const userBadgeEl = document.getElementById("userBadge");

  const choiceSection = document.getElementById("choiceSection");
  const loginSection = document.getElementById("loginSection");
  const registerSection = document.getElementById("registerSection");
  const setup2faSection = document.getElementById("setup2faSection");
  const verifyOtpSection = document.getElementById("verifyOtpSection");
  const appSection = document.getElementById("appSection");

  const loginEmailEl = document.getElementById("loginEmail");
  const loginPasswordEl = document.getElementById("loginPassword");

  const registerEmailEl = document.getElementById("registerEmail");
  const registerPasswordEl = document.getElementById("registerPassword");
  const registerConfirmPasswordEl = document.getElementById("registerConfirmPassword");

  const setupOtpCodeEl = document.getElementById("setupOtpCode");
  const verifyOtpCodeEl = document.getElementById("verifyOtpCode");
  const qrContainerEl = document.getElementById("qrContainer");
  const secretKeyTextEl = document.getElementById("secretKeyText");

  let pendingLoginEmail = "";
  let pendingLoginToken = "";
  let pendingRefreshToken = "";
  let pendingSetupSecret = "";

  function showMessage(message) {
    statusEl.textContent = message;
  }

  function showSection(sectionName) {
    choiceSection.classList.add("hidden");
    loginSection.classList.add("hidden");
    registerSection.classList.add("hidden");
    setup2faSection.classList.add("hidden");
    verifyOtpSection.classList.add("hidden");
    appSection.classList.add("hidden");

    if (sectionName === "choice") choiceSection.classList.remove("hidden");
    if (sectionName === "login") loginSection.classList.remove("hidden");
    if (sectionName === "register") registerSection.classList.remove("hidden");
    if (sectionName === "setup2fa") setup2faSection.classList.remove("hidden");
    if (sectionName === "verifyOtp") verifyOtpSection.classList.remove("hidden");
    if (sectionName === "app") appSection.classList.remove("hidden");
  }

  function clearAuthInputs() {
    loginEmailEl.value = "";
    loginPasswordEl.value = "";
    registerEmailEl.value = "";
    registerPasswordEl.value = "";
    registerConfirmPasswordEl.value = "";
    setupOtpCodeEl.value = "";
    verifyOtpCodeEl.value = "";
  }

  function clearPendingLogin() {
    pendingLoginEmail = "";
    pendingLoginToken = "";
    pendingRefreshToken = "";
    pendingSetupSecret = "";
  }

  function validatePasswordPolicy(password) {
    if (password.length < 8) return "Password must be at least 8 characters.";
    if (!/[A-Z]/.test(password)) return "Password must include at least one uppercase letter.";
    if (!/[a-z]/.test(password)) return "Password must include at least one lowercase letter.";
    if (!/[0-9]/.test(password)) return "Password must include at least one number.";
    if (!/[^A-Za-z0-9]/.test(password)) return "Password must include at least one special character.";
    return "";
  }

  async function firebaseLogin(email, password) {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${API_KEY}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, returnSecureToken: true })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data?.error?.message || "Login failed");
    return data;
  }

  async function firebaseRegister(email, password) {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${API_KEY}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, returnSecureToken: true })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data?.error?.message || "Registration failed");
    return data;
  }

  async function firebaseResetPassword(email) {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${API_KEY}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        requestType: "PASSWORD_RESET",
        email: email
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data?.error?.message || "Password reset failed");
    return data;
  }

  async function getStored() {
    return await chrome.storage.local.get([
      "firebaseIdToken",
      "firebaseRefreshToken",
      "firebaseEmail",
      "totpSecrets"
    ]);
  }

   async function writeAuditLog(action, status, details = {}) {
    try {
      const { firebaseIdToken, firebaseEmail } = await chrome.storage.local.get([
        "firebaseIdToken",
        "firebaseEmail"
      ]);

      const auditData = {
        action: action,
        status: status,
        email: details.email || firebaseEmail || "unknown",
        details: details,
        userAgent: navigator.userAgent,
        source: "chrome_extension_popup",
        client_timestamp: new Date().toISOString()
      };

      await fetch(`${BACKEND}/audit-log`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(firebaseIdToken ? { "Authorization": "Bearer " + firebaseIdToken } : {})
        },
        body: JSON.stringify(auditData)
      });
    } catch (err) {
      console.error("Audit log failed:", err);
    }
  }

  async function getLoginLock(email) {
    const key = `loginLock_${email.toLowerCase()}`;
    const data = await chrome.storage.local.get([key]);
    return data[key] || { attempts: 0, lockedUntil: 0 };
  }

  async function setLoginLock(email, lockData) {
    const key = `loginLock_${email.toLowerCase()}`;
    await chrome.storage.local.set({ [key]: lockData });
  }

  async function clearLoginLock(email) {
    const key = `loginLock_${email.toLowerCase()}`;
    await chrome.storage.local.remove([key]);
  }

  async function getEffectiveUrlFromActiveTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentUrl = tab?.url || "";

    if (currentUrl.startsWith("chrome-extension://") && currentUrl.includes("blocked.html")) {
      try {
        const u = new URL(currentUrl);
        const original = u.searchParams.get("url");
        if (original) return decodeURIComponent(original);
      } catch (e) {
        console.error("Failed to parse blocked page URL:", e);
      }
    }

    return currentUrl;
  }

  function setLoggedOutState() {
    showSection("choice");
    userBadgeEl.textContent = "Not logged in";
    showMessage("Not logged in.");
  }

  async function setLoggedInState(email) {
    showSection("app");
    userBadgeEl.textContent = `Logged in as: ${email}`;
    showMessage(`Welcome, ${email}`);
  }

  async function getUserTotpSecret(email) {
    const { totpSecrets } = await chrome.storage.local.get(["totpSecrets"]);
    const allSecrets = totpSecrets || {};
    return allSecrets[email] || "";
  }

  async function saveUserTotpSecret(email, secret) {
    const { totpSecrets } = await chrome.storage.local.get(["totpSecrets"]);
    const allSecrets = totpSecrets || {};
    allSecrets[email] = secret;
    await chrome.storage.local.set({ totpSecrets: allSecrets });
  }

  function base32Encode(bytes) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0;
    let value = 0;
    let output = "";

    for (const byte of bytes) {
      value = (value << 8) | byte;
      bits += 8;

      while (bits >= 5) {
        output += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
    return output;
  }

  function base32Decode(base32) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const clean = base32.toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
    let bits = 0;
    let value = 0;
    const output = [];

    for (const char of clean) {
      const idx = alphabet.indexOf(char);
      if (idx === -1) continue;

      value = (value << 5) | idx;
      bits += 5;

      if (bits >= 8) {
        output.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }

    return new Uint8Array(output);
  }

  function generateTotpSecret(length = 20) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return base32Encode(bytes);
  }

  async function hmacSha1(keyBytes, messageBytes) {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageBytes);
    return new Uint8Array(signature);
  }

  function intToBytes(counter) {
    const bytes = new Uint8Array(8);
    let temp = counter;

    for (let i = 7; i >= 0; i--) {
      bytes[i] = temp & 0xff;
      temp = Math.floor(temp / 256);
    }

    return bytes;
  }

  async function generateHotp(secret, counter) {
    const keyBytes = base32Decode(secret);
    const counterBytes = intToBytes(counter);
    const hmac = await hmacSha1(keyBytes, counterBytes);

    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    return (binary % 1000000).toString().padStart(6, "0");
  }

  async function generateTotp(secret, timeStep = 30, skew = 0) {
    const counter = Math.floor(Date.now() / 1000 / timeStep) + skew;
    return await generateHotp(secret, counter);
  }

  async function verifyTotp(secret, code) {
    const normalizedCode = String(code).trim();
    if (!/^\d{6}$/.test(normalizedCode)) return false;

    for (let skew = -1; skew <= 1; skew++) {
      const expected = await generateTotp(secret, 30, skew);
      if (expected === normalizedCode) return true;
    }

    return false;
  }

  function buildOtpAuthUrl(email, secret) {
    const issuer = "PhishingDetector";
    const label = `${issuer}:${email}`;
    return `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  }

  function renderQrCode(text) {
    qrContainerEl.innerHTML = "";

    if (typeof QRCode === "undefined") {
      qrContainerEl.innerHTML = `<div>QR library not found.<br>Please use the manual setup key below.</div>`;
      return;
    }

    try {
      new QRCode(qrContainerEl, {
        text,
        width: 180,
        height: 180,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.H
      });
    } catch (error) {
      console.error("QR generation error:", error);
      qrContainerEl.innerHTML = `<div>Failed to generate QR code.<br>Please use the manual setup key below.</div>`;
    }
  }

  function showSetup2fa(email, secret) {
    showSection("setup2fa");
    const otpAuthUrl = buildOtpAuthUrl(email, secret);
    renderQrCode(otpAuthUrl);
    secretKeyTextEl.textContent = secret;
    setupOtpCodeEl.value = "";
    showMessage(`Set up 2FA for ${email}.`);
  }

  document.getElementById("showLoginBtn").addEventListener("click", () => {
    showSection("login");
    showMessage("Please enter your login details.");
  });

  document.getElementById("showRegisterBtn").addEventListener("click", () => {
    showSection("register");
    showMessage("Create your new account.");
  });

  document.getElementById("goToRegisterBtn").addEventListener("click", () => {
    showSection("register");
    showMessage("Create your new account.");
  });

  document.getElementById("goToLoginBtn").addEventListener("click", () => {
    showSection("login");
    showMessage("Please login with your account.");
  });

  document.getElementById("backFromLoginBtn").addEventListener("click", () => {
    showSection("choice");
    showMessage("Not logged in.");
  });

  document.getElementById("backFromRegisterBtn").addEventListener("click", () => {
    showSection("choice");
    showMessage("Not logged in.");
  });

  document.getElementById("forgotPasswordBtn").addEventListener("click", async () => {
    try {
      const email = loginEmailEl.value.trim();

      if (!email) {
        showMessage("Please enter your email first.");
        return;
      }

      showMessage("Sending password reset email...");
      await firebaseResetPassword(email);

      await writeAuditLog("password_reset", "success", {
        email: email,
        reason: "Password reset email requested"
      });

      showMessage("Password reset email sent. Please check your inbox.");
    } catch (e) {
      await writeAuditLog("password_reset_failed", "failed", {
        email: loginEmailEl.value.trim() || "unknown",
        reason: e.message
      });

      showMessage("Password reset failed: " + e.message);
    }
  });

  document.getElementById("loginBtn").addEventListener("click", async () => {
    const email = loginEmailEl.value.trim();
    const password = loginPasswordEl.value.trim();

    if (!email || !password) {
      showMessage("Please enter email and password.");
      return;
    }

    const lock = await getLoginLock(email);
    const now = Date.now();

    if (lock.lockedUntil && now < lock.lockedUntil) {
      const remainingMinutes = Math.ceil((lock.lockedUntil - now) / 60000);

      await writeAuditLog("login_blocked_due_to_lock", "warning", {
        email: email,
        reason: "Login attempt during temporary lock period",
        remainingMinutes: remainingMinutes
      });

      showMessage(`Account temporarily locked. Please try again in ${remainingMinutes} minute(s).`);
      return;
    }

    try {
      showMessage("Logging in...");
      const data = await firebaseLogin(email, password);

      await clearLoginLock(email);

      pendingLoginEmail = data.email;
      pendingLoginToken = data.idToken;
      pendingRefreshToken = data.refreshToken;

      const existingSecret = await getUserTotpSecret(data.email);

      if (!existingSecret) {
        pendingSetupSecret = generateTotpSecret();
        showSetup2fa(data.email, pendingSetupSecret);
      } else {
        showSection("verifyOtp");
        verifyOtpCodeEl.value = "";
        showMessage("Enter the 6-digit code from Microsoft Authenticator.");
      }
    } catch (e) {

      await writeAuditLog("login_failed", "failed", {
        email: email,
        reason: e.message
      });

      const updatedLock = await getLoginLock(email);
      const attempts = (updatedLock.attempts || 0) + 1;

      if (attempts >= MAX_FAILED_ATTEMPTS) {
        await setLoginLock(email, {
          attempts: 0,
          lockedUntil: Date.now() + LOCK_TIME_MS
        });

        showMessage("Too many failed login attempts. Account locked for 5 minutes.");
      } else {
        await setLoginLock(email, {
          attempts,
          lockedUntil: 0
        });

        showMessage(`Login failed. Attempt ${attempts}/${MAX_FAILED_ATTEMPTS}.`);
      }
    }
  });

  document.getElementById("registerBtn").addEventListener("click", async () => {
    try {
      const email = registerEmailEl.value.trim();
      const password = registerPasswordEl.value.trim();
      const confirmPassword = registerConfirmPasswordEl.value.trim();

      if (!email || !password || !confirmPassword) {
        showMessage("Please complete all registration fields.");
        return;
      }

      if (password !== confirmPassword) {
        showMessage("Password and confirm password do not match.");
        return;
      }

      const policyError = validatePasswordPolicy(password);
      if (policyError) {
        showMessage(policyError);
        return;
      }

      showMessage("Creating account...");
      await firebaseRegister(email, password);

      await writeAuditLog("register_success", "success", {
        email: email,
        reason: "New account created"
      });

      registerEmailEl.value = "";
      registerPasswordEl.value = "";
      registerConfirmPasswordEl.value = "";

      showSection("login");
      loginEmailEl.value = email;
      loginPasswordEl.value = "";
      showMessage("Account created successfully. Please login.");
    } catch (e) {

      await writeAuditLog("register_failed", "failed", {
        email: registerEmailEl.value.trim() || "unknown",
        reason: e.message
      });

      showMessage("Registration failed: " + e.message);
    }
  });

  document.getElementById("activate2faBtn").addEventListener("click", async () => {
    try {
      const otp = setupOtpCodeEl.value.trim();

      if (!/^\d{6}$/.test(otp)) {
        showMessage("Please enter a valid 6-digit OTP code.");
        return;
      }

      if (!pendingLoginToken || !pendingLoginEmail || !pendingSetupSecret) {
        showMessage("No pending setup session found. Please login again.");
        showSection("login");
        return;
      }

      const isValid = await verifyTotp(pendingSetupSecret, otp);
      if (!isValid) {
        await writeAuditLog("otp_failed", "failed", {
          email: pendingLoginEmail,
          reason: "Invalid OTP during 2FA setup"
        });
        
        showMessage("Invalid OTP code. Please try again.");
        return;
      }

      await saveUserTotpSecret(pendingLoginEmail, pendingSetupSecret);

      await chrome.storage.local.set({
        firebaseIdToken: pendingLoginToken,
        firebaseRefreshToken: pendingRefreshToken,
        firebaseEmail: pendingLoginEmail
      });
      await writeAuditLog("otp_success", "success", {
        email: pendingLoginEmail,
        reason: "OTP verified during 2FA setup"
      });

      await writeAuditLog("login_success", "success", {
        email: pendingLoginEmail,
        reason: "User logged in after activating 2FA"
      });

      const email = pendingLoginEmail;
      clearPendingLogin();
      clearAuthInputs();
      await setLoggedInState(email);
      showMessage("2FA has been activated successfully.");
    } catch (e) {

      await writeAuditLog("otp_setup_failed", "failed", {
        email: pendingLoginEmail || "unknown",
        reason: e.message
      });


      showMessage("2FA setup failed: " + e.message);
    }
  });

  document.getElementById("verifyOtpBtn").addEventListener("click", async () => {
    try {
      const otp = verifyOtpCodeEl.value.trim();

      if (!/^\d{6}$/.test(otp)) {
        showMessage("Please enter a valid 6-digit OTP code.");
        return;
      }

      if (!pendingLoginToken || !pendingLoginEmail) {
        showMessage("No pending login session found. Please login again.");
        showSection("login");
        return;
      }

      const secret = await getUserTotpSecret(pendingLoginEmail);
      if (!secret) {
        showMessage("2FA is not set up for this account.");
        showSection("login");
        return;
      }

      const isValid = await verifyTotp(secret, otp);
      if (!isValid) {

        await writeAuditLog("otp_failed", "failed", {
          email: pendingLoginEmail,
          reason: "Invalid OTP during login"
        });

        showMessage("Invalid OTP code. Please try again.");
        return;
      }

      await chrome.storage.local.set({
        firebaseIdToken: pendingLoginToken,
        firebaseRefreshToken: pendingRefreshToken,
        firebaseEmail: pendingLoginEmail
      });

      await writeAuditLog("otp_success", "success", {
        email: pendingLoginEmail,
        reason: "OTP verified during login"
      });

      await writeAuditLog("login_success", "success", {
        email: pendingLoginEmail,
        reason: "User logged in with OTP verification"
      });

      const email = pendingLoginEmail;
      clearPendingLogin();
      clearAuthInputs();
      await setLoggedInState(email);
      showMessage("2FA verification successful.");
    } catch (e) {

      await writeAuditLog("otp_verification_failed", "failed", {
        email: pendingLoginEmail || "unknown",
        reason: e.message
      });

      showMessage("OTP verification failed: " + e.message);
    }
  });

  document.getElementById("backFromOtpBtn").addEventListener("click", () => {
    clearPendingLogin();
    verifyOtpCodeEl.value = "";
    showSection("login");
    showMessage("Please login with your account.");
  });

  document.getElementById("cancelSetup2faBtn").addEventListener("click", () => {
    clearPendingLogin();
    setupOtpCodeEl.value = "";
    qrContainerEl.innerHTML = "QR code will appear here.";
    secretKeyTextEl.textContent = "Not generated yet";
    showSection("login");
    showMessage("2FA setup cancelled.");
  });

 document.getElementById("logoutBtn").addEventListener("click", async () => {
  const { firebaseEmail } = await getStored();

  await writeAuditLog("logout", "success", {
    email: firebaseEmail || "unknown",
    reason: "User logged out"
  });

  await chrome.storage.local.remove([
    "firebaseIdToken",
    "firebaseRefreshToken",
    "firebaseEmail"
  ]);

  // Close any open dashboard tab after logout
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (
        tab.id &&
        tab.url &&
        tab.url.startsWith("http://127.0.0.1:8000/dashboard")
      ) {
        chrome.tabs.remove(tab.id);
      }
    }
  });

  clearPendingLogin();
  clearAuthInputs();
  setLoggedOutState();
});

  document.getElementById("saveSafeBtn").addEventListener("click", async () => {
    try {
      const { firebaseIdToken, firebaseEmail } = await getStored();

      if (!firebaseIdToken) {
        showMessage("Please login first.");
        return;
      }

      const effectiveUrl = await getEffectiveUrlFromActiveTab();
      showMessage("Saving safe feedback...");

      const res = await fetch(`${BACKEND}/feedback`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + firebaseIdToken
        },
        body: JSON.stringify({ url: effectiveUrl, verdict: "safe" })
      });

      if (!res.ok) {
        showMessage("Feedback failed. Please try again.");
        return;
      }

      await writeAuditLog("safe_feedback", "success", {
        email: firebaseEmail || "unknown",
        url: effectiveUrl,
        reason: "User marked current domain as safe"
      });

      showMessage(`✅ Current domain has been marked as safe for ${firebaseEmail}.`);
    } catch (e) {
      showMessage("Error while saving feedback.");
    }
  });

  document.getElementById("openDashboardBtn").addEventListener("click", async () => {
    const { firebaseIdToken } = await chrome.storage.local.get(["firebaseIdToken"]);
    const base = "http://127.0.0.1:8000/dashboard/";
    const url = firebaseIdToken ? `${base}?token=${encodeURIComponent(firebaseIdToken)}` : base;
    chrome.tabs.create({ url });
  });

  chrome.storage.local.get(["firebaseEmail"], async (r) => {
    if (r.firebaseEmail) {
      await setLoggedInState(r.firebaseEmail);
    } else {
      setLoggedOutState();
    }
  });
});