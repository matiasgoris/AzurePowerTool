// Sign-in with MSAL.js (redirect flow). Tokens stay in this browser; the app calls Azure directly.
// init() runs before Blazor starts, so the redirect back from Microsoft is handled first.
window.powerToolAuth = (() => {
    const ARM = "https://management.azure.com/.default";
    const TENANT_KEY = "powertool.tenant";

    let pca = null;
    let config = {};
    let error = null;

    const authority = tenant => `https://login.microsoftonline.com/${tenant || config.tenantId || "organizations"}`;
    const homeTenant = account => account.homeAccountId?.split(".")[1] ?? account.tenantId;

    function currentTenant() {
        try { return localStorage.getItem(TENANT_KEY); } catch { return null; }
    }

    function rememberTenant(tenantId) {
        try {
            if (tenantId) localStorage.setItem(TENANT_KEY, tenantId);
            else localStorage.removeItem(TENANT_KEY);
        } catch { /* private mode: only for this page load */ }
    }

    function account() {
        return pca?.getActiveAccount() ?? null;
    }

    async function readSettings(file) {
        try {
            const response = await fetch(file, { cache: "no-store" });
            if (!response.ok) return {};
            const auth = (await response.json())?.Auth ?? {};
            return Object.fromEntries(Object.entries(auth).filter(([, v]) => v));
        } catch {
            return {};
        }
    }

    async function init() {
        try {
            // appsettings.Local.json (not in git) overrides, for local development.
            const settings = { ...(await readSettings("appsettings.json")), ...(await readSettings("appsettings.Local.json")) };
            config = { clientId: settings.ClientId, tenantId: settings.TenantId };
            if (!config.clientId) {
                error = "Er is geen app registration ingesteld (Auth:ClientId in appsettings.json).";
                return;
            }

            pca = new msal.PublicClientApplication({
                auth: {
                    clientId: config.clientId,
                    authority: authority(null),
                    redirectUri: document.baseURI,
                    postLogoutRedirectUri: document.baseURI,
                    navigateToLoginRequestUrl: false,
                },
                // localStorage: the session survives closing the browser (like the old desktop app).
                cache: { cacheLocation: "localStorage" },
            });
            await pca.initialize();

            const result = await pca.handleRedirectPromise();
            if (result) {
                pca.setActiveAccount(result.account);
                rememberTenant(result.tenantId || result.account.tenantId);
                // Back to the page the sign-in started from.
                if (result.state && result.state.startsWith(location.origin)) {
                    history.replaceState(null, "", result.state);
                }
            } else if (!account()) {
                const all = pca.getAllAccounts();
                if (all.length > 0) pca.setActiveAccount(all[0]);
            }
        } catch (e) {
            error = `Aanmelden mislukt: ${e.message ?? e}`;
        }
    }

    // ---- Called from .NET (BrowserSession)

    function state() {
        const a = account();
        return {
            error,
            account: a ? { username: a.username, tenantId: currentTenant() || a.tenantId, homeTenantId: homeTenant(a) } : null,
        };
    }

    async function signIn(tenant, returnUrl) {
        if (!pca) throw new Error(error ?? "Aanmelden is niet beschikbaar.");
        rememberTenant(null);
        await pca.loginRedirect({
            scopes: [ARM],
            authority: authority(tenant),
            prompt: "select_account",
            state: returnUrl,
        });
    }

    async function getToken(scope, tenantId) {
        const a = account();
        if (!pca || !a) return { interactionRequired: true, error: "niet aangemeld" };
        try {
            const result = await pca.acquireTokenSilent({ scopes: [scope], account: a, authority: authority(tenantId || currentTenant() || a.tenantId) });
            return { token: result.accessToken, tenantId: result.tenantId };
        } catch (e) {
            if (e instanceof msal.InteractionRequiredAuthError || e.errorCode === "no_tokens_found" || e.errorCode === "monitor_window_timeout") {
                return { interactionRequired: true, error: e.message };
            }
            return { error: e.message ?? String(e) };
        }
    }

    // Full-page redirect to Microsoft; the page reloads afterwards.
    async function reauthenticate(scope, tenantId, returnUrl) {
        const a = account();
        const tenant = tenantId || currentTenant() || a?.tenantId;
        rememberTenant(tenant);
        await pca.acquireTokenRedirect({ scopes: [scope || ARM], account: a ?? undefined, authority: authority(tenant), state: returnUrl });
    }

    async function switchTenant(tenantId, returnUrl) {
        const result = await getToken(ARM, tenantId);
        if (result.token) {
            rememberTenant(tenantId);
            return result;
        }
        if (result.interactionRequired) {
            await reauthenticate(ARM, tenantId, returnUrl);
        }
        return result;
    }

    // Local sign-out: forget the tokens in this browser, without signing out of Microsoft everywhere.
    async function signOut() {
        rememberTenant(null);
        const a = account();
        if (pca) {
            await pca.clearCache(a ? { account: a } : undefined);
            pca.setActiveAccount(null);
        }
    }

    return { init, state, signIn, getToken, reauthenticate, switchTenant, signOut };
})();
