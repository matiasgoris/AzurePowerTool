// The log file (acknowledgements + activity log): a JSON file the user picks, e.g. in OneDrive.
// File System Access API (Edge, Chrome). The file handle is remembered in IndexedDB, so the next
// visit only needs one click to grant access again.
window.powerToolLogFile = (() => {
    const DB = "azurepowertool";
    const STORE = "handles";
    const KEY = "logfile";
    const PICKER = {
        types: [{ description: "Azure PowerTool-logbestand", accept: { "application/json": [".json"] } }],
        excludeAcceptAllOption: false,
    };

    let handle = null;

    function db() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(DB, 1);
            request.onupgradeneeded = () => request.result.createObjectStore(STORE);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async function idb(mode, action) {
        const database = await db();
        try {
            return await new Promise((resolve, reject) => {
                const tx = database.transaction(STORE, mode);
                const request = action(tx.objectStore(STORE));
                tx.oncomplete = () => resolve(request?.result);
                tx.onerror = () => reject(tx.error);
            });
        } finally {
            database.close();
        }
    }

    const remember = h => idb("readwrite", s => s.put(h, KEY));
    const recall = () => idb("readonly", s => s.get(KEY));
    const forgetHandle = () => idb("readwrite", s => s.delete(KEY));

    function isSupported() {
        return "showSaveFilePicker" in window && "showOpenFilePicker" in window;
    }

    // "none" | "prompt" | "granted" | "denied" | "unsupported"
    async function restore() {
        if (!isSupported()) return { state: "unsupported" };
        try {
            handle = (await recall()) ?? null;
        } catch {
            handle = null;
        }
        if (!handle) return { state: "none" };
        return { state: await handle.queryPermission({ mode: "readwrite" }), name: handle.name };
    }

    // Needs a user gesture (button click).
    async function reconnect() {
        if (!handle) return { state: "none" };
        return { state: await handle.requestPermission({ mode: "readwrite" }), name: handle.name };
    }

    async function pick(create) {
        try {
            handle = create
                ? await window.showSaveFilePicker({ ...PICKER, suggestedName: "AzurePowerTool-log.json" })
                : (await window.showOpenFilePicker({ ...PICKER, multiple: false }))[0];
        } catch (e) {
            if (e.name === "AbortError") return null; // user cancelled
            throw e;
        }
        await remember(handle);
        return { state: await handle.queryPermission({ mode: "readwrite" }), name: handle.name };
    }

    async function read() {
        if (!handle) throw new Error("Er is geen logbestand gekozen.");
        return await (await handle.getFile()).text();
    }

    async function write(text) {
        if (!handle) throw new Error("Er is geen logbestand gekozen.");
        const writable = await handle.createWritable();
        await writable.write(text);
        await writable.close();
    }

    async function forget() {
        handle = null;
        await forgetHandle();
    }

    return {
        restore,
        reconnect,
        create: () => pick(true),
        open: () => pick(false),
        read,
        write,
        forget,
    };
})();
