// Close an open filter dropdown when clicking outside it.
document.addEventListener("click", e => {
    document.querySelectorAll("details.dropdown[open]").forEach(d => {
        if (!d.contains(e.target)) d.removeAttribute("open");
    });
});

window.powerTool = {
    downloadFile(fileName, content, contentType) {
        const blob = new Blob([content], { type: contentType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    },
    async copyText(text) {
        try { await navigator.clipboard.writeText(text); return true; } catch { return false; }
    }
};
