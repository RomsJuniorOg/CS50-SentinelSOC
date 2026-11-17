// SentinelSOC Main Frontend Scripts - CS50 Final Project

document.addEventListener("DOMContentLoaded", () => {
    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll(".alert-dismissible");
    alerts.forEach((alert) => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 5000);
    });

    // Copy to clipboard helper
    const copyButtons = document.querySelectorAll("[data-copy-target]");
    copyButtons.forEach((btn) => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-copy-target");
            const target = document.getElementById(targetId);
            if (target) {
                const text = target.innerText || target.value;
                navigator.clipboard.writeText(text).then(() => {
                    const originalHtml = btn.innerHTML;
                    btn.innerHTML = '<i class="fa-solid fa-check text-success"></i> Copied!';
                    setTimeout(() => {
                        btn.innerHTML = originalHtml;
                    }, 2000);
                });
            }
        });
    });
});
