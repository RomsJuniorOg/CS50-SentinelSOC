// Dashboard Visual Charts with Chart.js - CS50 Final Project

document.addEventListener("DOMContentLoaded", async () => {
    const severityCanvas = document.getElementById("severityChart");
    const categoryCanvas = document.getElementById("categoryChart");

    if (!severityCanvas || !categoryCanvas) return;

    try {
        const response = await fetch("/api/stats");
        if (!response.ok) throw new Error("Network response was not ok");
        const stats = await response.json();

        // 1. Severity Doughnut Chart
        new Chart(severityCanvas, {
            type: "doughnut",
            data: {
                labels: stats.severity.labels,
                datasets: [{
                    data: stats.severity.data,
                    backgroundColor: [
                        "#0dcaf0", // Low (Cyan)
                        "#0d6efd", // Medium (Blue)
                        "#ffc107", // High (Yellow/Orange)
                        "#dc3545"  // Critical (Red)
                    ],
                    borderColor: "#161b22",
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#c9d1d9", font: { size: 12 } }
                    }
                }
            }
        });

        // 2. Incident Category Horizontal Bar Chart
        new Chart(categoryCanvas, {
            type: "bar",
            data: {
                labels: stats.category.labels,
                datasets: [{
                    label: "Incidents by Category",
                    data: stats.category.data,
                    backgroundColor: "rgba(56, 189, 248, 0.7)",
                    borderColor: "#38bdf8",
                    borderWidth: 1,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y",
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: { stepSize: 1, color: "#8b949e" },
                        grid: { color: "#30363d" }
                    },
                    y: {
                        ticks: { color: "#c9d1d9" },
                        grid: { display: false }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });

    } catch (err) {
        console.error("Failed to load dashboard metrics:", err);
    }
});
