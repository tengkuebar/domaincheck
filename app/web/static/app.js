// Progressive enhancement. Every page works without this file.
"use strict";

// Progress bars: widths are set through the CSSOM (allowed by the CSP) from data-pct.
// Transitioning clip-path keeps the animation off the layout path.
function fillBars() {
  const bars = document.querySelectorAll(".bar-fill[data-pct]");
  requestAnimationFrame(() => {
    for (const bar of bars) {
      const pct = Math.max(0, Math.min(100, Number(bar.dataset.pct) || 0));
      bar.style.clipPath = `inset(0 ${100 - pct}% 0 0 round 99px)`;
    }
  });
}

// Findings filter: chips hide rows by status. Instant on purpose (no animation for filtering).
function setupFilters() {
  const group = document.querySelector(".chips");
  if (!group) return;
  group.hidden = false;
  group.addEventListener("click", (event) => {
    const chip = event.target.closest("[data-filter]");
    if (!chip) return;
    const filter = chip.dataset.filter;
    for (const other of group.querySelectorAll("[data-filter]")) {
      other.setAttribute("aria-pressed", String(other === chip));
    }
    const rows = document.querySelectorAll(".row[data-status]");
    let shown = 0;
    for (const row of rows) {
      row.hidden = filter !== "all" && row.dataset.status !== filter;
      if (!row.hidden) shown += 1;
    }
    // Screen readers do not notice rows appearing and disappearing, so say what changed.
    const status = document.getElementById("filter-status");
    if (status) status.textContent = `Showing ${shown} of ${rows.length} findings`;
  });
}

// While a scan runs, poll for the result instead of reloading the page on a timer. A timed
// reload resets a screen reader's position and focus every few seconds.
function pollWhileRunning() {
  const card = document.querySelector("[data-running]");
  if (!card) return;
  const timer = setInterval(async () => {
    try {
      const response = await fetch(location.href, { cache: "no-store" });
      const html = await response.text();
      if (!html.includes("data-running")) {
        clearInterval(timer);
        card.querySelector("p").textContent = "The check is finished. Loading the report.";
        location.reload();
      }
    } catch {
      // Network blip: try again on the next tick.
    }
  }, 2500);
}

// Copy buttons for DNS values (kept for any page that uses data-copy).
document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const text = document.getElementById(button.dataset.copy)?.textContent ?? "";
  try {
    await navigator.clipboard.writeText(text.trim());
    const old = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = old; }, 1500);
  } catch {
    // Clipboard blocked: the value is still selectable on the page.
  }
});

// Scan form: show a busy state once the browser has started submitting.
function setupScanForm() {
  const form = document.querySelector("[data-scan-form]");
  if (!form) return;
  form.addEventListener("submit", () => {
    // Defer so the form data is read before the button is disabled.
    setTimeout(() => {
      form.classList.add("is-loading");
      const button = form.querySelector("button[type=submit]");
      button.disabled = true;
      button.querySelector(".btn-label").textContent = "Checking…";
    }, 0);
  });
}

// Back/forward cache can restore the page in its busy state; reset it.
window.addEventListener("pageshow", (event) => {
  if (!event.persisted) return;
  const form = document.querySelector("[data-scan-form]");
  if (!form) return;
  form.classList.remove("is-loading");
  const button = form.querySelector("button[type=submit]");
  button.disabled = false;
  button.querySelector(".btn-label").textContent = "Run check";
});

fillBars();
setupFilters();
setupScanForm();
pollWhileRunning();
