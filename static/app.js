(() => {
  "use strict";

  const body = document.body;
  if (!body) return;

  const normalize = (value) =>
    String(value ?? "")
      .normalize("NFKC")
      .trim()
      .toLocaleLowerCase("zh-Hant");

  const setupDashboardFilters = () => {
    const rows = Array.from(document.querySelectorAll("[data-site-row]"));
    const search = document.querySelector("[data-site-search]");
    const categoryButtons = Array.from(
      document.querySelectorAll("[data-category-filter]")
    );
    const scopeButtons = Array.from(
      document.querySelectorAll("[data-scope-filter]")
    );
    const statusButtons = Array.from(
      document.querySelectorAll("[data-status-filter]")
    );
    const clearButtons = Array.from(
      document.querySelectorAll("[data-clear-filters]")
    );
    const resultsLabel = document.querySelector("[data-results-label]");
    const emptyState = document.querySelector("[data-empty-state]");
    const siteList = document.querySelector(".site-list");
    const candidatePanel = document.querySelector("[data-candidate-panel]");
    const candidateCount = Number.parseInt(
      candidatePanel?.dataset.candidateCount || "0",
      10
    );

    if (!rows.length && !search) return;

    const validCategories = new Set(
      categoryButtons.map((button) => normalize(button.dataset.categoryFilter))
    );
    const validScopes = new Set(
      scopeButtons.map((button) => normalize(button.dataset.scopeFilter))
    );
    const validStatuses = new Set(
      statusButtons.map((button) => normalize(button.dataset.statusFilter))
    );

    const params = new URLSearchParams(window.location.search);
    const requestedCategory = normalize(params.get("category") || "all");
    const requestedScope = normalize(params.get("scope") || "all");
    const requestedStatus = normalize(params.get("status") || "all");

    const state = {
      query: params.get("q") || "",
      category: validCategories.has(requestedCategory)
        ? requestedCategory
        : "all",
      scope: validScopes.has(requestedScope) ? requestedScope : "all",
      status: validStatuses.has(requestedStatus) ? requestedStatus : "all",
    };

    if (search) search.value = state.query;

    const hasFilters = () =>
      Boolean(state.query.trim()) ||
      state.category !== "all" ||
      state.scope !== "all" ||
      state.status !== "all";

    const updateAddress = () => {
      const nextParams = new URLSearchParams();
      if (state.query.trim()) nextParams.set("q", state.query.trim());
      if (state.category !== "all") {
        nextParams.set("category", state.category);
      }
      if (state.scope !== "all") nextParams.set("scope", state.scope);
      if (state.status !== "all") nextParams.set("status", state.status);

      const queryString = nextParams.toString();
      const nextUrl = `${window.location.pathname}${
        queryString ? `?${queryString}` : ""
      }${window.location.hash}`;
      window.history.replaceState(null, "", nextUrl);
    };

    const updateControls = () => {
      categoryButtons.forEach((button) => {
        const isActive =
          normalize(button.dataset.categoryFilter) === state.category &&
          state.scope === "all";
        button.classList.toggle("is-active", isActive);
        button.setAttribute("aria-pressed", String(isActive));
      });

      scopeButtons.forEach((button) => {
        const isActive =
          normalize(button.dataset.scopeFilter) === state.scope;
        button.classList.toggle("is-active", isActive);
        button.setAttribute("aria-pressed", String(isActive));
      });

      statusButtons.forEach((button) => {
        const isActive =
          normalize(button.dataset.statusFilter) === state.status;
        button.setAttribute("aria-pressed", String(isActive));
      });
    };

    const applyFilters = ({ updateUrl = true } = {}) => {
      const query = normalize(state.query);
      const candidateMode = state.scope === "candidate";
      let visibleCount = 0;

      rows.forEach((row) => {
        const matchesSearch =
          !query || normalize(row.dataset.search).includes(query);
        const matchesCategory =
          state.category === "all" ||
          normalize(row.dataset.category) === state.category;
        const matchesStatus =
          state.status === "all" ||
          normalize(row.dataset.status) === state.status;
        const matchesScope =
          state.scope === "all" ||
          (state.scope === "candidate" && row.dataset.candidate === "true") ||
          (state.scope === "archived" && row.dataset.archived === "true");

        const isVisible =
          matchesSearch &&
          matchesCategory &&
          matchesStatus &&
          matchesScope;
        row.hidden = !isVisible;
        if (isVisible) visibleCount += 1;
      });

      updateControls();

      const filtered = hasFilters();
      clearButtons.forEach((button) => {
        button.hidden = !filtered;
      });

      if (resultsLabel) {
        if (candidateMode) {
          resultsLabel.textContent = `顯示 ${candidateCount} 個待確認項目`;
        } else {
          resultsLabel.textContent =
            visibleCount === rows.length && !filtered
              ? `顯示 ${visibleCount} 個項目`
              : `顯示 ${visibleCount} / ${rows.length} 個項目`;
        }
      }

      if (candidatePanel && candidateMode) candidatePanel.open = true;
      if (emptyState) {
        emptyState.hidden = candidateMode
          ? candidateCount > 0
          : visibleCount !== 0;
      }
      if (siteList) siteList.hidden = candidateMode || visibleCount === 0;
      if (updateUrl) updateAddress();
    };

    const clearFilters = ({ focusSearch = false } = {}) => {
      state.query = "";
      state.category = "all";
      state.scope = "all";
      state.status = "all";
      if (search) search.value = "";
      if (candidatePanel) candidatePanel.open = false;
      applyFilters();
      if (focusSearch && search) search.focus();
    };

    search?.addEventListener("input", (event) => {
      state.query = event.currentTarget.value;
      applyFilters();
    });

    categoryButtons.forEach((button) => {
      button.addEventListener("click", () => {
        state.category = normalize(button.dataset.categoryFilter);
        state.scope = "all";
        applyFilters();
      });
    });

    scopeButtons.forEach((button) => {
      button.addEventListener("click", () => {
        const requested = normalize(button.dataset.scopeFilter);
        state.scope = state.scope === requested ? "all" : requested;
        state.category = "all";
        if (requested === "candidate" && state.scope === "candidate") {
          state.query = "";
          state.status = "all";
          if (search) search.value = "";
        } else if (requested === "candidate" && candidatePanel) {
          candidatePanel.open = false;
        }
        applyFilters();
        if (state.scope === "candidate" && candidatePanel) {
          window.requestAnimationFrame(() => {
            candidatePanel.scrollIntoView({
              behavior: window.matchMedia("(prefers-reduced-motion: reduce)")
                .matches
                ? "auto"
                : "smooth",
              block: "start",
            });
          });
        }
      });
    });

    statusButtons.forEach((button) => {
      button.addEventListener("click", () => {
        const requested = normalize(button.dataset.statusFilter);
        state.status = state.status === requested ? "all" : requested;
        state.scope = "all";
        if (candidatePanel) candidatePanel.open = false;
        applyFilters();
        document.querySelector(".workspace")?.scrollIntoView({
          behavior: window.matchMedia("(prefers-reduced-motion: reduce)")
            .matches
            ? "auto"
            : "smooth",
          block: "start",
        });
      });
    });

    clearButtons.forEach((button) => {
      button.addEventListener("click", () => clearFilters({ focusSearch: true }));
    });

    document.addEventListener("keydown", (event) => {
      const target = event.target;
      const isTyping =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        target?.isContentEditable;

      if (
        event.key === "/" &&
        !isTyping &&
        search &&
        !event.metaKey &&
        !event.ctrlKey &&
        !event.altKey
      ) {
        event.preventDefault();
        search.focus();
      }

      if (event.key === "Escape" && hasFilters()) {
        event.preventDefault();
        clearFilters({ focusSearch: Boolean(search) });
      }
    });

    applyFilters({ updateUrl: false });
  };

  const setupAutoRefresh = () => {
    const refreshSeconds = Number.parseInt(
      body.dataset.refreshSeconds || "30",
      10
    );
    const label = document.querySelector("[data-refresh-label]");
    const refreshPaused =
      new URLSearchParams(window.location.search).get("refresh") === "off";

    if (!Number.isFinite(refreshSeconds) || refreshSeconds < 1) return;
    if (refreshPaused) {
      if (label) label.textContent = "自動更新已暫停";
      return;
    }

    let remaining = refreshSeconds;
    const updateLabel = () => {
      if (label) label.textContent = `${remaining} 秒後更新`;
    };

    updateLabel();
    window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      remaining -= 1;
      if (remaining <= 0) {
        if (label) label.textContent = "正在更新…";
        window.location.reload();
        return;
      }
      updateLabel();
    }, 1000);
  };

  const markExternalLinks = () => {
    document
      .querySelectorAll('a[target="_blank"]')
      .forEach((link) => {
        const label = link.getAttribute("aria-label") || link.textContent.trim();
        if (label && !label.includes("新分頁")) {
          link.setAttribute("aria-label", `${label}（在新分頁開啟）`);
        }
      });
  };

  setupDashboardFilters();
  setupAutoRefresh();
  markExternalLinks();
  body.classList.add("is-enhanced");
})();
