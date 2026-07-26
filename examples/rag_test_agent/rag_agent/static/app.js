const indexForm = document.querySelector("#index-form");
const askForm = document.querySelector("#ask-form");
const folderPath = document.querySelector("#folder-path");
const question = document.querySelector("#question");
const rootFilter = document.querySelector("#root-filter");
const jobState = document.querySelector("#job-state");
const jobCounts = document.querySelector("#job-counts");
const eventsList = document.querySelector("#events");
const answerEl = document.querySelector("#answer");
const sourcesEl = document.querySelector("#sources");
const statsEl = document.querySelector("#stats");
const providerEl = document.querySelector("#provider");

let activeJob = null;

async function refreshStats(root = "") {
  const url = root ? `/api/stats?root=${encodeURIComponent(root)}` : "/api/stats";
  const response = await fetch(url);
  const stats = await response.json();
  statsEl.textContent = `${stats.documents} documents, ${stats.chunks} chunks`;
  providerEl.textContent = `provider: ${stats.embedding_provider}`;
}

function renderEvents(events) {
  eventsList.innerHTML = "";
  for (const event of events.slice(-80).reverse()) {
    const item = document.createElement("li");
    const path = event.relative_path ? ` ${event.relative_path}` : "";
    const count = event.chunks ? ` (${event.chunks} chunks)` : "";
    item.textContent = `${event.phase}${path}${count}`;
    eventsList.appendChild(item);
  }
}

async function pollJob(jobId) {
  activeJob = jobId;
  while (activeJob === jobId) {
    const response = await fetch(`/api/jobs/${jobId}`);
    const job = await response.json();
    jobState.textContent = job.status;
    renderEvents(job.events || []);

    if (job.result) {
      const r = job.result;
      jobCounts.textContent = `${r.directories_seen} dirs, ${r.documents_seen} docs, ${r.chunks_indexed} chunks`;
      rootFilter.value = r.root || "";
      await refreshStats(r.root || "");
    }
    if (job.error) {
      answerEl.textContent = job.error;
      answerEl.classList.add("warning");
    }
    if (job.status === "complete" || job.status === "failed") {
      activeJob = null;
      indexForm.querySelector("button").disabled = false;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 700));
  }
}

function renderSources(sources) {
  sourcesEl.innerHTML = "";
  for (const source of sources || []) {
    const card = document.createElement("article");
    card.className = "source-card";

    const title = document.createElement("h3");
    title.textContent = source.relative_path;
    card.appendChild(title);

    const meta = document.createElement("div");
    meta.className = "source-meta";
    meta.textContent = `chunk ${source.chunk_index} | score ${source.score.toFixed(4)}`;
    card.appendChild(meta);

    const pre = document.createElement("pre");
    pre.textContent = source.content;
    card.appendChild(pre);

    sourcesEl.appendChild(card);
  }
}

indexForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  answerEl.classList.remove("warning");
  const path = folderPath.value.trim();
  if (!path) return;

  indexForm.querySelector("button").disabled = true;
  jobState.textContent = "queued";
  jobCounts.textContent = "";
  eventsList.innerHTML = "";

  const response = await fetch("/api/index", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ folder_path: path }),
  });
  const payload = await response.json();
  pollJob(payload.job_id);
});

askForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  answerEl.classList.remove("warning");
  const q = question.value.trim();
  if (!q) return;

  answerEl.textContent = "Searching...";
  renderSources([]);
  const response = await fetch("/api/ask", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      question: q,
      root: rootFilter.value.trim() || null,
      top_k: 6,
    }),
  });
  const payload = await response.json();
  answerEl.textContent = payload.answer || "";
  renderSources(payload.sources || []);
});

refreshStats().catch(() => {
  statsEl.textContent = "Stats unavailable";
});
