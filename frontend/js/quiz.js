// frontend/js/quiz.js
let questions = [];

document.addEventListener("DOMContentLoaded", async () => {
  questions = await apiGet("/api/quiz");
  const card = document.getElementById("quiz-card");
  card.innerHTML = `<h2>Answer all ${questions.length} questions</h2>` +
    questions.map(q => `
      <div style="margin-bottom:.8rem">
        <p><strong>Q${q.id}.</strong> ${escapeHtml(q.question)}</p>
        ${Object.entries(q.options).map(([k,v]) =>
          `<label style="margin-right:1rem">
            <input type="radio" name="q${q.id}" value="${k}"/> ${k}. ${escapeHtml(v)}
          </label>`).join("")}
      </div>
    `).join("") +
    `<button onclick="submitQuiz()">Submit</button>`;

  const res = document.getElementById("result-card");
  res.style.display = "block";
  res.innerHTML = `<p style="color:#94a3b8">Complete the quiz to see your score.</p>`;
});

async function submitQuiz(){
  const answers = {};
  questions.forEach(q => {
    const el = document.querySelector(`input[name="q${q.id}"]:checked`);
    if(el) answers[q.id] = el.value;
  });
  const r = await apiPost("/api/quiz/submit", { answers, user_id: "anonymous" });
  document.getElementById("result-card").innerHTML = `
    <h2>Result: ${r.overall_score}/100 — ${r.band}</h2>
    <h3>Category Scores</h3>
    <ul>${Object.entries(r.category_scores).map(([c,s]) =>
      `<li>${escapeHtml(c)}: ${s}%</li>`).join("")}</ul>
    <h3>Personalized Recommendations</h3>
    <ul>${r.recommendations.length
        ? r.recommendations.map(x => `<li>${escapeHtml(x.category)} (${x.score}%) — ${escapeHtml(x.recommendation)}</li>`).join("")
        : "<li>No weak areas detected. Keep it up!</li>"}</ul>
    <p style="color:#94a3b8"><em>${escapeHtml(r.disclaimer)}</em></p>
  `;
  document.getElementById("result-card").scrollIntoView({behavior:"smooth"});
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}