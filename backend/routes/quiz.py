import json
import os
from datetime import datetime

from flask import Blueprint, jsonify, request

from backend.db import get_connection

quiz_bp = Blueprint("quiz", __name__, url_prefix="/api/quiz")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
QUESTIONS_PATH = os.path.join(ROOT, "awareness", "quiz_questions.json")


def _load_questions():
    with open(QUESTIONS_PATH, encoding="utf-8") as f:
        return json.load(f)


@quiz_bp.get("")
def get_quiz():
    qs = _load_questions()
    # Do not reveal correct answers in the client payload
    safe = [{k: v for k, v in q.items() if k not in ("correct", "explanation")}
            for q in qs]
    return jsonify(safe)


@quiz_bp.post("/submit")
def submit_quiz():
    payload = request.get_json(silent=True) or {}
    answers = payload.get("answers", {})
    questions = _load_questions()
    by_id = {str(q["id"]): q for q in questions}

    per_category = {}
    total_correct = 0
    total = len(questions)

    for qid, q in by_id.items():
        cat = q["category"]
        per_category.setdefault(cat, {"correct": 0, "total": 0})
        per_category[cat]["total"] += 1
        if str(answers.get(qid, "")).upper() == q["correct"].upper():
            per_category[cat]["correct"] += 1
            total_correct += 1

    overall = round((total_correct / total) * 100) if total else 0
    category_scores = {
        c: round((v["correct"] / v["total"]) * 100)
        for c, v in per_category.items()
    }

    if overall <= 40:
        band = "Needs Improvement"
    elif overall <= 60:
        band = "Basic Awareness"
    elif overall <= 80:
        band = "Good Awareness"
    else:
        band = "Strong Awareness"

    weakest = sorted(category_scores.items(), key=lambda x: x[1])[:3]
    recs = [
        {"category": c, "score": s,
         "recommendation": f"Review the {c} awareness module."}
        for c, s in weakest if s < 80
    ]

    conn = get_connection()
    conn.execute(
        """INSERT INTO quiz_results
           (anonymous_user_id, overall_score, category_scores, created_at)
           VALUES (?,?,?,?)""",
        (payload.get("user_id", "anonymous"), overall,
         json.dumps(category_scores),
         datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
    )
    conn.commit()
    conn.close()

    return jsonify({
        "overall_score": overall,
        "band": band,
        "category_scores": category_scores,
        "recommendations": recs,
        "disclaimer": ("This is an educational score, not an employee "
                       "fitness or competency judgment."),
    })