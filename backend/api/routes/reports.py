from __future__ import annotations

import io

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from core.attack_path.remediation import ranked_remediations
from core.graph_engine import graph

router = APIRouter()


@router.get("/pdf")
def pdf_report():
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 54
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(54, y, "SecureGraph Attack Surface Report")
    y -= 28
    pdf.setFont("Helvetica", 10)
    pdf.drawString(54, y, "Built by Mohammed Saif | SecureGraph vulnerability intelligence platform")
    y -= 34
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(54, y, "Top Attack Paths")
    y -= 18
    pdf.setFont("Helvetica", 10)
    for path in graph.attack_paths(limit=6):
        pdf.drawString(54, y, f"{path['cve_id']} -> {path['package_name']} -> {path['service_name']} -> {path['data_name']} | Risk {path['risk_score']}/10")
        y -= 16
    y -= 10
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(54, y, "Recommended Patches")
    y -= 18
    pdf.setFont("Helvetica", 10)
    for item in ranked_remediations(limit=5):
        pdf.drawString(54, y, f"{item['package_name']}: {item['current_version']} -> {item['fixed_version']} | Risk reduction {item['risk_reduction']}")
        y -= 16
    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    headers = {"Content-Disposition": 'attachment; filename="securegraph-report.pdf"'}
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)
