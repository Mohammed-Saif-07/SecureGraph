from __future__ import annotations

import io

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.pdfgen import canvas

from core.attack_path.remediation import ranked_remediations
from core.graph_engine import graph

router = APIRouter()


class ReportRequest(BaseModel):
    scan_id: str | None = Field(default=None, examples=["scan-uuid"])
    title: str = Field(default="SecureGraph Attack Surface Report", examples=["Q2 Payment Platform Attack Surface Report"])


def _build_pdf(title: str) -> io.BytesIO:
    """Build an executive PDF report from current graph evidence."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42)
    styles = getSampleStyleSheet()
    story = [Paragraph(title, styles["Title"]), Paragraph("Executive Summary", styles["Heading2"])]
    paths = graph.attack_paths(limit=8)
    remediations = ranked_remediations(limit=6)
    top_risk = paths[0]["risk_score"] if paths else 0
    story.append(Paragraph(f"SecureGraph found {len(paths)} graph-backed attack paths. Highest current path risk is {top_risk}/10.", styles["BodyText"]))
    story.append(Spacer(1, 14))
    story.append(Paragraph("Top Attack Paths", styles["Heading2"]))
    path_rows = [["CVE", "Package", "Service", "Data", "Risk"]]
    for path in paths:
        path_rows.append([path["cve_id"], path["package_name"], path["service_name"], path["data_name"], str(path["risk_score"])])
    path_table = Table(path_rows, repeatRows=1)
    path_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#172033")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]))
    story.append(path_table)
    story.append(Spacer(1, 14))
    story.append(Paragraph("Remediation Plan", styles["Heading2"]))
    remediation_rows = [["Package", "Current", "Target", "Risk Reduction"]]
    for item in remediations:
        remediation_rows.append([item["package_name"], item["current_version"], item["fixed_version"], str(item["risk_reduction"])])
    remediation_table = Table(remediation_rows, repeatRows=1)
    remediation_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f766e")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]))
    story.append(remediation_table)
    doc.build(story)
    buffer.seek(0)
    return buffer


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


@router.post("/generate")
def generate_report(request: ReportRequest):
    buffer = _build_pdf(request.title)
    headers = {"Content-Disposition": 'attachment; filename="securegraph-executive-report.pdf"'}
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)
