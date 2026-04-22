// pdf-generator.js — Monthly invoice PDF generator for TASKAFÉ
// Depends on jsPDF being loaded globally as window.jspdf

/**
 * Generate and download a monthly PDF invoice for a client.
 * @param {object} client - Client record from state.clients
 * @param {object[]} monthlySales - Sales for the client this month, sorted ascending by created_at
 * @param {string} monthLabel - Human-readable month label (e.g. "avril 2026")
 * @param {string} thisMonth - ISO month string (e.g. "2026-04")
 * @param {function} formatDh - Format a number as "X.XX DHS"
 * @param {function} formatQty - Format a quantity number (no trailing .00)
 */
export async function generateMonthlyPDF(client, monthlySales, monthLabel, thisMonth, formatDh, formatQty) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

  const now = new Date();
  const margin = 15;
  const pageW = 210;
  const pageH = 297;
  let y = margin;

  const colBlack = [17, 17, 17];
  const colGray = [107, 93, 85];
  const colLight = [245, 242, 238];

  // Watermark / filigrane logo centré
  try {
    const logoImg = new Image();
    logoImg.crossOrigin = 'anonymous';
    await new Promise(resolve => {
      logoImg.onload = resolve;
      logoImg.onerror = resolve;
      logoImg.src = 'icon-512.png.PNG';
    });
    if (logoImg.complete && logoImg.naturalWidth > 0) {
      const canvas = document.createElement('canvas');
      canvas.width = logoImg.naturalWidth;
      canvas.height = logoImg.naturalHeight;
      const ctx = canvas.getContext('2d');
      ctx.globalAlpha = 0.07;
      ctx.drawImage(logoImg, 0, 0);
      const wdata = canvas.toDataURL('image/png');
      const wSize = 110;
      doc.addImage(wdata, 'PNG', (pageW - wSize) / 2, (pageH - wSize) / 2, wSize, wSize);
    }
  } catch (_) { /* skip watermark on error */ }

  // ── Header block ────────────────────────────────────────────────────────
  doc.setFillColor(...colLight);
  doc.roundedRect(margin, y, pageW - margin * 2, 30, 4, 4, 'F');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(20);
  doc.setTextColor(...colBlack);
  doc.text('TASKAFÉ', margin + 6, y + 11);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(...colGray);
  doc.text('Distribution café — Gestion commerciale', margin + 6, y + 18);

  const invoiceNum = `FC-${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}-${client.name.replace(/\s+/g,'').substring(0,6).toUpperCase()}`;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(...colBlack);
  doc.text(`N° ${invoiceNum}`, pageW - margin - 5, y + 9, { align: 'right' });
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(...colGray);
  doc.text(`Période : ${monthLabel}`, pageW - margin - 5, y + 15, { align: 'right' });
  doc.text(`Émis le : ${now.toLocaleDateString('fr-FR')}`, pageW - margin - 5, y + 21, { align: 'right' });

  y += 36;

  // ── Client block ─────────────────────────────────────────────────────────
  doc.setFillColor(255, 255, 255);
  doc.setDrawColor(220, 215, 208);
  doc.roundedRect(margin, y, pageW - margin * 2, 30, 3, 3, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(...colGray);
  doc.text('FACTURÉ À', margin + 5, y + 7);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(...colBlack);
  doc.text(client.name, margin + 5, y + 15);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(...colGray);
  let infoY = y + 22;
  if (client.address) { doc.text(`Adresse : ${client.address}`, margin + 5, infoY); infoY += 6; }
  if (client.ice) doc.text(`ICE : ${client.ice}`, margin + 5, infoY);

  y += 36;

  // ── Table header ─────────────────────────────────────────────────────────
  doc.setFillColor(...colBlack);
  doc.rect(margin, y, pageW - margin * 2, 9, 'F');

  const cDate = margin + 3;
  const cCat  = margin + 36;
  const cQty  = margin + 76;
  const cUnit = margin + 110;
  const cTot  = pageW - margin - 3;

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(255, 255, 255);
  doc.text('Date', cDate, y + 6);
  doc.text('Catégorie', cCat, y + 6);
  doc.text('Quantité', cQty, y + 6);
  doc.text('Prix unit.', cUnit, y + 6);
  doc.text('Total', cTot, y + 6, { align: 'right' });

  y += 9;

  // ── Table rows ────────────────────────────────────────────────────────────
  let grandTotal = 0;
  monthlySales.forEach((s, idx) => {
    if (y > pageH - 50) {
      doc.addPage();
      y = margin;
    }
    const rowBg = idx % 2 === 0 ? [250, 247, 244] : [255, 255, 255];
    doc.setFillColor(...rowBg);
    doc.rect(margin, y, pageW - margin * 2, 7.5, 'F');

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8);
    doc.setTextColor(...colBlack);

    doc.text(new Date(s.created_at).toLocaleDateString('fr-FR'), cDate, y + 5.2);
    doc.text(s.category, cCat, y + 5.2);
    doc.text(`${formatQty(s.quantity)} ${s.category === 'SUCRE' ? 'pcs' : 'kg'}`, cQty, y + 5.2);
    doc.text(formatDh(s.unit_price), cUnit, y + 5.2);
    doc.text(formatDh(s.total_price), cTot, y + 5.2, { align: 'right' });

    grandTotal += Number(s.total_price || 0);
    y += 7.5;
  });

  // Separator
  doc.setDrawColor(220, 215, 208);
  doc.line(margin, y + 2, pageW - margin, y + 2);
  y += 8;

  // ── Totals block ──────────────────────────────────────────────────────────
  const totW = 80;
  const totX = pageW - margin - totW;
  doc.setFillColor(...colLight);
  doc.roundedRect(totX, y, totW, 18, 3, 3, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(...colGray);
  doc.text('TOTAL', totX + 4, y + 7);
  doc.setFontSize(14);
  doc.setTextColor(...colBlack);
  doc.text(formatDh(grandTotal), pageW - margin - 4, y + 14, { align: 'right' });

  y += 26;

  // ── Footer ────────────────────────────────────────────────────────────────
  doc.setDrawColor(...colLight);
  doc.line(margin, y, pageW - margin, y);
  y += 5;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(...colGray);
  doc.text('TASKAFÉ — Suivi des ventes café', pageW / 2, y, { align: 'center' });
  doc.text(
    `Document généré automatiquement le ${now.toLocaleDateString('fr-FR')} à ${now.toLocaleTimeString('fr-FR')}`,
    pageW / 2, y + 5, { align: 'center' }
  );

  const fileName = `taskafe-${client.name.replace(/\s+/g,'-').toLowerCase()}-${thisMonth}.pdf`;
  doc.save(fileName);
}
