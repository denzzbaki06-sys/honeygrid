package com.honeygrid.honeygrid.controller;

import com.honeygrid.honeygrid.model.AttackLog;
import com.honeygrid.honeygrid.repository.AttackLogRepository;
import com.itextpdf.text.*;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfWriter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/api/v1/reports")
public class PdfReportController {

    private final AttackLogRepository repository;

    public PdfReportController(AttackLogRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/download/pdf")
    public ResponseEntity<byte[]> generatePdfReport() {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            Document document = new Document(PageSize.A4, 36, 36, 36, 36);
            PdfWriter.getInstance(document, out);
            document.open();

            // Başlık Stilleri
            Font headerFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, BaseColor.RED);
            Font subHeaderFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, BaseColor.DARK_GRAY);
            Font cellFont = FontFactory.getFont(FontFactory.HELVETICA, 9, BaseColor.BLACK);

            // Başlık Ekleme
            Paragraph title = new Paragraph("HONEYGRID // THREAT INTELLIGENCE SUMMARY REPORT", headerFont);
            title.setAlignment(Element.ALIGN_CENTER);
            document.add(title);

            Paragraph timeStamp = new Paragraph("Latest 1000 observations (heuristic classifications). Generated on: " + new Date().toString(), subHeaderFont);
            timeStamp.setAlignment(Element.ALIGN_CENTER);
            timeStamp.setSpacingAfter(20);
            document.add(timeStamp);

            // Tablo Oluşturma
            PdfPTable table = new PdfPTable(6);
            table.setWidthPercentage(100);
            table.setWidths(new float[]{2.5f, 1.5f, 2f, 2f, 1.5f, 1.5f});

            String[] headers = {"IP Address", "Country", "Protocol", "MITRE Code", "Threat Score", "Intent"};
            for (String header : headers) {
                PdfPCell cell = new PdfPCell(new Phrase(header, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, BaseColor.WHITE)));
                cell.setBackgroundColor(BaseColor.DARK_GRAY);
                cell.setHorizontalAlignment(Element.ALIGN_CENTER);
                table.addCell(cell);
            }

            List<AttackLog> logs = repository.findAll(org.springframework.data.domain.PageRequest.of(0, 1000, org.springframework.data.domain.Sort.by("id").descending())).getContent();
            for (AttackLog log : logs) {
                table.addCell(new Phrase(log.getIpAddress(), cellFont));
                table.addCell(new Phrase(log.getCountry() != null ? log.getCountry() : "Global", cellFont));
                table.addCell(new Phrase(log.getProtocol(), cellFont));
                table.addCell(new Phrase(log.getMitreTechniqueId() != null ? log.getMitreTechniqueId() : "T1210", cellFont));
                table.addCell(new Phrase(String.valueOf(log.getThreatScore()), cellFont));
                table.addCell(new Phrase(log.getPredictedIntent() != null ? log.getPredictedIntent() : "BOT", cellFont));
            }

            document.add(table);
            document.close();

            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setContentType(MediaType.APPLICATION_PDF);
            httpHeaders.setContentDispositionFormData("attachment", "honeygrid_threat_report.pdf");

            return ResponseEntity.ok().headers(httpHeaders).body(out.toByteArray());

        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}