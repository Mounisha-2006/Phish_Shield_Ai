from fpdf import FPDF
from datetime import datetime
import os


def sanitize_for_pdf(text):
    """
    Strip out any character that the PDF's core font (Helvetica) can't
    render — emojis, special Unicode symbols, etc. Unsupported characters
    are replaced with '?' instead of crashing PDF generation entirely.
    This is necessary because Helvetica only supports Latin-1 characters,
    and scanned URLs/email content can contain anything (including emoji).
    """
    if text is None:
        return ''
    if not isinstance(text, str):
        text = str(text)
    return text.encode('latin-1', errors='replace').decode('latin-1')


class PhishShieldReport(FPDF):

    def header(self):
        self.set_fill_color(38, 33, 92)
        self.rect(0, 0, 210, 28, 'F')
        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(206, 203, 246)
        self.set_xy(10, 8)
        self.cell(0, 10, 'PhishShield AI - Security Report')
        self.ln()
        self.set_font('Helvetica', '', 9)
        self.set_text_color(175, 169, 236)
        self.set_xy(10, 18)
        self.cell(0, 6, 'AI-Driven Cyber Threat Detection System')
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10,
            'PhishShield AI  |  Page ' + str(self.page_no()) +
            '  |  Confidential Security Report',
            align='C'
        )

def generate_report(scan_results, user_email, filename=None):

    if not filename:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.expanduser(
            '~/phishshield/reports/report_' + ts + '.pdf'
        )

    pdf = PhishShieldReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)

    now = datetime.now().strftime('%d %B %Y  %H:%M:%S')
    user_email = sanitize_for_pdf(user_email)

    # Report info
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, 'Generated : ' + now)
    pdf.ln()
    pdf.cell(0, 6, 'User      : ' + user_email)
    pdf.ln()
    pdf.cell(0, 6, 'Total scans : ' + str(len(scan_results)))
    pdf.ln(4)

    # Summary box
    high   = sum(1 for s in scan_results if s.get('threat_level') == 'HIGH')
    medium = sum(1 for s in scan_results if s.get('threat_level') == 'MEDIUM')
    low    = sum(1 for s in scan_results if s.get('threat_level') == 'LOW')

    pdf.set_fill_color(238, 237, 254)
    pdf.set_draw_color(175, 169, 236)
    box_y = pdf.get_y()
    pdf.rect(10, box_y, 190, 28, 'FD')
    pdf.set_xy(15, box_y + 4)
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(38, 33, 92)
    pdf.cell(0, 7, 'Executive Summary')
    pdf.ln()
    pdf.set_xy(15, box_y + 13)
    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(60, 6, 'High Risk    : ' + str(high))
    pdf.cell(60, 6, 'Medium Risk  : ' + str(medium))
    pdf.cell(60, 6, 'Safe / Low   : ' + str(low))
    pdf.ln(12)

    def section_title(title):
        pdf.set_fill_color(83, 74, 183)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.cell(0, 8, '  ' + title, fill=True)
        pdf.ln(6)

    section_title('Detailed Scan Results')

    for i, scan in enumerate(scan_results, 1):
        scan_type    = sanitize_for_pdf(scan.get('type', 'Unknown'))
        input_data   = sanitize_for_pdf(str(scan.get('input', 'N/A')))
        threat_level = scan.get('threat_level', 'LOW')
        confidence   = scan.get('confidence', 0)
        timestamp    = sanitize_for_pdf(str(scan.get('time', now)))

        # Replace special characters (em-dash/en-dash were already handled
        # here; sanitize_for_pdf above now catches everything else too,
        # including emoji, so this line is mostly redundant but harmless)
        input_data = input_data.replace('\u2014', '-').replace('\u2013', '-')

        if threat_level == 'HIGH':
            pdf.set_fill_color(252, 235, 235)
            pdf.set_draw_color(240, 149, 149)
            tc = (163, 45, 45)
            bar_color = (226, 75, 74)
        elif threat_level == 'MEDIUM':
            pdf.set_fill_color(250, 238, 218)
            pdf.set_draw_color(250, 199, 117)
            tc = (133, 79, 11)
            bar_color = (186, 117, 23)
        else:
            pdf.set_fill_color(234, 243, 222)
            pdf.set_draw_color(192, 221, 151)
            tc = (59, 109, 17)
            bar_color = (99, 153, 34)

        card_y = pdf.get_y()
        pdf.rect(10, card_y, 190, 38, 'FD')

        # Scan title
        pdf.set_xy(14, card_y + 3)
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(38, 33, 92)
        pdf.cell(0, 6, 'Scan #' + str(i) + ' - ' + scan_type + ' Scanner')
        pdf.ln()

        # Input
        pdf.set_xy(14, card_y + 11)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(80, 80, 80)
        display_input = (
            input_data[:70] + '...'
            if len(input_data) > 70
            else input_data
        )
        pdf.cell(0, 5, 'Input   : ' + display_input)
        pdf.ln()

        # Threat level
        pdf.set_xy(14, card_y + 18)
        pdf.set_font('Helvetica', 'B', 9)
        pdf.set_text_color(tc[0], tc[1], tc[2])
        pdf.cell(60, 5, 'Threat  : ' + threat_level)

        # Confidence
        pdf.set_text_color(80, 80, 80)
        pdf.set_font('Helvetica', '', 9)
        pdf.cell(65, 5, 'Confidence : ' + str(round(confidence, 1)) + '%')

        # Time
        pdf.cell(0, 5, 'Time : ' + timestamp[:19])
        pdf.ln()

        # Confidence bar background
        bar_y = card_y + 28
        pdf.set_fill_color(220, 220, 230)
        pdf.rect(14, bar_y, 170, 4, 'F')

        # Confidence bar fill
        fill_w = (confidence / 100) * 170
        pdf.set_fill_color(bar_color[0], bar_color[1], bar_color[2])
        pdf.rect(14, bar_y, fill_w, 4, 'F')

        pdf.ln(44)

        if pdf.get_y() > 240:
            pdf.add_page()

    # Recommendations
    pdf.ln(4)
    section_title('Security Recommendations')

    tips = [
        '1. Never click links in unsolicited emails - verify by visiting the site directly.',
        '2. Always check the URL carefully before entering login credentials.',
        '3. Look for HTTPS and a valid SSL certificate before submitting any data.',
        '4. Enable two-factor authentication on all important accounts.',
        '5. Report suspicious emails to your IT security team immediately.',
        '6. Keep your browser and antivirus software up to date.',
        '7. Use a password manager to avoid reusing passwords across sites.',
        '8. Be suspicious of emails creating urgency - phishing relies on panic.',
    ]

    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(60, 60, 60)
    for tip in tips:
        pdf.set_x(14)
        pdf.multi_cell(182, 6, tip)
        pdf.ln(1)

    # Footer note
    pdf.ln(6)
    note_y = pdf.get_y()
    pdf.set_fill_color(238, 237, 254)
    pdf.set_draw_color(175, 169, 236)
    pdf.rect(10, note_y, 190, 16, 'FD')
    pdf.set_xy(14, note_y + 3)
    pdf.set_font('Helvetica', 'I', 9)
    pdf.set_text_color(60, 52, 137)
    pdf.multi_cell(182, 5,
        'This report was generated by PhishShield AI using '
        'Machine Learning and Natural Language Processing. '
        'Results are for informational purposes only.'
    )

    pdf.output(filename)
    print('Report saved to: ' + filename)
    return filename


if __name__ == '__main__':
    test_scans = [
        {
            'type'        : 'URL',
            'input'       : 'http://paypal-secure-login.xyz/verify',
            'threat_level': 'HIGH',
            'confidence'  : 94.5,
            'time'        : '2026-06-14 10:23:11'
        },
        {
            'type'        : 'Email',
            'input'       : 'Urgent! Your account will be suspended',
            'threat_level': 'HIGH',
            'confidence'  : 91.2,
            'time'        : '2026-06-14 10:25:44'
        },
        {
            'type'        : 'Clone',
            'input'       : 'http://netflix-free-login.tk',
            'threat_level': 'HIGH',
            'confidence'  : 97.0,
            'time'        : '2026-06-14 10:28:02'
        },
        {
            'type'        : 'URL',
            'input'       : 'https://www.google.com',
            'threat_level': 'LOW',
            'confidence'  : 12.0,
            'time'        : '2026-06-14 10:30:15'
        },
    ]

    path = generate_report(
        scan_results=test_scans,
        user_email='student@example.com'
    )
    print('PDF report generated successfully!')
    print('Open this file: ' + path)