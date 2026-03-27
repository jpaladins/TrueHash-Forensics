import os
import hashlib
import threading
from datetime import datetime
import xml.etree.ElementTree as ET
import io
import json
import wx
import wx.richtext as rt

from fpdf import FPDF
from fpdf.html import HTMLMixin
from pyhanko.sign import timestamps
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers import pdf_signer

# OpenTimestamps imports
from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.op import OpSHA256, OpAppend
from opentimestamps.core.serialize import StreamSerializationContext
from opentimestamps.core.timestamp import DetachedTimestampFile, make_merkle_tree
import opentimestamps.calendar


# --- FUNZIONI DI SUPPORTO ---

def calcola_hash_sha256(filepath, block_size=65536):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(block_size)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except Exception as e:
        return f"Errore: {e}"

def format_bytes(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def sanitize_text(text):
    if not isinstance(text, str):
        return str(text)
    return text.encode('cp1252', 'replace').decode('cp1252')

def parse_richtext_xml_to_html(xml_str):
    if not xml_str.strip():
        return ""
    
    # Rimuovi il namespace per permettere al parser standard di trovare i tag
    xml_str = xml_str.replace('xmlns="http://www.wxwidgets.org"', '')
    
    try:
        root = ET.fromstring(xml_str)
    except Exception:
        return ""
    
    html_parts = []
    # In wx.richtext: alignment=1 -> left, 2 -> right?, wait, in my test output: 
    # Left is 1, Center is 2, Right is 3.
    # We will use simple mapping
    
    for layout in root.iter('paragraphlayout'):
        for para in layout.findall('paragraph'):
            align_val = para.get('alignment', '1')
            if align_val == '2':
                align_str = 'center'
            elif align_val == '3':
                align_str = 'right'
            else:
                align_str = 'left'
            
            p_html = f'<p align="{align_str}">'
            has_text = False
            for text_node in para.findall('text'):
                content = text_node.text
                if not content: continue
                has_text = True
                
                content = content.replace('<', '&lt;').replace('>', '&gt;')
                
                fw = text_node.get('fontweight', '400')
                fs = text_node.get('fontstyle', '90')
                is_bold = fw in ('700', 'bold')
                is_italic = fs == '93'
                
                if is_bold: content = f"<b>{content}</b>"
                if is_italic: content = f"<i>{content}</i>"
                
                p_html += content
            
            p_html += '</p>'
            if has_text:
                html_parts.append(p_html)
            else:
                # empty paragraph
                html_parts.append('<p><br/></p>')

    return "".join(html_parts)

def applica_marca_temporale_pdf(pdf_originale_path, pdf_marcato_path):
    tsa_url = 'http://timestamp.digicert.com'
    tst_client = timestamps.HTTPTimeStamper(url=tsa_url)
    try:
        with open(pdf_originale_path, 'rb') as doc_file:
            writer = IncrementalPdfFileWriter(doc_file)
            timestamp_setup = pdf_signer.PdfTimeStamper(timestamper=tst_client)
            with open(pdf_marcato_path, 'wb') as out_file:
                timestamp_setup.timestamp_pdf(writer, md_algorithm='sha256', output=out_file)
        return True, "Marca temporale applicata con successo."
    except Exception as e:
        return False, str(e)


def notarizza_opentimestamps(filepath):
    ots_path = filepath + '.ots'
    try:
        with open(filepath, 'rb') as fd:
            file_timestamp = DetachedTimestampFile.from_fd(OpSHA256(), fd)

        nonce_appended_stamp = file_timestamp.timestamp.ops.add(OpAppend(os.urandom(16)))
        merkle_root = nonce_appended_stamp.ops.add(OpSHA256())

        calendar_urls = [
            'https://a.pool.opentimestamps.org',
            'https://b.pool.opentimestamps.org',
            'https://a.pool.eternitywall.com',
        ]

        from queue import Queue, Empty
        q = Queue()
        timeout = 15

        for url in calendar_urls:
            def submit_thread(cal_url, msg, queue, tout):
                try:
                    remote = opentimestamps.calendar.RemoteCalendar(
                        cal_url, user_agent="TrueHash-Forensics/2.4"
                    )
                    result = remote.submit(msg, timeout=tout)
                    queue.put(result)
                except Exception as exc:
                    queue.put(exc)

            t = threading.Thread(target=submit_thread, args=(url, merkle_root.msg, q, timeout))
            t.start()

        import time
        start = time.time()
        merged = 0
        for _ in range(len(calendar_urls)):
            try:
                remaining = max(0, timeout - (time.time() - start))
                result = q.get(block=True, timeout=remaining)
                if isinstance(result, Timestamp):
                    merkle_root.merge(result)
                    merged += 1
            except Empty:
                continue

        if merged == 0:
            return False, "Nessun calendar server ha risposto entro il timeout.", ""

        with open(ots_path, 'wb') as ots_fd:
            ctx = StreamSerializationContext(ots_fd)
            file_timestamp.serialize(ctx)

        return True, f"Notarizzazione completata ({merged} server).", ots_path

    except Exception as e:
        return False, f"Errore OpenTimestamps: {e}", ""


# --- LOGICA REPORT PRINCIPALE ---

class ForensicReport(FPDF, HTMLMixin):
    def __init__(self, firm_settings, case_name, investigator, target_path, has_timestamp, has_ots=False, has_extracted_zip=False):
        super().__init__()
        self.firm_settings = firm_settings
        self.case_name = sanitize_text(case_name)
        self.investigator = sanitize_text(investigator)
        self.target_path = sanitize_text(target_path)
        self.has_timestamp = has_timestamp
        self.has_ots = has_ots
        self.has_extracted_zip = has_extracted_zip
        self.set_auto_page_break(auto=True, margin=15)
        self.is_cover = True
        self.file_links = {}

    def header(self):
        if self.is_cover: return
        self.set_font("helvetica", "I", 9)
        self.set_text_color(128, 128, 128)
        self.cell(0, 6, f"Caso: {self.case_name} | Analisi Hash SHA-256", align="L")
        self.ln(8)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_draw_color(180, 180, 180)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        cert_parts = []
        if self.has_timestamp: cert_parts.append("Marca Temporale TSA")
        if self.has_ots: cert_parts.append("Blockchain Bitcoin (OTS)")
        if cert_parts:
            self.cell(0, 4, f"Sigillato con: {' + '.join(cert_parts)}.", align="C", new_x="LMARGIN", new_y="NEXT")
        else:
            self.cell(0, 4, "Report generato localmente. SHA-256.", align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 4, f"Generato con TrueHash Forensics | Pagina {self.page_no()}/{{nb}}", align="C")

    def crea_copertina(self):
        self.add_page()
        self.ln(5)
        
        # 1) Logo e Intestazione Studio (WYSIWYG HTML)
        logo_path = self.firm_settings.get('logo_path', '')
        if logo_path and os.path.exists(logo_path):
            try:
                self.image(logo_path, x=65, y=self.get_y(), w=80)
                self.ln(80)
            except:
                self.ln(5)
        
        # Genera Intestazione Rich Text (HTML)
        rich_xml = self.firm_settings.get('rich_text_xml', '')
        if rich_xml:
            html_intestazione = parse_richtext_xml_to_html(rich_xml)
            if html_intestazione:
                self.set_font("helvetica", "", 11)
                self.set_text_color(0, 0, 0)
                try:
                    self.write_html(html_intestazione)
                    self.ln(5)
                except Exception as e:
                    self.set_text_color(200, 0, 0)
                    self.multi_cell(0, 5, f"[Errore parser HTML: {e}]", align="C")
                    self.set_text_color(0, 0, 0)
        
        self.ln(10)

        # 2) Titolo Principale
        self.set_font("helvetica", "B", 24)
        self.set_text_color(33, 58, 143)
        self.cell(0, 15, "REPORT DI ACQUISIZIONE FORENSE", align="C", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "", 13)
        self.set_text_color(80, 80, 80)
        self.cell(0, 10, "Estrazione sicura delle firme digitali (Hash SHA-256)", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(15)

        # 3) BOX Dettagli
        self.set_fill_color(245, 245, 245)
        self.set_draw_color(200, 200, 200)
        self.set_font("helvetica", "B", 11)
        self.set_text_color(0, 0, 0)

        self.cell(50, 12, " Riferimento Caso:", border="LT", fill=True)
        self.set_font("helvetica", "", 11)
        self.cell(0, 12, f" {self.case_name}", border="TR", new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "B", 11)
        self.cell(50, 12, " Investigatore:", border="L", fill=True)
        self.set_font("helvetica", "", 11)
        self.cell(0, 12, f" {self.investigator}", border="R", new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "B", 11)
        self.cell(50, 12, " Target Analizzato:", border="L", fill=True)
        self.set_font("helvetica", "I", 10)
        self.cell(0, 12, f" {self.target_path}", border="R", new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "B", 11)
        self.cell(50, 12, " Data Operazione:", border="L", fill=True)
        self.set_font("helvetica", "", 11)
        self.cell(0, 12, f" {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", border="R", new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "B", 11)
        self.cell(50, 12, " Certificazione:", border="LB", fill=True)

        cert_labels = []
        if self.has_timestamp: cert_labels.append("TSA")
        if self.has_ots: cert_labels.append("Blockchain OTS")
        if cert_labels:
            self.set_font("helvetica", "B", 11)
            self.set_text_color(0, 100, 0)
            self.cell(0, 12, f" {' + '.join(cert_labels)}", border="RB", new_x="LMARGIN", new_y="NEXT")
        else:
            self.set_font("helvetica", "I", 11)
            self.set_text_color(150, 0, 0)
            self.cell(0, 12, " Nessuna / Hash Locale", border="RB", new_x="LMARGIN", new_y="NEXT")

        self.set_text_color(0, 0, 0)
        self.is_cover = False

    def _costruisci_albero(self, base_path, files):
        albero = {}
        for f in files:
            percorso_relativo = os.path.relpath(f, base_path)
            parti = percorso_relativo.split(os.sep)
            corrente = albero
            for parte in parti[:-1]:
                corrente = corrente.setdefault(parte, {})
            corrente[parti[-1]] = f
        return albero

    def _stampa_nodo(self, nodo, indent_level=0):
        chiavi_ordinate = sorted(nodo.keys(), key=lambda k: (isinstance(nodo[k], str), k.lower()))

        for chiave in chiavi_ordinate:
            if self.get_y() > 260: self.add_page()
            x_pos = 15 + (indent_level * 8)
            self.set_x(x_pos)

            if isinstance(nodo[chiave], dict):
                self.set_font("helvetica", "B", 10)
                self.set_text_color(33, 58, 143)
                self.cell(0, 6, f"[+] {chiave}/", new_x="LMARGIN", new_y="NEXT")
                self._stampa_nodo(nodo[chiave], indent_level + 1)
            else:
                filepath = nodo[chiave]
                link_id = self.file_links.get(filepath)
                self.set_font("helvetica", "U", 10)
                self.set_text_color(0, 102, 204)
                self.cell(0, 6, sanitize_text(f"{chiave}"), link=link_id, new_x="LMARGIN", new_y="NEXT")

    def crea_indice(self, target_path, files_to_hash):
        self.add_page()
        self.set_font("helvetica", "B", 16)
        self.set_text_color(33, 58, 143)
        self.cell(0, 15, "INDICE INTERATTIVO DEI REPERTI", new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "I", 9)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, "Clicca sul nome di un file per visualizzarne i dettagli e il codice hash.", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)

        for f in files_to_hash:
            self.file_links[f] = self.add_link()

        if os.path.isfile(target_path) and not getattr(self, 'has_extracted_zip', False):
            link_id = self.file_links[target_path]
            self.set_font("helvetica", "U", 11)
            self.set_text_color(0, 102, 204)
            self.cell(0, 8, f"[FILE] {os.path.basename(target_path)}", link=link_id, new_x="LMARGIN", new_y="NEXT")
            return

        base_path = target_path
        if getattr(self, 'has_extracted_zip', False):
            base_path = os.path.dirname(target_path)

        albero = self._costruisci_albero(base_path, files_to_hash)
        self.set_font("helvetica", "B", 11)
        self.set_text_color(33, 58, 143)
        if getattr(self, 'has_extracted_zip', False):
            self.cell(0, 8, f"[DIR BASE] Contenuto estratto e archivio originario/", new_x="LMARGIN", new_y="NEXT")
        else:
            self.cell(0, 8, f"[DIR BASE] {os.path.basename(target_path)}/", new_x="LMARGIN", new_y="NEXT")
        self._stampa_nodo(albero, indent_level=1)
        self.set_text_color(0, 0, 0)
        self.ln(5)

    def crea_conclusioni(self, totale_file, totale_byte, durata_secondi, note_investigative):
        self.add_page()
        self.set_font("helvetica", "B", 16)
        self.set_text_color(33, 58, 143)
        self.cell(0, 15, "CONCLUSIONI E RIEPILOGO", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)
        self.set_font("helvetica", "", 11)
        self.set_text_color(0, 0, 0)
        testo_conclusione = ("La procedura di acquisizione ed estrazione delle impronte hash si e' conclusa "
                             "correttamente. Tutti i file elencati in questo documento sono stati analizzati "
                             "utilizzando l'algoritmo di hashing sicuro SHA-256, standard di settore.")
        if getattr(self, 'has_extracted_zip', False):
            testo_conclusione += ("\n\nNota: Il file ZIP originale selezionato e' stato scompattato su richiesta dell'operatore. "
                                  "L'analisi ha quindi incluso sia l'impronta hash dell'archivio compresso originale sia le impronte "
                                  "di tutti i file estratti nella cartella dedicata.")
        self.multi_cell(0, 6, testo_conclusione)
        self.ln(5)

        if note_investigative.strip():
            self.set_font("helvetica", "B", 12)
            self.set_text_color(33, 58, 143)
            self.cell(0, 10, "Note Integrative dell'Operatore:", new_x="LMARGIN", new_y="NEXT")
            self.set_font("helvetica", "", 11)
            self.set_text_color(0, 0, 0)
            self.set_fill_color(248, 248, 240)
            self.set_draw_color(200, 200, 200)
            self.multi_cell(0, 6, sanitize_text(note_investigative.strip()), border=1, fill=True)
            self.ln(5)

        self.set_font("helvetica", "B", 12)
        self.set_text_color(33, 58, 143)
        self.cell(0, 10, "Dettagli di Certificazione Temporale:", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "", 11)
        self.set_text_color(0, 0, 0)
        if self.has_timestamp:
            testo_tsa = ("A questo report e' stata applicata una Marca Temporale crittografica. "
                         "L'impronta hash di questo PDF e' stata inviata alla TSA 'DigiCert', "
                         "che ha incorporato una firma basata su server certificati.")
            self.multi_cell(0, 6, testo_tsa)
        else:
            self.set_text_color(150, 0, 0)
            testo_tsa = ("ATTENZIONE: A questo report NON e' stata applicata una Marca Temporale TSA. "
                         "La data riportata si basa unicamente sull'orologio locale del computer.")
            self.multi_cell(0, 6, testo_tsa)
            self.set_text_color(0, 0, 0)

        self.ln(5)
        self.set_font("helvetica", "B", 12)
        self.set_text_color(33, 58, 143)
        self.cell(0, 10, "Notarizzazione Blockchain (OpenTimestamps):", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "", 11)
        self.set_text_color(0, 0, 0)
        if self.has_ots:
            testo_ots = ("Questo documento e' stato notarizzato sulla blockchain Bitcoin tramite il protocollo "
                         "OpenTimestamps. Un file di prova (.ots) e' stato generato accanto al report PDF. "
                         "La prova e' stata sottomessa ai calendar server pubblici e verra' ancorata "
                         "alla blockchain Bitcoin entro alcune ore. La verifica puo' essere effettuata "
                         "su https://opentimestamps.org.")
            self.multi_cell(0, 6, testo_ots)
        else:
            self.set_text_color(150, 0, 0)
            testo_ots = ("NOTA: Nessuna notarizzazione blockchain OpenTimestamps e' stata richiesta "
                         "per questo report.")
            self.multi_cell(0, 6, testo_ots)
            self.set_text_color(0, 0, 0)

        self.ln(10)

        self.set_font("helvetica", "B", 12)
        self.cell(0, 10, "Statistiche dell'Acquisizione:", new_x="LMARGIN", new_y="NEXT")
        self.set_fill_color(240, 240, 240)
        self.set_draw_color(200, 200, 200)
        self.set_font("helvetica", "B", 11)
        self.cell(80, 10, " Totale Reperti Analizzati:", border="LT", fill=True)
        self.set_font("helvetica", "", 11)
        self.cell(0, 10, f" {totale_file} file", border="TR", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "B", 11)
        self.cell(80, 10, " Volume Dati Processati:", border="L", fill=True)
        self.set_font("helvetica", "", 11)
        self.cell(0, 10, f" {format_bytes(totale_byte)}", border="R", new_x="LMARGIN", new_y="NEXT")
        self.set_font("helvetica", "B", 11)
        self.cell(80, 10, " Tempo di Esecuzione:", border="LB", fill=True)
        self.set_font("helvetica", "", 11)
        self.cell(0, 10, f" {durata_secondi:.2f} secondi", border="RB", new_x="LMARGIN", new_y="NEXT")

        self.ln(15)
        self.set_font("helvetica", "I", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 5, "Documento generato automaticamente e in modo sicuro tramite il software TrueHash Forensics.", align="C", new_x="LMARGIN", new_y="NEXT")

class VerbaleConsegna(FPDF, HTMLMixin):
    def crea_verbale(self, caso, investigatore, logo_path, rich_xml, main_pdf_path, main_pdf_hash, timestamp_applicato, ots_applicato=False):
        self.add_page()
        self.set_auto_page_break(auto=True, margin=15)

        if logo_path and os.path.exists(logo_path):
            try:
                self.image(logo_path, x=85, y=10, w=40)
                self.ln(30)
            except: pass
        else:
            self.ln(10)

        if rich_xml:
            html_intestazione = parse_richtext_xml_to_html(rich_xml)
            if html_intestazione:
                self.set_font("helvetica", "", 10)
                try:
                    self.write_html(html_intestazione)
                    self.ln(5)
                except:
                    pass

        self.set_font("helvetica", "B", 18)
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, "VERBALE DI CONSEGNA E CERTIFICAZIONE HASH", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(5)
        self.set_draw_color(0, 0, 0)
        self.line(20, self.get_y(), 190, self.get_y())
        self.ln(15)

        self.set_font("helvetica", "", 12)
        testo_intro = (f"Il sottoscritto Investigatore/Operatore {sanitize_text(investigatore)}, in riferimento al "
                       f"fascicolo/caso denominato \"{sanitize_text(caso)}\", con il presente verbale dichiara di aver "
                       f"generato tramite il software TrueHash Forensics e di consegnare in allegato il "
                       f"Report di Acquisizione Forense relativo alle operazioni compiute in data {datetime.now().strftime('%d/%m/%Y')}.")
        self.multi_cell(0, 8, testo_intro)
        self.ln(10)

        self.set_font("helvetica", "B", 12)
        self.cell(0, 10, "Dettagli del Documento Consegnato a garanzia della Catena di Custodia:", new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

        nome_file = os.path.basename(main_pdf_path)
        dim_file = os.path.getsize(main_pdf_path)

        self.set_fill_color(245, 245, 245)
        self.set_font("helvetica", "B", 10)
        self.cell(40, 10, " Nome File:", border="LT", fill=True)
        self.set_font("helvetica", "", 10)
        self.cell(0, 10, sanitize_text(f" {nome_file}"), border="TR", new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "B", 10)
        self.cell(40, 10, " Dimensione:", border="L", fill=True)
        self.set_font("helvetica", "", 10)
        self.cell(0, 10, f" {format_bytes(dim_file)}", border="R", new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "B", 10)
        self.cell(40, 10, " Sicurezza TSA:", border="L", fill=True)
        self.set_font("helvetica", "", 10)
        tsa_testo = "Si - Marca Temporale Applicata" if timestamp_applicato else "No - Solo Hash Locale"
        self.cell(0, 10, f" {tsa_testo}", border="R", new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "B", 10)
        self.cell(40, 10, " Blockchain OTS:", border="L", fill=True)
        self.set_font("helvetica", "", 10)
        ots_testo = "Si - Notarizzato su Bitcoin" if ots_applicato else "No"
        self.cell(0, 10, f" {ots_testo}", border="R", new_x="LMARGIN", new_y="NEXT")

        self.set_font("helvetica", "B", 10)
        self.cell(40, 10, " HASH SHA-256:", border="LB", fill=True)
        self.set_font("courier", "B", 10)
        self.cell(0, 10, f" {main_pdf_hash}", border="RB", new_x="LMARGIN", new_y="NEXT")

        self.ln(20)

        self.set_font("helvetica", "", 11)
        self.multi_cell(0, 6, "La stringa SHA-256 sovrascritta identifica in modo univoco il file PDF consegnato. "
                              "Qualsiasi alterazione, anche di un solo bit del documento originale, produrra' "
                              "un valore hash differente, invalidando la presente certificazione.")
        self.ln(30)

        self.set_font("helvetica", "", 12)
        self.cell(90, 10, "Firma di chi consegna:", align="C")
        self.cell(90, 10, "Firma di chi riceve:", align="C", new_x="LMARGIN", new_y="NEXT")
        self.ln(15)
        self.cell(90, 10, "__________________________", align="C")
        self.cell(90, 10, "__________________________", align="C", new_x="LMARGIN", new_y="NEXT")


# --- WXPYTHON WIZARD GUI ---

class SettingsDialog(wx.Dialog):
    """Dialog WYSIWYG per l'Intestazione Studio Forense (da inserire alla fine del logo)."""
    def __init__(self, parent, settings_data):
        super().__init__(parent, title="Impostazioni Intestazione e Logo", size=(600, 500))
        
        self.settings_data = settings_data
        sizer = wx.BoxSizer(wx.VERTICAL)

        # Editor di testo Ricco (WYSIWYG)
        lbl_rtc = wx.StaticText(self, label="Testo Riformattato (Allineamento, Grassetto, Corsivo):\nQuesta intestazione verra' stampata ad inizio pagina, appena sotto al logo.")
        sizer.Add(lbl_rtc, 0, wx.ALL | wx.EXPAND, 15)

        tb_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        btn_b = wx.Button(self, label="B", size=(30, 30))
        btn_i = wx.Button(self, label="I", size=(30, 30))
        tb_sizer.Add(btn_b, 0, wx.RIGHT, 5)
        tb_sizer.Add(btn_i, 0, wx.RIGHT, 15)
        
        btn_l = wx.Button(self, label="Sinistra", size=(60, 30))
        btn_c = wx.Button(self, label="Centro", size=(60, 30))
        btn_r = wx.Button(self, label="Destra", size=(60, 30))
        tb_sizer.Add(btn_l, 0, wx.RIGHT, 5)
        tb_sizer.Add(btn_c, 0, wx.RIGHT, 5)
        tb_sizer.Add(btn_r, 0, wx.RIGHT, 5)
        
        sizer.Add(tb_sizer, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 15)

        self.rtc = rt.RichTextCtrl(self, style=wx.TE_MULTILINE | wx.TE_RICH2)
        sizer.Add(self.rtc, 1, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 15)
        
        btn_b.Bind(wx.EVT_BUTTON, self.on_bold)
        btn_i.Bind(wx.EVT_BUTTON, self.on_italic)
        btn_l.Bind(wx.EVT_BUTTON, self.on_align_left)
        btn_c.Bind(wx.EVT_BUTTON, self.on_align_center)
        btn_r.Bind(wx.EVT_BUTTON, self.on_align_right)

        # Restore XML Se presente
        rich_xml = settings_data.get('rich_text_xml', '')
        if rich_xml:
            handler = rt.RichTextXMLHandler()
            stream = io.BytesIO(rich_xml.encode('utf-8'))
            self.rtc.GetBuffer().AddHandler(handler)
            handler.LoadFile(self.rtc.GetBuffer(), stream)
            self.rtc.Refresh()

        # Selezione Logo
        logo_sizer = wx.BoxSizer(wx.HORIZONTAL)
        lbl_logo = wx.StaticText(self, label="Logo Ente:")
        self.tc_logo = wx.TextCtrl(self, value=settings_data.get('logo_path', ''), style=wx.TE_READONLY)
        btn_logo = wx.Button(self, label="Sfoglia...")
        btn_logo.Bind(wx.EVT_BUTTON, self.on_select_logo)
        
        logo_sizer.Add(lbl_logo, 0, wx.ALIGN_CENTER_VERTICAL | wx.RIGHT, 10)
        logo_sizer.Add(self.tc_logo, 1, wx.EXPAND | wx.RIGHT, 5)
        logo_sizer.Add(btn_logo, 0)
        sizer.Add(logo_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 15)

        line = wx.StaticLine(self)
        sizer.Add(line, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 15)

        btn_sizer = wx.StdDialogButtonSizer()
        btn_ok = wx.Button(self, wx.ID_OK, label="Salva")
        btn_cancel = wx.Button(self, wx.ID_CANCEL, label="Annulla")
        btn_sizer.AddButton(btn_ok)
        btn_sizer.AddButton(btn_cancel)
        btn_sizer.Realize()
        
        sizer.Add(btn_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 15)
        self.SetSizer(sizer)

    def on_bold(self, event):
        self.rtc.ApplyBoldToSelection()

    def on_italic(self, event):
        self.rtc.ApplyItalicToSelection()

    def on_align_left(self, event):
        self.rtc.ApplyAlignmentToSelection(wx.TEXT_ALIGNMENT_LEFT)

    def on_align_center(self, event):
        self.rtc.ApplyAlignmentToSelection(wx.TEXT_ALIGNMENT_CENTER)

    def on_align_right(self, event):
        self.rtc.ApplyAlignmentToSelection(wx.TEXT_ALIGNMENT_RIGHT)

    def on_select_logo(self, event):
        wildcard_str = "Immagini JPG/PNG (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg"
        with wx.FileDialog(self, "Seleziona logo", wildcard=wildcard_str,
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL: return
            self.tc_logo.SetValue(fileDialog.GetPath())

    def GetSettings(self):
        handler = rt.RichTextXMLHandler()
        self.rtc.GetBuffer().AddHandler(handler)
        stream = io.BytesIO()
        handler.SaveFile(self.rtc.GetBuffer(), stream)
        xml_str = stream.getvalue().decode('utf-8')
        
        return {
            'rich_text_xml': xml_str,
            'logo_path': self.tc_logo.GetValue()
        }


class Step0Panel(wx.Panel):
    """Passo 0: Benvenuto."""
    def __init__(self, parent):
        super().__init__(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)
        
        btn_license = wx.Button(self, label="Licenza")
        btn_license.Bind(wx.EVT_BUTTON, self.on_show_license)
        sizer.Add(btn_license, 0, wx.ALL | wx.ALIGN_LEFT, 10)
        
        sizer.AddStretchSpacer()
        
        title = wx.StaticText(self, label="Benvenuto in TrueHash Forensics")
        font = title.GetFont()
        font.SetPointSize(24)
        font.SetWeight(wx.FONTWEIGHT_BOLD)
        title.SetFont(font)
        sizer.Add(title, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL, 10)
        
        desc = wx.StaticText(self, label="Acquisizione sicura, Hash SHA-256 e Notarizzazione Blockchain.")
        font_desc = desc.GetFont()
        font_desc.SetPointSize(14)
        desc.SetFont(font_desc)
        sizer.Add(desc, 0, wx.BOTTOM | wx.ALIGN_CENTER_HORIZONTAL, 30)
        
        instructions = wx.StaticText(self, label="Clicca su 'Inizia' per procedere con il fascicolo investigativo.")
        sizer.Add(instructions, 0, wx.BOTTOM | wx.ALIGN_CENTER_HORIZONTAL, 20)
        
        sizer.AddStretchSpacer()
        
        version_lbl = wx.StaticText(self, label="v0.1\nDeveloped by Michele Paladini", style=wx.ALIGN_CENTER_HORIZONTAL)
        version_lbl.SetForegroundColour(wx.Colour(130, 130, 130))
        font_ver = version_lbl.GetFont()
        font_ver.SetPointSize(11)
        version_lbl.SetFont(font_ver)
        sizer.Add(version_lbl, 0, wx.BOTTOM | wx.ALIGN_CENTER_HORIZONTAL, 15)
        
        self.SetSizer(sizer)

    def on_show_license(self, event):
        import os
        import sys
        if getattr(sys, 'frozen', False):
            base_dir = os.path.join(os.path.dirname(sys.executable), '..', 'Resources')
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            
        lic_path = os.path.join(base_dir, 'LICENSE')
        if os.path.exists(lic_path):
            try:
                with open(lic_path, 'r', encoding='utf-8') as f:
                    lic_text = f.read()
            except Exception:
                lic_text = "Impossibile leggere il file LICENSE."
        else:
            lic_text = "File LICENSE non trovato. Il software è distribuito sotto licenza GNU GPL v3.\nConsulta il sito ufficiale per il testo completo: https://www.gnu.org/licenses/gpl-3.0.txt"
        
        dlg = wx.Dialog(self, title="Licenza GNU GPL v3", size=(700, 500), style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER)
        d_sizer = wx.BoxSizer(wx.VERTICAL)
        
        tc = wx.TextCtrl(dlg, value=lic_text, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2)
        font = wx.Font(10, wx.FONTFAMILY_TELETYPE, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL)
        tc.SetFont(font)
        d_sizer.Add(tc, 1, wx.EXPAND | wx.ALL, 10)
        
        btn_ok = wx.Button(dlg, wx.ID_OK, "Chiudi")
        d_sizer.Add(btn_ok, 0, wx.ALIGN_RIGHT | wx.ALL, 10)
        
        dlg.SetSizer(d_sizer)
        dlg.ShowModal()
        dlg.Destroy()


class Step1Panel(wx.Panel):
    """Passo 1: Caso e Investigatore."""
    def __init__(self, parent):
        super().__init__(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)

        title = wx.StaticText(self, label="Passo 1 - Informazioni Generali")
        font = title.GetFont()
        font.SetPointSize(18)
        font.SetWeight(wx.FONTWEIGHT_BOLD)
        title.SetFont(font)
        sizer.Add(title, 0, wx.ALL, 20)

        grid = wx.FlexGridSizer(rows=2, cols=2, vgap=15, hgap=15)
        grid.AddGrowableCol(1, 1)

        lbl_caso = wx.StaticText(self, label="Riferimento Caso:")
        self.tc_caso = wx.TextCtrl(self, value="")
        grid.Add(lbl_caso, 0, wx.ALIGN_CENTER_VERTICAL)
        grid.Add(self.tc_caso, 1, wx.EXPAND)

        lbl_inv = wx.StaticText(self, label="Investigatore:")
        self.tc_inv = wx.TextCtrl(self, value="")
        grid.Add(lbl_inv, 0, wx.ALIGN_CENTER_VERTICAL)
        grid.Add(self.tc_inv, 1, wx.EXPAND)

        sizer.Add(grid, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 20)
        self.SetSizer(sizer)


class Step2Panel(wx.Panel):
    """Passo 2: Selezione Target (File/Cartella)."""
    def __init__(self, parent):
        super().__init__(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)

        self.lbl_caso_focus = wx.StaticText(self, label="CASO SELEZIONATO: ")
        font = self.lbl_caso_focus.GetFont()
        font.SetPointSize(18)
        font.SetWeight(wx.FONTWEIGHT_BOLD)
        self.lbl_caso_focus.SetFont(font)
        sizer.Add(self.lbl_caso_focus, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL, 20)
        
        line = wx.StaticLine(self)
        sizer.Add(line, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 20)

        title = wx.StaticText(self, label="Passo 2 - Sorgente Dati (Target)")
        font2 = title.GetFont()
        font2.SetPointSize(16)
        font2.SetWeight(wx.FONTWEIGHT_BOLD)
        title.SetFont(font2)
        sizer.Add(title, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 20)

        target_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.tc_target = wx.TextCtrl(self, style=wx.TE_READONLY)
        target_sizer.Add(self.tc_target, 1, wx.EXPAND | wx.RIGHT, 10)
        
        btn_file = wx.Button(self, label="Seleziona File")
        btn_folder = wx.Button(self, label="Seleziona Cartella")
        
        btn_file.Bind(wx.EVT_BUTTON, self.on_select_file)
        btn_folder.Bind(wx.EVT_BUTTON, self.on_select_folder)
        
        target_sizer.Add(btn_file, 0, wx.RIGHT, 5)
        target_sizer.Add(btn_folder, 0)

        sizer.Add(target_sizer, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 20)
        self.SetSizer(sizer)

    def on_select_file(self, event):
        with wx.FileDialog(self, "Seleziona file da analizzare", wildcard="*.*",
                           style=wx.FD_OPEN | wx.FD_FILE_MUST_EXIST) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL: return
            path = fileDialog.GetPath()
            self.tc_target.SetValue(path)
            self.estrai_zip = False
            if path.lower().endswith('.zip'):
                risposta = wx.MessageBox(
                    "Hai selezionato un file ZIP. Vuoi scompattarlo prima dell'analisi per calcolare l'hash anche dei file in esso contenuti?", 
                    "Estrazione ZIP", wx.YES_NO | wx.ICON_QUESTION
                )
                if risposta == wx.YES:
                    self.estrai_zip = True

    def on_select_folder(self, event):
        with wx.DirDialog(self, "Seleziona cartella da analizzare",
                          style=wx.DD_DEFAULT_STYLE | wx.DD_DIR_MUST_EXIST) as dirDialog:
            if dirDialog.ShowModal() == wx.ID_CANCEL: return
            self.tc_target.SetValue(dirDialog.GetPath())
            self.estrai_zip = False


class Step3Panel(wx.Panel):
    """Passo 3: Opzioni e Sicurezza."""
    def __init__(self, parent):
        super().__init__(parent)
        sizer = wx.BoxSizer(wx.VERTICAL)

        title = wx.StaticText(self, label="Passo 3 - Opzioni, Sicurezza e Generazione")
        font = title.GetFont()
        font.SetPointSize(16)
        font.SetWeight(wx.FONTWEIGHT_BOLD)
        title.SetFont(font)
        sizer.Add(title, 0, wx.ALL, 20)
        
        lbl_note = wx.StaticText(self, label="Note Integrative (Opzionali):")
        self.tc_note = wx.TextCtrl(self, style=wx.TE_MULTILINE, size=(-1, 80))
        sizer.Add(lbl_note, 0, wx.LEFT | wx.RIGHT | wx.BOTTOM, 5)
        sizer.Add(self.tc_note, 0, wx.EXPAND | wx.LEFT | wx.RIGHT | wx.BOTTOM, 20)

        self.cb_tsa = wx.CheckBox(self, label="Sigilla PDF con Marca Temporale TSA (Richiede Internet)")
        self.cb_ots = wx.CheckBox(self, label="Notarizza su Blockchain Bitcoin (OpenTimestamps)")
        self.cb_verbale = wx.CheckBox(self, label="Genera anche Verbale di Consegna (PDF aggiuntivo) [FUNZIONALITA' IN ARRIVO]")
        
        self.cb_tsa.SetValue(True)
        self.cb_ots.SetValue(True)
        self.cb_verbale.SetValue(False)
        self.cb_verbale.Disable()
        
        sizer.Add(self.cb_tsa, 0, wx.LEFT | wx.BOTTOM, 10)
        sizer.Add(self.cb_ots, 0, wx.LEFT | wx.BOTTOM, 10)
        sizer.Add(self.cb_verbale, 0, wx.LEFT | wx.BOTTOM, 10)
        
        self.SetSizer(sizer)


class TrueHashWizard(wx.Frame):
    def __init__(self):
        super().__init__(parent=None, title='TrueHash Forensics - Acquisizione', size=(750, 600))
        self.SetMinSize((650, 500))
        
        # Configurazione intestazione ditta e file JSON (path sicuro per macOS App)
        sp = wx.StandardPaths.Get()
        config_dir = sp.GetUserDataDir()
        if not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
            
        self.settings_file = os.path.join(config_dir, 'firm_settings.json')
        
        self.firm_settings = {
            'rich_text_xml': '',
            'logo_path': ''
        }
        
        # Carica preset di firma se presente
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    self.firm_settings.update(loaded)
            except Exception as e:
                print(f"Errore caricamento impostazioni: {e}")

        self.main_panel = wx.Panel(self)
        self.main_sizer = wx.BoxSizer(wx.VERTICAL)

        self.container = wx.Panel(self.main_panel)
        self.container_sizer = wx.BoxSizer(wx.VERTICAL)
        self.container.SetSizer(self.container_sizer)
        
        self.step0 = Step0Panel(self.container)
        self.step1 = Step1Panel(self.container)
        self.step2 = Step2Panel(self.container)
        self.step3 = Step3Panel(self.container)
        
        self.panels = [self.step0, self.step1, self.step2, self.step3]
        self.current_step = 0
        
        for p in self.panels:
            self.container_sizer.Add(p, 1, wx.EXPAND)
            p.Hide()
            
        self.panels[self.current_step].Show()
        
        self.main_sizer.Add(self.container, 1, wx.EXPAND | wx.ALL, 10)
        
        line = wx.StaticLine(self.main_panel)
        self.main_sizer.Add(line, 0, wx.EXPAND | wx.LEFT | wx.RIGHT, 10)
        
        nav_sizer = wx.BoxSizer(wx.HORIZONTAL)
        
        self.btn_settings = wx.Button(self.main_panel, label="⚙️ Impostazioni")
        self.btn_settings.Bind(wx.EVT_BUTTON, self.on_open_settings)
        
        self.status_lbl = wx.StaticText(self.main_panel, label="")
        self.status_lbl.SetForegroundColour(wx.Colour(120, 120, 120))
        
        self.btn_back = wx.Button(self.main_panel, label="< Indietro")
        self.btn_next = wx.Button(self.main_panel, label="Inizia >")
        
        self.btn_back.Bind(wx.EVT_BUTTON, self.on_back)
        self.btn_next.Bind(wx.EVT_BUTTON, self.on_next)
        
        nav_sizer.Add(self.btn_settings, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 15)
        nav_sizer.Add(self.status_lbl, 0, wx.ALIGN_CENTER_VERTICAL | wx.LEFT, 15)
        nav_sizer.AddStretchSpacer()
        nav_sizer.Add(self.btn_back, 0, wx.RIGHT, 10)
        nav_sizer.Add(self.btn_next, 0, wx.RIGHT, 15)
        
        self.main_sizer.Add(nav_sizer, 0, wx.EXPAND | wx.TOP | wx.BOTTOM, 15)
        self.main_panel.SetSizer(self.main_sizer)
        
        self.update_ui()
        self.Centre()

    def on_open_settings(self, event):
        dlg = SettingsDialog(self, self.firm_settings)
        if dlg.ShowModal() == wx.ID_OK:
            self.firm_settings = dlg.GetSettings()
            
            # Salva preset di firma nel file JSON
            try:
                with open(self.settings_file, 'w', encoding='utf-8') as f:
                    json.dump(self.firm_settings, f, ensure_ascii=False, indent=4)
            except Exception as e:
                wx.MessageBox(f"Impossibile salvare le impostazioni: {e}", "Errore Salvataggio", wx.OK | wx.ICON_ERROR)
                
        dlg.Destroy()

    def update_ui(self):
        for p in self.panels:
            p.Hide()
        self.panels[self.current_step].Show()
        
        self.btn_back.Enable(self.current_step > 0)
        
        if self.current_step == 0:
            self.btn_next.SetLabel("Inizia >")
            self.status_lbl.SetLabel("Benvenuto")
        elif self.current_step == len(self.panels) - 1:
            self.btn_next.SetLabel("Genera Report...")
            self.status_lbl.SetLabel("Pronto per la generazione")
        else:
            self.btn_next.SetLabel("Avanti >")
            self.status_lbl.SetLabel(f"Step {self.current_step} di 3")
            
        self.container.Layout()
        self.main_panel.Layout()

    def on_back(self, event):
        if self.current_step > 0:
            self.current_step -= 1
            self.update_ui()

    def on_next(self, event):
        if self.current_step == 0:
            self.current_step += 1
            self.update_ui()
            
        elif self.current_step == 1:
            caso = self.step1.tc_caso.GetValue().strip()
            inv = self.step1.tc_inv.GetValue().strip()
            if not caso or not inv:
                wx.MessageBox("Inserisci il nome del caso e dell'investigatore per procedere.", "Attenzione", wx.OK | wx.ICON_WARNING)
                return
            self.step2.lbl_caso_focus.SetLabel(f"CASO SELEZIONATO: {caso}")
            self.current_step += 1
            self.update_ui()
            
        elif self.current_step == 2:
            target = self.step2.tc_target.GetValue().strip()
            if not target:
                wx.MessageBox("Seleziona un file o una cartella da analizzare.", "Attenzione", wx.OK | wx.ICON_WARNING)
                return
            self.current_step += 1
            self.update_ui()

        elif self.current_step == 3:
            self.on_genera()

    def on_genera(self):
        target = self.step2.tc_target.GetValue().strip()
        caso = self.step1.tc_caso.GetValue().strip()
        investigatore = self.step1.tc_inv.GetValue().strip()

        with wx.FileDialog(self, "Salva Report PDF Come...", defaultFile="report_forense.pdf", 
                           wildcard="PDF files (*.pdf)|*.pdf|Tutti i file (*.*)|*.*",
                           style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL: return
            percorso_salvataggio = fileDialog.GetPath()

        if not percorso_salvataggio.lower().endswith('.pdf'):
            percorso_salvataggio += '.pdf'

        self.btn_next.Disable()
        self.btn_back.Disable()
        self.btn_settings.Disable()
        
        self.progress_dlg = wx.ProgressDialog(
            "Generazione Report in corso",
            "Inizializzazione del processo...",
            maximum=100,
            parent=self,
            style=wx.PD_APP_MODAL | wx.PD_AUTO_HIDE | wx.PD_SMOOTH
        )

        data = {
            'target': target,
            'caso': caso,
            'investigatore': investigatore,
            'firm_settings': self.firm_settings,
            'note': self.step3.tc_note.GetValue().strip(),
            'usa_tsa': self.step3.cb_tsa.GetValue(),
            'usa_ots': self.step3.cb_ots.GetValue(),
            'usa_verbale': self.step3.cb_verbale.GetValue(),
            'percorso_salvataggio': percorso_salvataggio,
            'estrai_zip': getattr(self.step2, 'estrai_zip', False)
        }

        threading.Thread(target=self._worker_thread, args=(data,), daemon=True).start()

    def _worker_thread(self, data):
        try:
            time_start = datetime.now()
            totale_byte = 0
            files_to_hash = []

            target = data['target']
            estrai_zip = data.get('estrai_zip', False)
            ha_estratto_zip = False
            
            if os.path.isfile(target): 
                files_to_hash.append(target)
                if estrai_zip and target.lower().endswith('.zip'):
                    import zipfile
                    extract_dir = os.path.splitext(target)[0]
                    if os.path.exists(extract_dir):
                        extract_dir += "_estratto"
                    os.makedirs(extract_dir, exist_ok=True)
                    
                    wx.CallAfter(self.progress_dlg.Update, 5, "Estrazione archivio ZIP in corso...")
                    try:
                        with zipfile.ZipFile(target, 'r') as zip_ref:
                            zip_ref.extractall(extract_dir)
                        for root, _, files in os.walk(extract_dir):
                            for f in files: files_to_hash.append(os.path.join(root, f))
                        ha_estratto_zip = True
                    except Exception as e:
                        print(f"Errore estrazione ZIP: {e}")
            else:
                for root, _, files in os.walk(target):
                    for f in files: files_to_hash.append(os.path.join(root, f))

            totale_file = len(files_to_hash)

            wx.CallAfter(self.progress_dlg.Update, 10, "Raccolta e hashing dei file in corso...")

            pdf = ForensicReport(data['firm_settings'], data['caso'], data['investigatore'], 
                                 target, data['usa_tsa'], has_ots=data['usa_ots'],
                                 has_extracted_zip=ha_estratto_zip)
            pdf.crea_copertina()
            pdf.crea_indice(target, files_to_hash)

            pdf.add_page()
            pdf.set_font("helvetica", "B", 14)
            pdf.set_text_color(33, 58, 143)
            pdf.cell(0, 10, "Elenco Reperti e Impronte Hash (SHA-256)", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)

            for i, filepath in enumerate(files_to_hash):
                sha256 = calcola_hash_sha256(filepath)
                dimensione = os.path.getsize(filepath) if os.path.exists(filepath) else 0
                totale_byte += dimensione
                nome_file = os.path.basename(filepath)

                if pdf.get_y() > 230:
                    pdf.add_page()

                if filepath in pdf.file_links:
                    pdf.set_link(pdf.file_links[filepath], y=pdf.get_y(), page=pdf.page_no())

                pdf.set_font("helvetica", "B", 11)
                if ha_estratto_zip and filepath == target:
                    pdf.set_text_color(200, 0, 0)
                else:
                    pdf.set_text_color(33, 58, 143)
                    
                pdf.cell(0, 6, sanitize_text(f"Reperto #{i+1}: {nome_file}"), new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("helvetica", "", 9)
                pdf.set_text_color(100, 100, 100)
                
                try:
                    percorso_parziale = os.path.relpath(filepath, os.path.dirname(target))
                except ValueError:
                    percorso_parziale = filepath
                    
                pdf.multi_cell(0, 5, sanitize_text(f"Percorso: {percorso_parziale}"))
                pdf.ln(1)
                pdf.set_font("helvetica", "B", 9)
                pdf.set_text_color(80, 80, 80)
                pdf.cell(25, 5, "Dimensione: ")
                pdf.set_font("helvetica", "", 9)
                pdf.cell(0, 5, format_bytes(dimensione), new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("helvetica", "B", 9)
                pdf.set_text_color(80, 80, 80)
                pdf.cell(25, 5, "SHA-256: ")
                pdf.set_font("courier", "B", 10)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 5, f"{sha256}", new_x="LMARGIN", new_y="NEXT")

                pdf.ln(3)
                pdf.set_draw_color(220, 220, 220)
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(4)

                percent = 10 + int(40 * (i+1)/totale_file)
                wx.CallAfter(self.progress_dlg.Update, percent, f"Hashing file: {nome_file[:30]}...")

            durata = (datetime.now() - time_start).total_seconds()
            pdf.crea_conclusioni(totale_file, totale_byte, durata, data['note'])

            percorso_salvataggio = data['percorso_salvataggio']
            timestamp_success = False
            ots_success = False
            ots_path = ""

            wx.CallAfter(self.progress_dlg.Update, 60, "Esportazione PDF basilare...")

            # --- MARCA TEMPORALE TSA ---
            if data['usa_tsa']:
                wx.CallAfter(self.progress_dlg.Update, 70, "Sigillatura con TSA in corso...")
                temp_pdf = percorso_salvataggio + ".tmp"
                pdf.output(temp_pdf)
                successo, msg = applica_marca_temporale_pdf(temp_pdf, percorso_salvataggio)
                if os.path.exists(temp_pdf): os.remove(temp_pdf)

                if successo:
                    timestamp_success = True
                else:
                    pdf.output(percorso_salvataggio)
                    wx.CallAfter(wx.MessageBox, f"Impossibile contattare server TSA.\nErrore: {msg}", "Errore TSA", wx.OK | wx.ICON_WARNING)
            else:
                pdf.output(percorso_salvataggio)

            # --- NOTARIZZAZIONE OPENTIMESTAMPS ---
            if data['usa_ots']:
                wx.CallAfter(self.progress_dlg.Update, 85, "Notarizzazione su Blockchain (OpenTimestamps)...")
                ots_ok, ots_msg, ots_path = notarizza_opentimestamps(percorso_salvataggio)
                if ots_ok:
                    ots_success = True
                else:
                    wx.CallAfter(wx.MessageBox, f"Errore OTS: {ots_msg}", "Errore OpenTimestamps", wx.OK | wx.ICON_WARNING)

            # --- VERBALE DI CONSEGNA ---
            msg_verbale = ""
            if data['usa_verbale']:
                wx.CallAfter(self.progress_dlg.Update, 95, "Generazione Verbale di Consegna...")
                
                hash_pdf_principale = calcola_hash_sha256(percorso_salvataggio)
                dir_salvataggio = os.path.dirname(percorso_salvataggio)
                nome_pdf_principale = os.path.basename(percorso_salvataggio)
                percorso_verbale = os.path.join(dir_salvataggio, f"Verbale_{nome_pdf_principale}")
                
                logo_verbale = data['firm_settings'].get('logo_path', '')
                rich_xml = data['firm_settings'].get('rich_text_xml', '')

                verbale_pdf = VerbaleConsegna()
                verbale_pdf.crea_verbale(data['caso'], data['investigatore'], logo_verbale, rich_xml,
                                         percorso_salvataggio, hash_pdf_principale,
                                         (data['usa_tsa'] and timestamp_success),
                                         ots_applicato=(data['usa_ots'] and ots_success))
                verbale_pdf.output(percorso_verbale)
                
                msg_verbale = f"• Verbale allegato: Si (salvato come Verbale_{nome_pdf_principale})"

            sep = "-" * 50
            msg_finale = f"RIEPILOGO ACQUISIZIONE\n{sep}\n\n"
            msg_finale += f"Il report e' stato generato e salvato con successo.\n\n"
            msg_finale += f"📍 Posizione: {percorso_salvataggio}\n\n"
            msg_finale += f"DETTAGLI SICUREZZA:\n"
            msg_finale += f"• Marca Temporale (TSA): {'✅ Applicata' if (data['usa_tsa'] and timestamp_success) else '❌ Nessuna implementata o Errore'}\n"
            msg_finale += f"• Notarizzazione Blockchain (OTS): {'✅ Riuscita su Bitcoin' if (data['usa_ots'] and ots_success) else '❌ Nessuna elaborazione'}\n"
            if data['usa_ots'] and ots_success:
                msg_finale += f"   ↳ File prova: {os.path.basename(ots_path)}\n"
            if data['usa_verbale']:
                msg_finale += f"{msg_verbale}\n"

            def _on_success():
                self.progress_dlg.Update(100, "Completato!")
                self.btn_next.Enable()
                self.btn_back.Enable()
                self.btn_settings.Enable()
                
                dlg = wx.MessageDialog(self, msg_finale, "Operazione Completata", wx.OK | wx.ICON_INFORMATION)
                dlg.ShowModal()
                dlg.Destroy()

            wx.CallAfter(_on_success)

        except Exception as e:
            def _on_error():
                self.progress_dlg.Update(100, "Errore.")
                self.btn_next.Enable()
                self.btn_back.Enable()
                self.btn_settings.Enable()
                wx.MessageBox(f"Si e' verificato un errore critico durante la generazione:\n\n{e}", "Errore Generazione", wx.OK | wx.ICON_ERROR)
            wx.CallAfter(_on_error)

if __name__ == '__main__':
    app = wx.App(False)
    frame = TrueHashWizard()
    frame.Show()
    app.MainLoop()