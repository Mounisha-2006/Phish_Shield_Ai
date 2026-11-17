from imap_tools import MailBox
import re
import os
import tempfile
import uuid

# Same dangerous/macro extensions used by attachment_analyzer, kept here too
# so we don't save obviously useless files (e.g. tiny inline tracking images)
SKIP_CONTENT_TYPES = ['image/gif']  # tracking pixels etc - skip saving these


def fetch_emails(email_address, password, limit=10, save_attachments=True):
    emails = []
    attachment_dir = os.path.join(tempfile.gettempdir(), 'phishshield_attachments')
    os.makedirs(attachment_dir, exist_ok=True)

    try:
        with MailBox('imap.gmail.com').login(email_address, password) as mailbox:
            # Search ALL mail (not just unread) and take the N most recent
            # by date. The previous AND(seen=False) filter meant "only
            # unread", not "most recent" - combined with the default
            # mark_seen=True (which silently marks every fetched email as
            # read), each call would eat further into a shrinking pool of
            # unread mail and return whatever unread messages were left,
            # scattered anywhere in the inbox - not the actual 10 latest
            # emails. reverse=True + limit=limit is what actually gets you
            # "N most recent": imap_tools sorts newest-first before slicing.
            # mark_seen=False so scanning an inbox for phishing doesn't
            # change the user's real read/unread state behind their back.
            messages = mailbox.fetch(
                limit=limit,
                reverse=True,
                mark_seen=False
            )
            for msg in messages:
                raw_source = msg.html or msg.text or ''

                # Extract real URLs from the RAW source before any tag
                # stripping happens. This matters because HTML emails put
                # the actual phishing link in href="..." - the anchor text
                # itself is often just "Click here" or "Verify Now", which
                # tells you nothing. If we strip tags first (as the old
                # code did), the href URL is deleted along with the tag
                # and the phishing link is never seen by the analyzer.
                href_links  = re.findall(r'href=["\'](https?://[^"\']+)["\']', raw_source, re.IGNORECASE)
                # Only scan for "bare" plain-text URLs (used by plain-text
                # emails, or stray text that isn't inside an anchor tag).
                # Running this over the RAW source instead would also match
                # URLs that live inside HTML markup but are never actual
                # clickable links - e.g. the DOCTYPE declaration
                # ("http://www.w3.org/TR/xhtml1/DTD/...") or the xmlns
                # attribute on <html> ("http://www.w3.org/1999/xhtml").
                # Those are structural boilerplate present in nearly every
                # HTML email, not something the recipient could ever click,
                # and being plain http:// (not https://) they get scored as
                # a "phishing link" by evaluate_link_risk - turning an
                # ordinary email into a false HIGH-risk result. Stripping
                # tags first removes DOCTYPE/xmlns along with everything
                # else inside < >, so only genuinely bare, visible-text
                # URLs are picked up here.
                tag_stripped_source = re.sub(r'<[^>]+>', ' ', raw_source)
                plain_links = re.findall(r'(https?://[^\s"\'<>]+)', tag_stripped_source)
                # Preserve order, drop duplicates (href capture + plain-text
                # capture will often find the same URL twice).
                seen = set()
                extracted_links = []
                for link in href_links + plain_links:
                    link = link.rstrip('"\'<>)')  # trim stray trailing punctuation/quotes
                    if link not in seen:
                        seen.add(link)
                        extracted_links.append(link)

                body = msg.text or msg.html or ''
                # Remove HTML tags if body is HTML
                body = re.sub(r'<[^>]+>', ' ', body)
                body = re.sub(r'\s+', ' ', body).strip()

                # Truncate the READABLE text now, before appending links.
                # The old order appended links first and truncated
                # afterward, which could slice straight through the
                # middle of a long link (e.g. a SendGrid/Mailchimp
                # click-tracking URL) - leaving a fragment that was
                # never actually in the email but still got handed to
                # the analyzer as if it were a real link. A malformed
                # fragment like that always scores as risky, so a
                # perfectly legitimate email could come back flagged
                # over a link that doesn't even exist. Truncating first
                # means every link appended after this point stays whole.
                body = body[:2000]

                # Re-append any links that got stripped out with their tags
                # so downstream analysis (analyze_email's link regex) can
                # still find and score them, even though they're no longer
                # visible in the human-readable text.
                for link in extracted_links:
                    if link not in body:
                        body += ' ' + link

                saved_attachments = []
                if save_attachments:
                    for att in msg.attachments:
                        if att.content_type in SKIP_CONTENT_TYPES:
                            continue
                        # Save with a unique name on disk but remember the
                        # original filename for analysis (extension checks
                        # rely on the ORIGINAL name, not the random one).
                        safe_name = f"{uuid.uuid4().hex}_{att.filename or 'attachment'}"
                        save_path = os.path.join(attachment_dir, safe_name)
                        try:
                            with open(save_path, 'wb') as f:
                                f.write(att.payload)
                            saved_attachments.append({
                                'filepath': save_path,
                                'original_filename': att.filename or 'unnamed_attachment',
                                'content_type': att.content_type,
                                'size_bytes': len(att.payload)
                            })
                        except Exception:
                            # Don't let one bad attachment break the whole fetch
                            continue

                emails.append({
                    'subject' : msg.subject or 'No Subject',
                    'from'    : msg.from_ or 'Unknown',
                    'date'    : str(msg.date)[:19],
                    # NOTE: readable text is capped at 2000 chars above,
                    # BEFORE links are appended - so this can be longer
                    # than 2000 total when a link-heavy email has several
                    # long tracking URLs, but every link in it is always
                    # complete, never sliced in half by a length cap.
                    'body'    : body,
                    'uid'     : str(msg.uid),
                    'attachments': saved_attachments
                })
        return {'success': True, 'emails': emails}
    except Exception as e:
        return {'success': False, 'error': str(e)}