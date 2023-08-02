# Simple python script to parse the CISA ICS alert feed

# DISCLAIMER
# The script developed by JHU/APL for the demonstration are not “turn key” and are 
# not safe for deployment without being tailored to production infrastructure. These
# files are not being delivered as software and are not appropriate for direct use on any
# production networks. JHU/APL assumes no liability for the direct use of these files and
# they are provided strictly as a reference implementation.
#
# NO WARRANTY, NO LIABILITY. THIS MATERIAL IS PROVIDED “AS IS.” JHU/APL MAKES NO
# REPRESENTATION OR WARRANTY WITH RESPECT TO THE PERFORMANCE OF THE MATERIALS, INCLUDING
# THEIR SAFETY, EFFECTIVENESS, OR COMMERCIAL VIABILITY, AND DISCLAIMS ALL WARRANTIES IN
# THE MATERIAL, WHETHER EXPRESS OR IMPLIED, INCLUDING (BUT NOT LIMITED TO) ANY AND ALL
# IMPLIED WARRANTIES OF PERFORMANCE, MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
# AND NON-INFRINGEMENT OF INTELLECTUAL PROPERTY OR OTHER THIRD PARTY RIGHTS. ANY USER OF
# THE MATERIAL ASSUMES THE ENTIRE RISK AND LIABILITY FOR USING THE MATERIAL. IN NO EVENT
# SHALL JHU/APL BE LIABLE TO ANY USER OF THE MATERIAL FOR ANY ACTUAL, INDIRECT,
# CONSEQUENTIAL, SPECIAL OR OTHER DAMAGES ARISING FROM THE USE OF, OR INABILITY TO USE,
# THE MATERIAL, INCLUDING, BUT NOT LIMITED TO, ANY DAMAGES FOR LOST PROFITS.

import configparser
import os
import smtplib
import sys
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from textwrap import dedent
from typing import List, Union

import bleach
import feedparser
import requests
from bs4 import BeautifulSoup

CONFIG = None
DOUBLE_MATCH_WARNING = "ATTENTION: The following alert references your specified vendors AND products!"
EMPTY_NIST_VULN_URL = "http://web.nvd.nist.gov/view/vuln/detail?vulnId="


# Class to store feed data
class ICSFeedData:
    def __init__(self, entry, max_hours_back):
        # Init everything at the top, even if we don't have values for it yet, so it's easy to come back
        # and look at.
        self.entry = entry
        self.entry_id = ""
        self.date_published = None
        self.is_old = False
        self.has_data = False
        self.cvss_scores = ""
        self.attention = ""
        self.vendor = ""
        self.equipment = ""
        self.vulns = ""
        self.cves = []
        # Note: Although feedparser does its own sanitizing, best we play it safe and use a known good one like
        # bleach throughout here. However,  bleach only prevents unsafe tags. We need to manually remove the <p> here
        # to better display to the user.
        self.entry.summary = bleach.clean(self.entry.summary.replace("<p>", "").replace("</p>", ""))
        if len(self.entry.summary.split("\n")) > 3:
            self.entry.summary = ""  # Empty summary if it's too long (comes from a mistake in the feed)
        entry.link = bleach.clean(entry.link.lower())
        link = entry.link
        link_split = link.split('icsa-', 1)
        if len(link_split) == 2:
            self.entry_id = 'icsa-' + link_split[1]
        else:
            link_split = link.split('icsma-', 1)
            self.entry_id = 'icsma-' + link_split[1]
        self.entry_id = self.entry_id.upper()
        # Get the time published, and don't retrieve further if the date is too far in the past
        entry.published = bleach.clean(entry.published)
        self.date_published = datetime.strptime(entry.published[:-6], "%a, %d %b %y %H:%M:%S")
        now = datetime.now()
        diff = now - self.date_published
        hours_since = diff.total_seconds() / 60 / 60
        if hours_since > max_hours_back:
            self.is_old = True
        else:
            # Retrieve main page and fetch information
            entry_page = requests.get(link, timeout=CONFIG["timeout_time"])
            entry_soup = BeautifulSoup(entry_page.content, 'html.parser')
            tags = entry_soup.find_all()
            for tag in tags:
                # Search on the actual page for data, since <meta> tags are inconsistent
                # (see https://www.cisa.gov/uscert/ics/advisories/icsa-22-181-03 as an example of a bad meta tag)
                if "1. EXECUTIVE SUMMARY" == tag.text:
                    info_tag = tag.next_sibling.next_element
                    for list_item in info_tag:
                        if hasattr(list_item, "text") and list_item.text != "":
                            text = bleach.clean(list_item.text)
                            if "CVSS" in text:
                                self.cvss_score = text.rsplit(" ", maxsplit=1)[-1]
                            elif "ATTENTION:" in text:
                                self.attention = text[len("ATTENTION: "):]
                            elif "Vendor:" in text:
                                self.vendor = text[len("Vendor: "):]
                            elif "Equipment:" in text:
                                self.equipment = text[len("Equipment: "):]
                            elif "Vulnerabilities:" in text:
                                self.vulns = text[len("Vulnerabilities: "):]
                            elif "Vulnerability:" in text:
                                self.vulns = text[len("Vulnerability: "):]
                elif "3.2 VULNERABILITY OVERVIEW" == tag.text:
                    tag = tag.next_sibling
                    while tag.text != "3.3 BACKGROUND" and tag.name in ["p", None]:
                        tag_text = tag.text.replace("\u200b",
                                                    "")  # Some entries have zero-width spaces. Get rid of them.
                        if tag_text.startswith("CVE-"):
                            # Need to do the extra replace for no-break spaces that can be found sometimes
                            self.cves.append(tag_text.split(" ")[0].replace("has", "").strip())
                        tag = tag.next_sibling

            self.has_data = self.cvss_score and self.attention and self.vendor and self.equipment and self.vulns

    @property
    def severity(self):
        scores = self.cvss_score.split(".")
        major_score = int(scores[0])
        if major_score < 4:
            return "Low"
        elif major_score < 7:
            return "Medium"
        elif major_score < 9:
            return "High"
        else:
            return "Critical"

    def data_applicable(self, equipment_list: List[str], vendors_list: List[str]) -> int:
        """Check if Vulnerability Applicable.

        Checks if this vulnerability is in the list of equipment and/or vendors.

        Args:
            equipment_list: String list of equipment to check against
            vendors_list: List of vendors to check against

        Returns:
            0 if this data is not in either list, 1 if this data is in only the vendor list or equipment list, and
            2 if it's in both lists.
        """
        score = 0
        for e in equipment_list:
            if e.lower() in self.equipment.lower():
                score += 1
                break
        for v in vendors_list:
            if v.lower() in self.vendor.lower():
                score += 1
                break
        return score

    def __str__(self):
        out = f"{'-' * 8}{self.entry.title} ({self.entry_id}) {'-' * 8}\n"
        if self.has_data:
            out += dedent(f"""
            Published: {self.entry.published} at: {self.entry.link}
            CVSS Score: {self.cvss_score} ({self.severity} Severity)
            Attention: {self.attention}
            Vendor Affected: {self.vendor}
            Equipment Affected: {self.equipment}
            Vulnerabilities: {self.vulns}
            CVEs: {' '.join(self.cves) if len(self.cves) > 0 else 'None'}
            """)
            if self.entry.summary:
                out += f"\nSummary: {self.entry.summary}"
            out += f"\nLink to ICS Page: {self.entry.link}"
        elif self.is_old:
            out += "\nNo Data! Did not obtain data due to this entry having been created too long ago!"
        else:
            out += "\nNo Data! Failed to retrieve it!"
        return out


def make_slack_message(data: ICSFeedData, double_matches: bool) -> dict:
    """Make Slack Text from ICSFeedData.

    Translates an ICSFeedData instance into a string formatted as a Slack message.

    Args:
        data: An ICSFeedData representing an ICS report.
        double_matches: Whether to include an extra warning that this warning is very applicable.

    Returns:
        A dictionary representing JSON to be sent to Slack's API.
    """
    content = {}
    blocks = []

    cvss_str = ""
    is_critical = data.severity == "Critical"
    is_high_or_critical = data.severity == "High" or is_critical
    if is_critical:
        cvss_str += "!" * 16 + " "
    if is_high_or_critical:
        cvss_str += "*"
    cvss_str += f"CVSS Score: {data.cvss_score} ({data.severity} Severity)"
    if is_high_or_critical:
        cvss_str += "*"
    if is_critical:
        cvss_str += " " + "!" * 16

    double_match_str = "*" + DOUBLE_MATCH_WARNING + "*\n" if double_matches else ""

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": dedent(f"""
            *{data.entry.title} ({data.entry_id})*
            {double_match_str}{cvss_str}
            """)
        }
    })
    body = dedent(f"""
    Published: {data.entry.published}
    Attention: {data.attention}
    Vendor Affected: {data.vendor}
    Equipment Affected: {data.equipment}
    Vulnerabilities: {data.vulns}
    CVEs: {' '.join([f"<{EMPTY_NIST_VULN_URL + cve}|{cve}> " for cve in data.cves]) if len(data.cves) > 0 else "None"}
    """)
    if data.entry.summary:
        body += f"\nSummary: {data.entry.summary}"
    body += f"\n<{data.entry.link}|ICS Page>"

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": body
        }
    })
    content["blocks"] = blocks

    return content


def make_html(data: ICSFeedData, double_matches: bool) -> str:
    """Make HTML from ICSFeedData.

    Translates an ICSFeedData instance into an alright-looking HTML document.

    Args:
        data: An ICSFeedData representing an ICS report.
        double_matches: Whether to include an extra warning that this vulnerability is very applicable.

    Returns:
        A string of an HTML document to be sent via email.
    """
    cve_html = ""
    if len(data.cves) > 0:
        cve_html = "<h2 style=\"font-weight: normal\">CVEs: "
        for cve in data.cves:
            cve_html += f"<span><a href={EMPTY_NIST_VULN_URL + cve}>{cve}</a></span>&nbsp;"
        cve_html += "</h2>"
    html = f"""
    <html><head><div style="text-align: center">
    {f'<h1 style="color: red">{DOUBLE_MATCH_WARNING}</h1>' if double_matches else ''}
    <h1>{data.entry.title} ({data.entry_id})</h1>
    </div></head>
    <body>
    <div style="text-align: center">
        <h3 style="font-weight: normal">Published: {data.date_published}</h3>
        <h2 style="font-weight: normal; color: darkred">CVSS Score: {data.cvss_score}</h2>
        <h2 style="font-weight: normal">Attention: {data.attention}</h2>
        <h2 style="font-weight: normal">Affected Product: {data.equipment} from {data.vendor}</h2>
        <h2 style="font-weight: normal">Vulnerabilities: {data.vulns}</h2>
        {cve_html}
        <h3 style="font-weight: normal">{data.entry.summary}</h3>
        <a href="{data.entry.link}"><h2 style="font-weight: normal">View ICS Page</h2></a>
        </div>
    </body>
    </html>
    """
    return html


def send_mail(subject: str, plain_text: str, html: Union[str, None] = None, to_error: bool = False):
    try:
        msgs = []
        receivers = CONFIG["error_receivers"] if to_error else CONFIG["receivers"]
        for receiver in receivers:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = CONFIG["from_address"]
            msg["To"] = receiver

            if html is not None:
                msg.attach(MIMEText(html, "html"))
            msg.attach(MIMEText(plain_text, "plain"))
            msgs.append(msg)
        if CONFIG["mail_ssl"]:
            smtp = smtplib.SMTP_SSL(host=CONFIG["mail_server"], port=CONFIG["mail_server_port"])
        else:
            smtp = smtplib.SMTP(host=CONFIG["mail_server"], port=CONFIG["mail_server_port"])
            smtp.starttls()
        if CONFIG["username"] and CONFIG["password"]:
            smtp.login(CONFIG["username"], CONFIG["password"])
        for msg in msgs:
            smtp.send_message(msg, CONFIG["from_address"], msg["To"])
        smtp.quit()
    except smtplib.SMTPException as e:
        print("Error while sending emails!")
        print(e)


def notify_of_vuln(feed_data: ICSFeedData, double_matches: bool):
    """Notify of Vulnerability.

    Notifies the end user(s) of a vulnerability.

    Args:
        feed_data: The ICSFeedData instance to report.
        double_matches: Whether both the equipment and vendor matched up during checking
    """
    if not double_matches and CONFIG["only_double_match"]:
        return  # Bail early if we're only looking for double matches and we don't double match
    print(f"Notifying of vulnerability for {feed_data.entry.title}{' with full applicability' if double_matches else ''}.")
    plain_text = ""
    if double_matches:
        plain_text += DOUBLE_MATCH_WARNING + "\n"
    plain_text += str(feed_data) + "\n"
    if CONFIG["use_emails"]:
        html = make_html(feed_data, double_matches)
        send_mail("Vulnerability Notification", plain_text, html)
    if CONFIG["use_slack"]:
        requests.post(CONFIG["slack_url"],
                      json=make_slack_message(feed_data, double_matches), verify=CONFIG["requests_verify"], timeout=CONFIG["timeout_time"])


def get_entries_for_past_hours(hours_back: int) -> List[ICSFeedData]:
    """Get Entries for Past Hours.

    Gets all the entries in the ICS feed from the past hours_back hours.

    Args:
        hours_back: The amount of hours to look back.

    Returns:
        A list of ICSFeedData instances containing all the vulnerability reports from the past hours_back hours.
    """
    entries = []
    icsa = feedparser.parse('https://www.cisa.gov/uscert/ics/advisories/advisories.xml')
    icsa_entries = icsa.entries

    if icsa.bozo:
        handle_error("Failed to retrieve ICS advisories.", icsa.bozo_exception)

    if len(icsa_entries) == 0:
        handle_error("Retrieved no ICS advisories. This is likely some sort of error.", None)

    for entry_in in icsa_entries:
        try:
            data = ICSFeedData(entry_in, hours_back)
        except Exception as e:
            handle_error("Failed to parse ICS advisory entry!", e)
        if data.has_data or not data.is_old:
            entries.append(data)
        else:  # Break if we created an old instance
            break
    return entries


def get_valid_lines(file_name: str) -> List[str]:
    """Get All Good Lines.

    Gets all lines from file_name that aren't empty.

    Args:
        file_name: File name to retrieve lines from.

    Returns:
        A list of non-empty lines from file_name.
    """
    with open(file_name, "r") as f:
        lines_raw = f.read().strip().replace("\r", "").split("\n")
        good_lines = []
        for line in lines_raw:
            line = line.strip()
            if len(line) > 0:
                good_lines.append(line)
    return good_lines


def fetch_config() -> dict:
    """Fetch Config.

    Fetches the config from config.ini and returns a dictionary from it for ICSFeedParser to use.

    Returns:
        The aforementioned dictionary.
    """
    config_dict = {}
    config = configparser.ConfigParser()
    config.read("config.ini")

    config_dict["use_emails"] = config["Mail Settings"].getboolean("use email notifications", fallback=True)
    config_dict["use_email_errors"] = config["Mail Settings"].getboolean("use email error notifications", fallback=True)
    config_dict["use_slack"] = config["Slack Settings"].getboolean("use slack notifications", fallback=True)
    config_dict["use_slack_errors"] = config["Slack Settings"].getboolean("use slack error notifications",
                                                                          fallback=True)

    config_dict["mail_server"] = config["Mail Settings"]["mail server"]
    config_dict["mail_server_port"] = config["Mail Settings"].getint("mail server port", fallback=25)
    config_dict["mail_ssl"] = config["Mail Settings"].getboolean("mail uses ssl encryption",
                                                                 fallback=config_dict["mail_server_port"] == 465)
    config_dict["from_address"] = config["Mail Settings"]["notification from email address"]
    config_dict["username"] = config["Mail Settings"]["smtp username"]
    config_dict["password"] = config["Mail Settings"]["smtp password"]

    config_dict["hours_back_to_check"] = \
        config["Notifier Settings"].getint("days back to check", fallback=1) * 24 + 0.1
    config_dict["only_double_match"] = config["Notifier Settings"] \
        .getboolean("only notify when vendor and equipment match", fallback=True)
    config_dict["receivers"] = get_valid_lines("notification_recipients.txt")
    config_dict["error_receivers"] = get_valid_lines("error_recipients.txt")
    config_dict["vendors"] = get_valid_lines("vendors.txt")
    config_dict["equipment"] = get_valid_lines("equipment.txt")

    config_dict["slack_url"] = config["Slack Settings"]["slack webhook url"]
    config_dict["slack_error_url"] = config["Slack Settings"]["slack error webhook url"]

    config_dict["requests_verify"] = config["Notifier Settings"].getboolean("use ssl verification", fallback=True)

    if config_dict["use_emails"]:
        for receiver in config_dict["receivers"]:
            if "@example.com" in receiver:
                print("You cannot send emails to users at example.com!")
                sys.exit(1)

    if config_dict["use_email_errors"]:
        for receiver in config_dict["error_receivers"]:
            if "@example.com" in receiver:
                print("You cannot send emails to users at example.com!")
                sys.exit(1)

    if config_dict["use_slack"] and config_dict["slack_url"] == "https://hooks.slack.com/services/YOUR/HOOK/HERE":
        print("Please set the Slack URL to something other than the example URL!")
        sys.exit(1)

    if config_dict["use_slack_errors"] and \
            config_dict["slack_error_url"]== "https://hooks.slack.com/services/YOUR/HOOK/HERE":
        print("Please set the Slack URL to something other than the example URL!")
        sys.exit(1)

    # Hardcoded config values
    config_dict["timeout_time"] = 60

    return config_dict


def check_write_config() -> bool:
    """Write Config.

    Writes the default config file if it doesn't already exist.

    Returns:
        True if the config was written, False if it was already there.
    """
    to_ret = False
    if not os.path.exists("config.ini"):
        config = configparser.ConfigParser()
        config["Mail Settings"] = {
            "Use Email Notifications": "True",
            "Use Email Error Notifications": "True",
            "Mail Server": "mail.example.com",
            "Mail Server Port": "25",
            "Mail Uses SSL Encryption": "False",
            "SMTP Username": "ENTER USERNAME HERE, OR LEAVE BLANK IF AUTHENTICATION IS NOT NEEDED",
            "SMTP Password": "ENTER PASSWORD HERE, OR LEAVE BLANK IF AUTHENTICATION IS NOT NEEDED",
            "Notification From Email Address": "ICSFeedAlerts@alerts.example.com"
        }

        config["Slack Settings"] = {
            "Use Slack Notifications": "True",
            "Slack Webhook URL": "https://hooks.slack.com/services/YOUR/HOOK/HERE",
            "Use Slack Error Notifications": "True",
            "Slack Error Webhook URL": "https://hooks.slack.com/services/YOUR/HOOK/HERE"
        }

        config["Notifier Settings"] = {
            "Days Back to Check": "1",
            "Only Notify When Vendor And Equipment Match": "False",
            "Use SSL Verification": "True"
        }

        with open("config.ini", "w") as f:
            config.write(f)
        print("Wrote config file for editing.")
        to_ret = True
    if not os.path.exists("vendors.txt"):
        with open("vendors.txt", "w") as f:
            f.write(dedent("""
            Example Vendor. Change Me!
            Another Vendor! Change Me as well!
            """))
        print("Wrote vendors.txt file for editing.")
        to_ret = True
    if not os.path.exists("equipment.txt"):
        with open("equipment.txt", "w") as f:
            f.write(dedent("""
            MODEL1-CHANGEME
            CHANGEMETOO
            """))
        print("Wrote equipment.txt file for editing.")
        to_ret = True
    if not os.path.exists("notification_recipients.txt"):
        with open("notification_recipients.txt", "w") as f:
            f.write(dedent("""
            alice@example.com
            bob@example.com
            """))
        print("Wrote notification_recipients.txt file for editing.")
        to_ret = True
    if not os.path.exists("error_recipients.txt"):
        with open("error_recipients.txt", "w") as f:
            f.write("admin@example.com")
        print("Wrote error_recipients.txt file for editing.")
        to_ret = True
    return to_ret


def handle_error(error_message: str, error: Union[None, Exception]):
    print("ERROR: " + error_message)
    # When handling errors, try-except email sending and Slack messages in case one fails so the other gets through

    if CONFIG["use_slack_errors"]:
        try:
            exception_msg = "*Error from ICSFeedParser script:* " + str(error) if error is not None else ""
            r = requests.post(CONFIG["slack_error_url"], json={
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": dedent(f"""
                            *An error has occurred!*
                            *Error:* {error_message}
                            {exception_msg}
                            """)
                        }
                    }
                ]
            }, verify=CONFIG["requests_verify"], timeout=CONFIG["timeout_time"])
            if not r.ok:
                print(f"Failed to send error to Slack with reason: {r.reason}.")
        except Exception as e:
            print("Failed to send error to Slack.")
            print(str(e))

    if CONFIG["use_email_errors"]:
        try:
            error_email_msg = f"<h2 style=\"font-weight: normal\">Error from ICSFeedParser script: {str(error)}</h2>"\
                if error is not None else ""
            html = f"""
                <head>
                    <div style="text-align: center">
                        <h1 style="color: red">ICSFeedParser Error</h1>
                    </div>
                </head>
                <body>
                    <div style="text-align: center">
                        <h2 style="font-weight: normal; color: darkred">An error has occurred in ICSFeedParser.</h2>
                        <h2 style="font-weight: normal">Error Message: {error_message}</h2>
                        {error_email_msg}
                    </div>
                </body>
                </html>
            """
            plaintext = dedent(f"""
            An error has occured in ICSFeedParser.
            Error Message: {error_message}
            {str(error) if error is not None else ''}
            """)
            send_mail("ICSFeedParser Error", plaintext, html, True)
        except Exception as e:
            print("Failed to send error via email.")
            print(str(e))

    if error is not None:
        raise error
    raise RuntimeError(error_message)


def main():
    """Main Function."""
    print("Fetching entries...")
    entries = get_entries_for_past_hours(CONFIG["hours_back_to_check"])
    print(f"Checking {str(len(entries))} entries and notifying...")
    for e in entries:
        applicable = e.data_applicable(CONFIG["equipment"], CONFIG["vendors"])
        if applicable:
            notify_of_vuln(e, applicable == 2)
    print("Process completed successfully!")


if __name__ == "__main__":
    print("Loading Config...")
    if check_write_config():
        print("Wrote configuration files! Please edit them as needed!")
        sys.exit(0)
    else:
        CONFIG = fetch_config()
    main()
