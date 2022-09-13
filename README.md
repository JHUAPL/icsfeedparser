# ICSFeedParser

## Description
This is a simple feed meant to monitor the CISA ICS alert feed RSS stream, investigate the alerts and their reference pages, and then query against a keyword list of vendors/products of interest to a particular community. The initial use case is to have this run automatically at an ISAC/ISAO in order to reduce the manual workload of monitoring the feed.

## Getting started

1. `python3 -m pip install -r requirements.txt`
2. Run `icsfeedparser.py` to generate `config.ini`, `vendors.txt`, `equipment.txt` and `notification_recipients.txt`.
3. Adjust `config.ini` based on the labels inside. See below for more details on each configuration value.
4. Add the vendors to monitor to `vendors.txt`, with one vendor on each line. Do the same with the equipment/model numbers to monitor for in `equipment.txt` and the email addresses of who to notify upon a discovered vulnerability to `notification_recipients.txt`.
5. Run `icsfeedparser.py` to receive notifications (such as a cronjob).

## Configuring ICSFeedParser

When initially running ICSFeedParser, it will create a `config.ini` with many settings that can be edited. These settings are as follows:

### Mail Settings

`use email notifications` - Whether to send out emails when a vulnerability is found. Set this to "True" if you would like to send emails, and "False" if you do not.

`mail server` - The mail server to use for sending notification emails.

`mail server port` - The port to communicate to the mail server with for sending notification emails.

`mail uses ssl encryption` - Set to "True" if the mail server uses SSL encryption. This is generally the case when the mail server port is 465.

`smtp username` - The username for logging into the mail server. Make this blank if there is no authentication needed.

`smtp password` - The password for logging into the mail server. Make this blank if there is no authentication needed.

`notification from email address` - The email address notifications should come from.

### Slack Settings

`use slack notifications` - Whether to send out a Slack message when a vulnerability is found. "True" if you would like to use Slack, "False" if you do not.

`slack webhook url` - The webhook URL for ICSFeedParser to talk to Slack with. See [this guide](https://slack.com/help/articles/115005265063-Incoming-webhooks-for-Slack) for how to get this URL.

### Notifier Settings

`days back to check` - The number of days backwards that should be checked when running this script to check for vulnerabilities. For example, if this is set to "3", this script will notify users for every vulnerability from the past 3 days that is applicable your vendors and/or equipment.

## License
Apache 2.0

