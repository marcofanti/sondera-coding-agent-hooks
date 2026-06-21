use crate::escalation::EscalationRecord;
use anyhow::{Context as _, Result};

pub async fn post(webhook_url: &str, record: &EscalationRecord, admin_port: u16) -> Result<()> {
    let base = format!("http://localhost:{admin_port}");
    let approve_url = format!("{base}/api/escalations/{}/approve", record.id);
    let deny_url = format!("{base}/api/escalations/{}/deny", record.id);

    let payload = serde_json::json!({
        "blocks": [
            {
                "type": "header",
                "text": { "type": "plain_text", "text": ":warning: Agent Action Requires Approval" }
            },
            {
                "type": "section",
                "fields": [
                    { "type": "mrkdwn", "text": format!("*Agent:*\n`{}`", record.agent_id) },
                    { "type": "mrkdwn", "text": format!("*Policies:*\n`{}`", record.policy_ids) }
                ]
            },
            {
                "type": "section",
                "text": { "type": "mrkdwn", "text": format!("*Escalation ID:* `{}`", record.id) }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": { "type": "plain_text", "text": "Approve" },
                        "style": "primary",
                        "url": approve_url
                    },
                    {
                        "type": "button",
                        "text": { "type": "plain_text", "text": "Deny" },
                        "style": "danger",
                        "url": deny_url
                    }
                ]
            }
        ]
    });

    reqwest::Client::new()
        .post(webhook_url)
        .json(&payload)
        .send()
        .await
        .context("Failed to post to Slack webhook")?
        .error_for_status()
        .context("Slack webhook returned error")?;

    Ok(())
}
