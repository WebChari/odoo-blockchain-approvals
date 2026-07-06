import logging
from datetime import timezone

import requests

from odoo import models

_logger = logging.getLogger(__name__)

# If the relayer runs on your host machine and Odoo runs inside Docker,
# 'localhost' from inside the container does NOT reach the host — use
# host.docker.internal instead. Adjust this if your setup differs.
RELAYER_URL = "http://host.docker.internal:5000/approve"


class PurchaseOrder(models.Model):
    _inherit = 'purchase.order'

    def action_notify_relayer(self):
        """
        Called from the Automation Rule when a PO's state transitions to
        'purchase' (confirmed). This method is defined in an installed
        module, so it runs as ordinary, unrestricted Python — this is why
        the Automation Rule calls this method instead of writing the
        requests.post() call directly into the rule's own code box, which
        Odoo's safe_eval sandbox blocks.
        """
        for po in self:
            if not po.date_approve:
                _logger.warning(f"PO {po.name} has no date_approve yet — skipping")
                continue

            # po.date_approve is a naive Python datetime here (ORM access,
            # not XML-RPC), but Odoo stores it in UTC internally. Same
            # tzinfo tagging needed here as on the relayer's read-back side,
            # or the two sides will compute different epoch values for
            # what is actually the same moment in time.
            erp_timestamp = int(po.date_approve.replace(tzinfo=timezone.utc).timestamp())

            # IMPORTANT: use .name (display name), not .login (username/email).
            # The relayer's verification code reads this same field back via
            # XML-RPC as fields['user_id'][1], which is the display name —
            # not the login. If this sends .login while verification reads
            # the display name, the two strings will never match, and every
            # verification will fail with a false "tampered" result, even
            # though nothing was actually altered.
            approver = po.user_id.name if po.user_id else ''

            payload = {
                'po_id':         po.name,
                'amount':        po.amount_total,
                'approver':      approver,
                'erp_timestamp': erp_timestamp,
            }

            try:
                resp = requests.post(RELAYER_URL, json=payload, timeout=10)
                _logger.info(f"Relayer notified for {po.name}: {resp.status_code} {resp.text}")
            except Exception as e:
                _logger.error(f"Failed to notify relayer for {po.name}: {e}")
