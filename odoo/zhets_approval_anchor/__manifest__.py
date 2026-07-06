{
    'name': 'Zhets+ Approval Anchor',
    'version': '16.0.1.0.0',
    'summary': 'Notifies the Zhets+ relayer when a purchase order is confirmed',
    'description': """
        Adds a method to purchase.order that POSTs approval data to the
        Zhets+ relayer when a PO is confirmed. Called from an Automation
        Rule rather than run directly in one, because Odoo's Automation
        Rule sandbox (safe_eval) blocks 'import requests' by design.
    """,
    'author': 'Chari',
    'category': 'Purchase',
    'depends': ['purchase'],
    'data': [],
    'installable': True,
    'application': False,
}
