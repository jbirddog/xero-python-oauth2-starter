# -*- coding: utf-8 -*-
import dateutil
import os
import requests
import time
from functools import wraps
from io import BytesIO
from logging.config import dictConfig

from flask import Flask, url_for, render_template, session, redirect, json, send_file, request
from flask_oauthlib.contrib.client import OAuth, OAuth2Application
from flask_session import Session
from xero_python.accounting import AccountingApi, ContactPerson, Contact, Contacts, LineItem, LineItemTracking, Invoice, Invoices
from xero_python.api_client import ApiClient, serialize
from xero_python.api_client.configuration import Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.exceptions import AccountingBadRequestException
from xero_python.identity import IdentityApi
from xero_python.utils import getvalue

import logging_settings
from utils import jsonify, serialize_model

dictConfig(logging_settings.default_settings)

# configure main flask application
app = Flask(__name__)
app.config.from_object("default_settings")
app.config.from_pyfile("config.py", silent=True)

if app.config["ENV"] != "production":
    # allow oauth2 loop to run over http (used for local testing only)
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# configure persistent session cache
Session(app)

CONNECTOR_PROXY_URL = app.config['CONNECTOR_PROXY_URL']

# configure flask-oauthlib application
# TODO fetch config from https://identity.xero.com/.well-known/openid-configuration #1
oauth = OAuth(app)
xero = oauth.remote_app(
    name="xero",
    version="2",
    client_id=app.config["XERO_CLIENT_ID"],
    client_secret=app.config["XERO_CLIENT_SECRET"],
    endpoint_url="https://api.xero.com/",
    authorization_url="https://login.xero.com/identity/connect/authorize",
    access_token_url="https://identity.xero.com/connect/token",
    refresh_token_url="https://identity.xero.com/connect/token",
    scope="offline_access openid profile email accounting.transactions "
    "accounting.reports.read accounting.journals.read accounting.settings "
    "accounting.contacts accounting.attachments assets projects",
)  # type: OAuth2Application


# configure xero-python sdk client
api_client = ApiClient(
    Configuration(
        debug=app.config["DEBUG"],
        oauth2_token=OAuth2Token(
            client_id=app.config["XERO_CLIENT_ID"], client_secret=app.config["XERO_CLIENT_SECRET"]
        ),
    ),
    pool_threads=1,
)


# configure token persistence and exchange point between flask-oauthlib and xero-python
@xero.tokengetter
@api_client.oauth2_token_getter
def obtain_xero_oauth2_token():
    return session.get("token")


@xero.tokensaver
@api_client.oauth2_token_saver
def store_xero_oauth2_token(token):
    session["token"] = token
    session.modified = True


def xero_token_required(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        xero_token = obtain_xero_oauth2_token()
        if not xero_token:
            return redirect(url_for("login", _external=True))

        return function(*args, **kwargs)

    return decorator


@app.route("/")
def index():
    xero_access = dict(obtain_xero_oauth2_token() or {})
    return render_template(
        "code.html",
        title="Home | oauth token",
        code=json.dumps(xero_access, sort_keys=True, indent=4),
    )


@app.route("/tenants")
@xero_token_required
def tenants():
    identity_api = IdentityApi(api_client)
    accounting_api = AccountingApi(api_client)

    available_tenants = []
    for connection in identity_api.get_connections():
        tenant = serialize(connection)
        if connection.tenant_type == "ORGANISATION":
            organisations = accounting_api.get_organisations(
                xero_tenant_id=connection.tenant_id
            )
            tenant["organisations"] = serialize(organisations)

        available_tenants.append(tenant)

    return render_template(
        "code.html",
        title="Xero Tenants",
        code=json.dumps(available_tenants, sort_keys=True, indent=4),
    )


@app.route("/create-contact-person")
@xero_token_required
def create_contact_person():
    xero_tenant_id = get_xero_tenant_id()
    accounting_api = AccountingApi(api_client)

    contact_person = ContactPerson(
        first_name="John",
        last_name="Smith",
        email_address="john.smith@24locks.com",
        include_in_emails=True,
    )
    contact = Contact(
        name="FooBar",
        first_name="Foo",
        last_name="Bar",
        email_address="ben.bowden@24locks.com",
        contact_persons=[contact_person],
    )
    contacts = Contacts(contacts=[contact])
    try:
        created_contacts = accounting_api.create_contacts(
            xero_tenant_id, contacts=contacts
        )  # type: Contacts
    except AccountingBadRequestException as exception:
        sub_title = "Error: " + exception.reason
        code = jsonify(exception.error_data)
    else:
        sub_title = "Contact {} created.".format(
            getvalue(created_contacts, "contacts.0.name", "")
        )
        code = serialize_model(created_contacts)

    return render_template(
        "code.html", title="Create Contacts", code=code, sub_title=sub_title
    )


@app.route("/create-multiple-contacts")
@xero_token_required
def create_multiple_contacts():
    xero_tenant_id = get_xero_tenant_id()
    accounting_api = AccountingApi(api_client)

    contact = Contact(
        name="George Jetson",
        first_name="George",
        last_name="Jetson",
        email_address="george.jetson@aol.com",
    )
    # Add the same contact twice - the first one will succeed, but the
    # second contact will fail with a validation error which we'll show.
    contacts = Contacts(contacts=[contact, contact])
    try:
        created_contacts = accounting_api.create_contacts(
            xero_tenant_id, contacts=contacts, summarize_errors=False
        )  # type: Contacts
    except AccountingBadRequestException as exception:
        sub_title = "Error: " + exception.reason
        result_list = None
        code = jsonify(exception.error_data)
    else:
        sub_title = ""
        result_list = []
        for contact in created_contacts.contacts:
            if contact.has_validation_errors:
                error = getvalue(contact.validation_errors, "0.message", "")
                result_list.append("Error: {}".format(error))
            else:
                result_list.append("Contact {} created.".format(contact.name))

        code = serialize_model(created_contacts)

    return render_template(
        "code.html",
        title="Create Multiple Contacts",
        code=code,
        result_list=result_list,
        sub_title=sub_title,
    )


@app.route("/invoices")
@xero_token_required
def get_invoices():
    xero_tenant_id = get_xero_tenant_id()
    accounting_api = AccountingApi(api_client)

    invoices = accounting_api.get_invoices(
        xero_tenant_id, statuses=["DRAFT", "SUBMITTED"]
    )
    code = serialize_model(invoices)
    sub_title = "Total invoices found: {}".format(len(invoices.invoices))

    return render_template(
        "/code.html", title="Invoices", code=code, sub_title=sub_title
    )

@app.route("/create_invoice2")
@xero_token_required
def create_invoice2():
    params = {
        'access_token': json.dumps(obtain_xero_oauth2_token()),
        'description': 'Monthly Contributor Payment',
        #'contact_id': '2aa14f27-1b27-45a0-94ee-80d19f60dc92',
        'contact_name': 'Foo Bar',
        'contact_email': 'ben.bowden@24locks.com',
        'amount': '1000000.99',
    }
    proxied_response = requests.get(f'{CONNECTOR_PROXY_URL}/do/xero/CreateInvoice', params)
    sub_title = 'Proxied create invoice response'

    invoices = json.loads(proxied_response.text)
    code = serialize_model(invoices)
    return render_template(
        "/code.html", title="Invoices", code=code, sub_title=sub_title
    )

@app.route("/get_employee_salary")
def get_employee_salary():
    params = {
        'employee_id': '4',
    }

    proxied_response = requests.get(f'{CONNECTOR_PROXY_URL}/do/bamboohr/GetPayRate', params)
    sub_title = 'Proxied get pay rate response'

    invoices = json.loads(proxied_response.text)
    code = serialize_model(invoices)
    return render_template(
        "/code.html", title="Pay Rate", code=code, sub_title=sub_title
    )

@app.route('/proxy_commands')
def proxy_commands():
    proxied_response = requests.get(f'{CONNECTOR_PROXY_URL}/commands')
    code = json.dumps(json.loads(proxied_response.text), indent=4)
    sub_title = 'Commands'

    return render_template("/code.html", title="Commands", code=code, sub_title=sub_title)

@app.route('/proxy_auths')
def proxy_auths():
    proxied_response = requests.get(f'{CONNECTOR_PROXY_URL}/auths')
    code = json.dumps(json.loads(proxied_response.text), indent=4)
    sub_title = 'Auths'

    return render_template("/code.html", title="Auths", code=code, sub_title=sub_title)

@app.route('/create_and_upload_pdf')
def create_and_upload_pdf():
    params = {
        'template': '''# Invoice Title
## Sub Title

Name: {{ name }}

Amount: {{ amount }}
''',
        'spiff__task_data': '{"name": "Task Data", "amount": "$67.43"}',
        'aws_object_name': f'invoice_{time.time()}.pdf',
    }
    proxied_response = requests.get(f'{CONNECTOR_PROXY_URL}/do/pdf/CreatePDFAndUploadToS3', params)
    code = json.dumps(json.loads(proxied_response.text), indent=1)
    sub_title = 'Create and Upload PDF to S3'

    return render_template('/code.html', title='Invoice PDF -> S3', code=code, sub_title=sub_title)

@app.route('/upload_file_data')
def upload_file_data():
    params = {
        "file_data": "data:application/pdf;name=Harmeet_13435%20(1).pdf;base64,JVBERi0xLjQKJZOMi54gUmVwb3J0TGFiIEdlbmVyYXRlZCBQREYgZG9jdW1lbnQgaHR0cDovL3d3dy5yZXBvcnRsYWIuY29tCjEgMCBvYmoKPDwKL0YxIDIgMCBSIC9GMiAzIDAgUiAvRjMgNCAwIFIKPj4KZW5kb2JqCjIgMCBvYmoKPDwKL0Jhc2VGb250IC9IZWx2ZXRpY2EgL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcgL05hbWUgL0YxIC9TdWJ0eXBlIC9UeXBlMSAvVHlwZSAvRm9udAo+PgplbmRvYmoKMyAwIG9iago8PAovQmFzZUZvbnQgL0hlbHZldGljYS1Cb2xkIC9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nIC9OYW1lIC9GMiAvU3VidHlwZSAvVHlwZTEgL1R5cGUgL0ZvbnQKPj4KZW5kb2JqCjQgMCBvYmoKPDwKL0Jhc2VGb250IC9IZWx2ZXRpY2EtQm9sZE9ibGlxdWUgL0VuY29kaW5nIC9XaW5BbnNpRW5jb2RpbmcgL05hbWUgL0YzIC9TdWJ0eXBlIC9UeXBlMSAvVHlwZSAvRm9udAo+PgplbmRvYmoKNSAwIG9iago8PAovQ29udGVudHMgMTIgMCBSIC9NZWRpYUJveCBbIDAgMCA1OTUuMjc1NiA4NDEuODg5OCBdIC9QYXJlbnQgMTEgMCBSIC9SZXNvdXJjZXMgPDwKL0ZvbnQgMSAwIFIgL1Byb2NTZXQgWyAvUERGIC9UZXh0IC9JbWFnZUIgL0ltYWdlQyAvSW1hZ2VJIF0KPj4gL1JvdGF0ZSAwIC9UcmFucyA8PAoKPj4gCiAgL1R5cGUgL1BhZ2UKPj4KZW5kb2JqCjYgMCBvYmoKPDwKL091dGxpbmVzIDggMCBSIC9QYWdlTW9kZSAvVXNlTm9uZSAvUGFnZXMgMTEgMCBSIC9UeXBlIC9DYXRhbG9nCj4+CmVuZG9iago3IDAgb2JqCjw8Ci9BdXRob3IgKCkgL0NyZWF0aW9uRGF0ZSAoRDoyMDIyMTAxMzExNDQyNSswMCcwMCcpIC9DcmVhdG9yIChcKHVuc3BlY2lmaWVkXCkpIC9LZXl3b3JkcyAoKSAvTW9kRGF0ZSAoRDoyMDIyMTAxMzExNDQyNSswMCcwMCcpIC9Qcm9kdWNlciAoeGh0bWwycGRmIDxodHRwczovL2dpdGh1Yi5jb20veGh0bWwycGRmL3hodG1sMnBkZi8+KSAKICAvU3ViamVjdCAoKSAvVGl0bGUgKCkgL1RyYXBwZWQgL0ZhbHNlCj4+CmVuZG9iago4IDAgb2JqCjw8Ci9Db3VudCAyIC9GaXJzdCA5IDAgUiAvTGFzdCA5IDAgUiAvVHlwZSAvT3V0bGluZXMKPj4KZW5kb2JqCjkgMCBvYmoKPDwKL0NvdW50IC0xIC9EZXN0IFsgNSAwIFIgL0ZpdCBdIC9GaXJzdCAxMCAwIFIgL0xhc3QgMTAgMCBSIC9QYXJlbnQgOCAwIFIgL1RpdGxlIChJbnZvaWNlIFN1Ym1pc3Npb24gSW5mb3JtYXRpb24pCj4+CmVuZG9iagoxMCAwIG9iago8PAovRGVzdCBbIDUgMCBSIC9GaXQgXSAvUGFyZW50IDkgMCBSIC9UaXRsZSAoSW52b2ljZSBTdWJtaXNzaW9uIEluZm9ybWF0aW9uKQo+PgplbmRvYmoKMTEgMCBvYmoKPDwKL0NvdW50IDEgL0tpZHMgWyA1IDAgUiBdIC9UeXBlIC9QYWdlcwo+PgplbmRvYmoKMTIgMCBvYmoKPDwKL0ZpbHRlciBbIC9BU0NJSTg1RGVjb2RlIC9GbGF0ZURlY29kZSBdIC9MZW5ndGggNTA3Cj4+CnN0cmVhbQpHYXUxK2dJZkBLJjtLWkYnUVtDYmg8cksuai4zVW8kUjFoVCM9cUtrLk87aUlVQTRGVzY3WjRgNnRmWzhRQ1soMW1mPmBGXyJQT2YhVV5WZy9lRiplZmA+aV0rYUpacCxeUEFMcjhHYmVdTVI8cyRTSFY+YF1WcjpYZ288WCp1MW9NOy1rKTglYVlLYl1lXjNUZlN0QWw2QzsuTllTRUg8M21CNkkrVXQ/MkplWGIzI11HXk0lUikqKShWXlBrNW89cipPUTpyVzwwUjNPL3VaJDRuT3Q3YCZiW25eKEBVP25TJilcbWpHMmRjOl9wOGRHJUpiRE1XWnBbXUwiQWtrWjtXSVgkOEZbTD9oX1JgX1ImLlRSUjVUS0pVVmciOkhiIiRyMWt1Rz5dU2cwJlUiWzhrWTE9ViYhOypsMzZkXC8/M1tBZTVbQ0UzUituYig6Ml1jUE5ySnFkdVwzRmVYUEljMHNPKzk+OXNLSj9kOmFjT2E6TGZtVksrRXBPJFE9J3VBTCU+MUgsJlREMztJVjNVOylPIU5gJEcyNFVAWHA5SFJePD1eMlc0TCdIbSlzNlUpWHQwW0szMW86VHUzckErWTEhbio/KVNsa0lpYGwzOGZlWms+XmF0OGhhJkElLURdYTkxUC5ZSm9YMzFNJTdvTC4/VElhfj5lbmRzdHJlYW0KZW5kb2JqCnhyZWYKMCAxMwowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwNzMgMDAwMDAgbiAKMDAwMDAwMDEyNCAwMDAwMCBuIAowMDAwMDAwMjMxIDAwMDAwIG4gCjAwMDAwMDAzNDMgMDAwMDAgbiAKMDAwMDAwMDQ2MiAwMDAwMCBuIAowMDAwMDAwNjY3IDAwMDAwIG4gCjAwMDAwMDA3NTIgMDAwMDAgbiAKMDAwMDAwMTAwNCAwMDAwMCBuIAowMDAwMDAxMDc1IDAwMDAwIG4gCjAwMDAwMDEyMDggMDAwMDAgbiAKMDAwMDAwMTMwNSAwMDAwMCBuIAowMDAwMDAxMzY1IDAwMDAwIG4gCnRyYWlsZXIKPDwKL0lEIApbPDFjM2QzNmZmOTRjM2ZmMjRkNDg2MTViY2ZlNTg3ZDY5PjwxYzNkMzZmZjk0YzNmZjI0ZDQ4NjE1YmNmZTU4N2Q2OT5dCiUgUmVwb3J0TGFiIGdlbmVyYXRlZCBQREYgZG9jdW1lbnQgLS0gZGlnZXN0IChodHRwOi8vd3d3LnJlcG9ydGxhYi5jb20pCgovSW5mbyA3IDAgUgovUm9vdCA2IDAgUgovU2l6ZSAxMwo+PgpzdGFydHhyZWYKMTk2MwolJUVPRgo=",
        "bucket": "sartography-status-pdfs",
        "object_name": "upload-from-task-data2.1.pdf",
    }
    proxied_response = requests.get(f'{CONNECTOR_PROXY_URL}/do/aws/UploadFileData', params)
    code = json.dumps(json.loads(proxied_response.text), indent=1)
    sub_title = 'Upload File Data'

    return render_template('/code.html', title='File Data -> S3', code=code, sub_title=sub_title)


@app.route('/proxy_xero_oauth')
def proxy_xero_oauth():
    sub_title = 'Xero OAuth'

    redirect_url = 'http://localhost:5000/proxy_callback'

    link = f'{CONNECTOR_PROXY_URL}/auth/xero/OAuth?redirect_url={redirect_url}'

    return render_template("/code.html", title="Xero OAuth", sub_title=sub_title, link=link)

@app.route("/create_invoice")
@xero_token_required
def create_invoice():
    api_instance = AccountingApi(api_client)
    xero_tenant_id = get_xero_tenant_id()
    summarize_errors = 'True'
    unitdp = 2
    date_value = dateutil.parser.parse('2020-10-10T00:00:00Z')
    due_date_value = dateutil.parser.parse('2020-10-28T00:00:00Z')

    contact = Contact(
        contact_id = "de73f5b8-6ead-4639-91b9-f80d363e757b")

    #line_item_tracking = LineItemTracking(
    #    tracking_category_id = "00000000-0000-0000-0000-000000000000",
    #    tracking_option_id = "00000000-0000-0000-0000-000000000000")
    
    #line_item_trackings = []    
    #line_item_trackings.append(line_item_tracking)

    line_item = LineItem(
        description = "Foobar",
        quantity = 1.0,
        unit_amount = 20.0,
        account_code = "612",
        tax_type = "NONE",
        tracking = []) #line_item_trackings)
    
    line_items = []    
    line_items.append(line_item)

    invoice = Invoice(
        type = "ACCREC",
        contact = contact,
        date = date_value,
        due_date = due_date_value,
        line_items = line_items,
        reference = "Website Design",
        status = "AUTHORISED")

    invoices = Invoices( 
        invoices = [invoice])
    
    created_invoices = api_instance.create_invoices(xero_tenant_id, invoices, summarize_errors, unitdp)
    code = serialize_model(created_invoices)
    sub_title = "Total invoices created: {}".format(len(created_invoices.invoices))

    return render_template(
        "/code.html", title="Created Invoices", code=code, sub_title=sub_title
    )

@app.route("/login")
def login():
    redirect_url = url_for("oauth_callback", _external=True)
    response = xero.authorize(callback_uri=redirect_url)
    return response

@app.route('/proxy_callback')
def proxy_callback():
    response = json.loads(request.args['response'])
    store_xero_oauth2_token(response)
    return redirect(url_for("index", _external=True))

@app.route("/callback")
def oauth_callback():
    try:
        response = xero.authorized_response()
    except Exception as e:
        print(e)
        raise
    # todo validate state value
    if response is None or response.get("access_token") is None:
        return "Access denied: response=%s" % response
    store_xero_oauth2_token(response)
    return redirect(url_for("index", _external=True))


@app.route("/logout")
def logout():
    store_xero_oauth2_token(None)
    return redirect(url_for("index", _external=True))


@app.route("/export-token")
@xero_token_required
def export_token():
    token = obtain_xero_oauth2_token()
    buffer = BytesIO("token={!r}".format(token).encode("utf-8"))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="x.python",
        as_attachment=True,
        download_name="oauth2_token.py",
    )


@app.route("/refresh-token")
@xero_token_required
def refresh_token():
    xero_token = obtain_xero_oauth2_token()
    new_token = api_client.refresh_oauth2_token()
    return render_template(
        "code.html",
        title="Xero OAuth2 token",
        code=jsonify({"Old Token": xero_token, "New token": new_token}),
        sub_title="token refreshed",
    )


def get_xero_tenant_id():
    token = obtain_xero_oauth2_token()
    if not token:
        return None

    identity_api = IdentityApi(api_client)
    for connection in identity_api.get_connections():
        if connection.tenant_type == "ORGANISATION":
            return connection.tenant_id


if __name__ == '__main__':
    app.run(host='localhost', port=5000)
