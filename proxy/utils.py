import urllib.parse
import json
import re

ANSI_GREEN, ANSI_ORANGE, ANSI_PURPLE = 32, 91, 35

def colorize(color_code: int, text: str):
    return f"\x1b[{color_code}m{text}\x1b[0m"

def parse_query_string(query_string):
    return "\n".join(
        f"%-20s %s" % (k, v)
        for k, v in urllib.parse.parse_qsl(query_string, keep_blank_values=True)
    )

def log_request_info(req, req_body, res, res_body):
    req_header_text = "%s %s %s\n%s" % (
        req.command,
        req.path,
        req.request_version,
        req.headers,
    )
    version_table = {10: "HTTP/1.0", 11: "HTTP/1.1"}
    res_header_text = "%s %d %s\n%s" % (
        version_table[res.version],
        res.status,
        res.reason,
        res.headers,
    )

    print(colorize(ANSI_ORANGE, req_header_text))

    url_parts = urllib.parse.urlsplit(req.path)
    if url_parts.query:
        query_text = parse_query_string(url_parts.query)
        print(colorize(ANSI_GREEN, "==== QUERY PARAMETERS ====\n%s\n" % query_text))

    cookie = req.headers.get("Cookie", "")
    if cookie:
        cookie = parse_query_string(re.sub(r";\s*", "&", cookie))
        print(colorize(ANSI_GREEN, "==== COOKIE ====\n%s\n" % cookie))

    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("basic"):
        token = auth.split()[1].decode("base64")
        print(colorize(ANSI_PURPLE, "==== BASIC AUTH ====\n%s\n" % token))

    if req_body:
        req_body_text = None
        content_type = req.headers.get("Content-Type", "")

        if content_type.startswith("application/x-www-form-urlencoded"):
            req_body_text = parse_query_string(req_body)
        elif content_type.startswith("application/json"):
            try:
                json_obj = json.loads(req_body)
                json_str = json.dumps(json_obj, indent=2)
                if json_str.count("\n") < 50:
                    req_body_text = json_str
                else:
                    lines = json_str.splitlines()
                    req_body_text = "%s\n(%d lines)" % (
                        "\n".join(lines[:50]),
                        len(lines),
                    )
            except ValueError:
                req_body_text = req_body
        elif len(req_body) < 1024:
            req_body_text = req_body

        if req_body_text:
            print(colorize(ANSI_GREEN, "==== REQUEST BODY ====\n%s\n" % req_body_text))

    print(colorize(ANSI_PURPLE, res_header_text))

    cookies = res.headers.get("Set-Cookie")
    if cookies:
        print(colorize(ANSI_PURPLE, "==== SET-COOKIE ====\n%s\n" % cookies))

    if res_body:
        res_body_text = None
        content_type = res.headers.get("Content-Type", "")

        if content_type.startswith("application/json"):
            try:
                json_obj = json.loads(res_body)
                json_str = json.dumps(json_obj, indent=2)
                if json_str.count("\n") < 50:
                    res_body_text = json_str
                else:
                    lines = json_str.splitlines()
                    res_body_text = "%s\n(%d lines)" % (
                        "\n".join(lines[:50]),
                        len(lines),
                    )
            except ValueError:
                res_body_text = res_body
        elif content_type.startswith("text/html"):
            m = re.search(rb"<title[^>]*>\s*([^<]+?)\s*</title>", res_body, re.I)
            if m:
                print(
                    colorize(
                        ANSI_GREEN, "==== HTML TITLE ====\n%s\n" % m.group(1).decode()
                    )
                )
        elif content_type.startswith("text/") and len(res_body) < 1024:
            res_body_text = res_body

        if res_body_text:
            print(colorize(ANSI_GREEN, "==== RESPONSE BODY ====\n%s\n" % res_body_text))