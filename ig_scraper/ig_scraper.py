import base64
import datetime
import json
import logging
from typing import List

import pandas as pd
import requests

STORIES_UA = "Instagram 123.0.0.21.114 (iPhone; CPU iPhone OS 11_4 like Mac OS X; en_US; en-US; scale=2.00; 750x1334) AppleWebKit/605.1.15"
BASE_URL = "https://www.instagram.com/"
LOGIN_URL = BASE_URL + "accounts/login/ajax/"
LOGOUT_URL = BASE_URL + "accounts/logout/"
CHROME_WIN_UA = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36"

IG_QUERY_TEMPLATE = "https://www.instagram.com/graphql/query/?query_hash=bc3296d1ce80a24b1b6e40b1e72903f5&shortcode=B4CxPbNlvQK&first=400&after="

IG_REQUEST_HEADER = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "accept-language": "sv,en;q=0.9,en-GB;q=0.8,en-US;q=0.7,no;q=0.6",
    "cache-control": "max-age=0",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 Edg/87.0.664.57",
}


def take(d, *args, default=None):
    for arg in args:
        if d.get(arg, None) is None:
            return default
        d = d[arg]
    return d


# https://www.instagram.com/graphql/query/?query_hash=bc3296d1ce80a24b1b6e40b1e72903f5&shortcode=B4CxPbNlvQK&first=400&after=


def id_to_shortcode(instagram_id: int) -> str:
    return (
        base64.b64encode(int(instagram_id).to_bytes(9, "big"), b"-_")
        .decode()
        .replace("A", " ")
        .lstrip()
        .replace(" ", "A")
    )


def shortcode_to_id(shortcode):
    code = ("A" * (12 - len(shortcode))) + shortcode
    return int.from_bytes(base64.b64decode(code.encode(), b"-_"), "big")


class Session:
    def __init__(self):
        self.logged_in = False
        self.authenticated = False
        self.cookies = None
        self.cookie_jar = None
        self.csrf_token = None
        self.session_id = None

        # from instagram-scraper
        self.session = requests.Session()
        # if self.no_check_certificate:
        #     self.session.verify = False
        self.session.headers = {"user-agent": IG_REQUEST_HEADER["user-agent"]}
        # if self.cookiejar and os.path.exists(self.cookiejar):
        #     with open(self.cookiejar, 'rb') as f:
        #         self.session.cookies.update(pickle.load(f))
        self.session.cookies.set("ig_pr", "1")
        self.rhx_gis = ""

    def fetch_ig_post(
        self, shortcode: str, end_cursor: str = "", count: int = 40
    ) -> "CommentPagingPage":
        # response = requests.get(
        #     url=f'https://www.instagram.com/graphql/query/?query_hash=bc3296d1ce80a24b1b6e40b1e72903f5&shortcode={shortcode}&first={count}&after={end_cursor}',
        #     headers=IG_REQUEST_HEADER,
        # )
        response = self.get(
            url=f"https://www.instagram.com/graphql/query/?query_hash=bc3296d1ce80a24b1b6e40b1e72903f5&shortcode={shortcode}&first={count}&after={end_cursor}",
        )
        if response.status_code not in (200,):
            raise ValueError(f"failed {shortcode}")

        content = json.loads(response.content)
        if content.get("status", None) != "ok":
            raise ValueError(
                f"expected status 'ok' found {content.get('status', None)}"
            )

        edge_media_to_parent_comment = take(
            content, "data", "shortcode_media", "edge_media_to_parent_comment"
        )

        if edge_media_to_parent_comment is not None:
            return CommentPagingPage(session=self, data=edge_media_to_parent_comment, shortcode=shortcode)

        logging.warning(f"no comments found for {shortcode}")
        return None

    def get(self, *args, **kwargs):
        response = self.session.get(timeout=30, cookies=self.cookies, *args, **kwargs)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        content_length = response.headers.get("Content-Length")
        if content_length is not None and len(response.content) != int(content_length):
            raise Exception("Only partial response received")
        return response

    def login(self, username: str, password: str):

        link = "https://www.instagram.com/accounts/login/"
        login_url = "https://www.instagram.com/accounts/login/ajax/"

        time = int(datetime.datetime.now().timestamp())
        response = requests.get(link)
        csrf = response.cookies["csrftoken"]

        payload = {
            "username": username,
            "enc_password": f"#PWD_INSTAGRAM_BROWSER:0:{time}:{password}",
            "queryParams": {},
            "optIntoOneTap": "false",
        }

        login_header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.instagram.com/accounts/login/",
            "x-csrftoken": csrf,
        }

        login_response = requests.post(login_url, data=payload, headers=login_header)
        json_data = json.loads(login_response.text)

        if json_data["authenticated"]:

            print("login successful")
            self.cookies = login_response.cookies
            self.cookie_jar = self.cookies.get_dict()
            self.csrf_token = self.cookie_jar["csrftoken"]
            self.session_id = self.cookie_jar["sessionid"]
        else:
            print("login failed ", login_response.text)

        return self

    def authenticate_as_guest(self):
        """Authenticate as a guest/non-signed in user"""

        self.session.headers.update({"Referer": BASE_URL, "user-agent": STORIES_UA})
        req = self.session.get(BASE_URL)

        self.session.headers.update({"X-CSRFToken": req.cookies["csrftoken"]})

        self.session.headers.update({"user-agent": CHROME_WIN_UA})
        self.rhx_gis = ""
        self.authenticated = True

        return self

    def authenticate_with_login(self, login_user: str, password: str):
        """Logs in to instagram."""
        self.session.headers.update({"Referer": BASE_URL, "user-agent": STORIES_UA})
        req = self.session.get(BASE_URL)

        self.session.headers.update({"X-CSRFToken": req.cookies["csrftoken"]})

        login_data = {"username": login_user, "password": password}
        login = self.session.post(LOGIN_URL, data=login_data, allow_redirects=True)
        self.session.headers.update({"X-CSRFToken": login.cookies["csrftoken"]})
        self.cookies = login.cookies
        login_text = json.loads(login.text)

        if login_text.get("authenticated") and login.status_code == 200:
            self.authenticated = True
            self.logged_in = True
            self.session.headers.update({"user-agent": CHROME_WIN_UA})
            self.rhx_gis = ""
        else:
            self.logger.error("Login failed for " + login_user)

        return self


class Comment:
    def __init__(self, *, session: "Session", node, parent_shortcode: str):
        super().__setattr__("node", node or dict())
        self.parent_shortcode = parent_shortcode
        self.attributes = [
            "id",
            "text",
            "created_at",
            "did_report_as_spam",
            "owner",
            "viewer_has_liked",
            "edge_liked_by",
            "is_restricted_pending",
            "edge_threaded_comments",
        ]
        if len([x for x in self.node.keys() if x not in self.attributes]) > 0:
            print(
                f"Unhandled key(s) encountered {','.join([ x for x in self.node.keys() if x not in self.attributes])}"
            )
        self.session = session

    @property
    def id(self) -> str:
        return self.node.get("id", None)

    @property
    def shortcode(self) -> str:
        return id_to_shortcode(self.id)

    @property
    def text(self) -> str:
        return self.node.get("text", None)

    @property
    def created_at(self) -> int:
        return self.node.get("created_at", None)

    @property
    def did_report_as_spam(self) -> bool:
        return self.node.get("did_report_as_spam", None)

    @property
    def owner(self) -> dict:
        return self.node.get("owner", None)

    @property
    def viewer_has_liked(self) -> bool:
        return self.node.get("viewer_has_liked", None)

    @property
    def edge_liked_by(self) -> int:
        return take(self.node, "edge_liked_by", "count", default=0)

    @property
    def is_restricted_pending(self) -> bool:
        return self.node.get("is_restricted_pending", None)

    @property
    def replies(self) -> "CommentPagingPage":
        if take(self.node, "edge_threaded_comments", "count", default=0) == 0:
            return None

        return CommentPagingPage(
            session=self.session,
            data=self.node["edge_threaded_comments"],
            shortcode=self.shortcode,
            parent_shortcode=self.shortcode,
        )


class CommentPagingPage:
    def __init__(self, *, session: "Session", data: dict, shortcode: str, parent_shortcode: str=''):
        super().__setattr__("data", data or dict())
        self.session = session
        self.shortcode = shortcode
        self.parent_shortcode = parent_shortcode

    @property
    def count(self) -> int:
        return self.data.get("count", None)

    @property
    def has_next_page(self) -> bool:
        return take(self.data, "page_info", "has_next_page", default=False)

    @property
    def end_cursor(self) -> str:
        return take(self.data, "page_info", "end_cursor")

    @property
    def comments(self) -> List[Comment]:
        edges = self.data.get("edges", [])
        return [
            Comment(
                session=self.session,
                node=node["node"],
                parent_shortcode=self.parent_shortcode,
            )
            for node in edges
        ]

    def turn_page(self) -> "CommentPagingPage":
        if not self.has_next_page:
            return None
        return self.session.fetch_ig_post(self.shortcode, end_cursor=self.end_cursor)


def scrape(*, ig_post: CommentPagingPage, parent_shortcode=''):

    comments = []
    while ig_post is not None:

        for ig_comment in ig_post.comments:
            comments.append(
                {
                    "short_code": ig_comment.shortcode,
                    "parent_shortcode": parent_shortcode,
                    "id": ig_comment.id,
                    "text": ig_comment.text,
                    "created_at": ig_comment.created_at,
                    "did_report_as_spam": ig_comment.did_report_as_spam,
                    "username": ig_comment.owner["username"],
                    "user_id": ig_comment.owner["id"],
                    "viewer_has_liked": ig_comment.viewer_has_liked,
                    "edge_liked_by": ig_comment.edge_liked_by,
                    "is_restricted_pending": ig_comment.is_restricted_pending,
                }
            )
            logging.info(f"{ig_comment.shortcode};{parent_shortcode};")
            if ig_comment.replies:
                comments.extend(scrape(ig_post=ig_comment.replies, parent_shortcode=ig_comment.shortcode,))

        ig_post = ig_post.turn_page()

    return comments


scrape_codes = [
    ('VisitDubai', 'B4CxPbNlvQK'),
    ('VisitDubai', 'B4FwCVSluNe'),
    ('VisitDubai', 'B4ItOyol4NC'),
    ('VisitDubai', 'B4ItOyol4NC'),
    ('VisitDubai', 'B4KmFi9nKIG'),

    ### BLM:
    ('BLM', 'CA3LpKaAH2e'),
    ('BLM', 'CA7a2N0jLTw'),
    ('BLM', 'CBDMgfll6u4'),
    ('BLM', 'CA94uQGHsP6'),
    ('BLM', 'CBAJmyjnzC8'),
    ('BLM', 'CA0lNEtnrWb'),
    ('BLM', 'CA7ty2OHR3s'),
    ('BLM', 'CBBcOcgHQMj'),
    ('BLM', 'CBBgU18Hoik'),
    ('BLM', 'CBGnxrdnmQ1'),
    ('BLM', 'CA7iN-FJXue'),
    ('BLM', 'CA7BnkjjZzs'),
    ('BLM', 'CBIL9Dijjk9'),
    ('BLM', 'CA2ojW7BL8C'),
    ('BLM', 'CA7i6MGhPj_'),
    ('BLM', 'CA9mLqYhKGy'),
    ('BLM', 'CA7S1yqIY6g'),
    ('BLM', 'CA_M3a0IJES'),
    ('BLM', 'CBBZfXzoyv5'),
    ('BLM', 'CA7eCv3heZz'),
    ('BLM', 'CBJK5fOjreh'),
    ('BLM', 'CA7qyTalK7r'),
    ('BLM', 'CA7maxxF_WV'),
    ('BLM', 'CA7bs3sjGP8'),
    ('BLM', 'CA7mR9uHFBa'),
    ('BLM', 'CA7We5bggm8'),
    ('BLM', 'CA8S-13JWEl'),
    ('BLM', 'CA9zG2YDWGi'),
    ('BLM', 'CA7iRWCA8-m'),
    ('BLM', 'CA8R-hOJ864'),
    ('BLM', 'CA7PfKYAD64'),
    ('BLM', 'CA9f1oLAiQx'),
]


session = Session().authenticate_with_login("username", "password")

dfs = []

for tag, shortcode in scrape_codes:

    ig_post: CommentPagingPage = session.fetch_ig_post(
        shortcode=shortcode, end_cursor="", count=100
    )
    comments = scrape(ig_post=ig_post)

    df = pd.DataFrame(comments)
    df['post'] = shortcode
    df['tag'] = tag

    dfs.append(df)

df_total = pd.concat(dfs)

df_total.to_csv(f"ig_scraped_data.csv", sep='\t', quotechar='"')
df_total.to_excel(f"ig_scraped_data.xlsx")

