import scrapy
import tldextract
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
from scrapy.http import HtmlResponse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.common.proxy import Proxy, ProxyType
import requests
import logging
from webdriver_manager.chrome import ChromeDriverManager

class MySpider(scrapy.Spider):
    name = 'crawler'

    custom_settings = {
        'REQUEST_FINGERPRINTER_IMPLEMENTATION': '2.7',  # 또는 'sha1'
    }

    def __init__(self, start_url=None, login_url=None, username=None, password=None, *args, **kwargs):
        super(MySpider, self).__init__(*args, **kwargs)

        if start_url:
            self.start_urls = [start_url]
        else:
            raise ValueError("No start URL provided")

        if not login_url or not username or not password:
            raise ValueError("Login URL, username, and password must be provided")

        self.login_url = login_url
        self.username = username
        self.password = password

        self.domain_origin = tldextract.extract(self.start_urls[0]).domain
        self.output_file = 'output.txt'
        self.seen_urls = set()

        self.proxy_url = 'http://13.209.63.65:8888'  # 프록시 주소 변경 가능
        capabilities = webdriver.DesiredCapabilities.CHROME.copy()
        capabilities['proxy'] = {
            "proxyType": ProxyType.MANUAL,
            "httpProxy": self.proxy_url,
            "sslProxy": self.proxy_url,
        }

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument(f'--proxy-server={self.proxy_url}')
        logging.info(f'Using proxy: {self.proxy_url}')

        self.service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=self.service, options=chrome_options)

        self.login()

    def login(self):
        try:
            self.driver.get(self.login_url)
            username_field = WebDriverWait(self.driver, 10).until(
                EC.visibility_of_element_located((By.NAME, 'username'))
            )
            password_field = self.driver.find_element(By.NAME, 'password')
            submit_button = self.driver.find_element(By.XPATH, '//input[@type="submit" and @value="Login"]')

            username_field.send_keys(self.username)
            logging.info(f'Entered username: {self.username}')
            password_field.send_keys(self.password)
            logging.info(f'Entered password: {self.password}')

            self.driver.execute_script("arguments[0].scrollIntoView(true);", submit_button)
            submit_button.click()
            logging.info('Submit button clicked')

            WebDriverWait(self.driver, 10).until(EC.url_changes(self.login_url))

            self.current_url = self.driver.current_url
            logging.info(f'After login, current URL is {self.current_url}')

            self.session_cookies = self.driver.get_cookies()
            self.session_cookie_dict = self.get_session_cookie_dict()
            self.init_requests_session()
        except Exception as e:
            logging.error(f'Error during login: {e}')

    def init_requests_session(self):
        self.requests_session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62'
        }
        self.requests_session.headers.update(headers)
        self.requests_session.cookies.update(self.session_cookie_dict)

    def start_requests(self):
        for url in self.start_urls:
            logging.info(f'Starting request for {url} with proxy {self.proxy_url}')
            yield scrapy.Request(url, callback=self.parse, cookies=self.session_cookie_dict, meta={'proxy': self.proxy_url})

    def parse(self, response):
        try:
            content_type = response.headers.get('Content-Type', b'').decode('utf-8')

            if not content_type.startswith('text'):
                return

            normalized_url = self.normalize_url(response.url)

            if normalized_url in self.seen_urls:
                return

            self.seen_urls.add(normalized_url)
            with open(self.output_file, 'a') as f:
                f.write(f'{normalized_url}\n')
                f.flush()

            a_links = response.xpath('//a/@href').extract()

            for link in a_links:
                link = response.urljoin(link)
                link = self.normalize_url(link)
                link_domain = urlparse(link).netloc

                if self.domain_origin in link_domain and link not in self.seen_urls and not link.endswith('logout.php'):
                    logging.info(f'Following link: {link} with proxy {self.proxy_url}')
                    yield scrapy.Request(url=link, callback=self.parse, cookies=self.session_cookie_dict, meta={'proxy': self.proxy_url})

            try:
                self.driver.get(response.url)
                logging.info(f'Accessing {response.url} through proxy.')

                self.trigger_js_events()

                updated_body = self.driver.page_source
                updated_response = HtmlResponse(
                    url=response.url,
                    body=updated_body,
                    encoding='utf-8',
                    headers={'Content-Type': 'text/html'}
                )

                yield from self.parse_page(updated_response)
            except Exception as e:
                logging.error(f'Failed to access {response.url} through proxy: {e}')

        except Exception as e:
            logging.error(f'Error in parse: {e}')

    def parse_page(self, response):
        try:
            a_links = response.xpath('//a/@href').extract()

            for link in a_links:
                link = response.urljoin(link)
                link = self.normalize_url(link)
                link_domain = urlparse(link).netloc

                if self.domain_origin in link_domain and link not in self.seen_urls and not link.endswith('logout.php'):
                    logging.info(f'Following link: {link} with proxy {self.proxy_url}')
                    yield scrapy.Request(url=link, callback=self.parse, cookies=self.session_cookie_dict, meta={'proxy': self.proxy_url})

        except Exception as e:
            logging.error(f'Error during parse_page: {e}')

    def normalize_url(self, url):
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        filtered_query = {k: v for k, v in query.items() if k not in ['random', 'session', 'timestamp']}
        normalized_query = urlencode(filtered_query, doseq=True)

        normalized_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            normalized_query,
            parsed_url.fragment
        ))
        return normalized_url

    def trigger_js_events(self):
        try:
            initial_url = self.driver.current_url
            self.driver.execute_script("""
                var elements = document.querySelectorAll('*');
                elements.forEach(function(element) {
                    var href = element.getAttribute('href');
                    if (typeof element.onclick == 'function' && href !== 'reset.php' && href !== 'logout.php') {
                        element.click();
                    }
                });
            """)

            try:
                WebDriverWait(self.driver, 10).until(EC.url_changes(initial_url))
                self.driver.back()
            except Exception as e:
                logging.error(f'Error during WebDriverWait or driver.back(): {e}')

        except Exception as e:
            logging.error(f'Error during trigger_js_events: {e}')

    def get_session_cookie_dict(self):
        cookies = {cookie['name']: cookie['value'] for cookie in self.session_cookies}
        return cookies

    def closed(self, reason):
        self.driver.quit()