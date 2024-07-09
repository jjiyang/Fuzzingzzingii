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
import requests
import logging

class MySpider(scrapy.Spider):
    name = 'crawler'

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

        chrome_driver_path = './chromedriver'
        self.service = Service(chrome_driver_path)

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        
        proxy = 'http://13.209.63.65:8888'
        chrome_options.add_argument(f'--proxy-server={proxy}')
        logging.info(f'Using proxy: {proxy}')

        self.driver = webdriver.Chrome(service=self.service, options=chrome_options)

        self.login()

    def login(self):
        self.driver.get(self.login_url)
        username_field = WebDriverWait(self.driver, 10).until(
            EC.visibility_of_element_located((By.NAME, 'username'))
        )
        password_field = self.driver.find_element(By.NAME, 'password')
        submit_button = self.driver.find_element(By.XPATH, '//input[@type="submit" and @value="Login"]')

        username_field.send_keys(self.username)
        password_field.send_keys(self.password)

        try:
            self.driver.execute_script("arguments[0].scrollIntoView(true);", submit_button)
            submit_button.click()
        except Exception as e:
            self.driver.execute_script("arguments[0].click();", submit_button)

        WebDriverWait(self.driver, 10).until(EC.url_changes(self.login_url))

        self.session_cookies = self.driver.get_cookies()
        self.session_cookie_dict = self.get_session_cookie_dict()
        self.init_requests_session()

    def init_requests_session(self):
        self.requests_session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36 Edg/96.0.1054.62'
        }
        self.requests_session.headers.update(headers)
        self.requests_session.cookies.update(self.session_cookie_dict)

    def start_requests(self):
        for url in self.start_urls:
            logging.info(f'Starting request for {url} with proxy {self.driver.capabilities.get("proxy")}')
            yield scrapy.Request(url, callback=self.parse, cookies=self.session_cookie_dict)

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
                f.flush()  # Flush the buffer to ensure data is written immediately

            a_links = response.xpath('//a/@href').extract()

            for link in a_links:
                link = response.urljoin(link)
                link = self.normalize_url(link)
                link_domain = urlparse(link).netloc

                if self.domain_origin in link_domain and link not in self.seen_urls and not link.endswith('logout.php'):
                    logging.info(f'Following link: {link} with proxy {self.driver.capabilities.get("proxy")}')
                    yield scrapy.Request(url=link, callback=self.parse, cookies=self.session_cookie_dict)

            self.driver.get(response.url)
            self.trigger_js_events()

            updated_body = self.driver.page_source
            updated_response = HtmlResponse(
                url=response.url, 
                body=updated_body, 
                encoding='utf-8',
                headers={'Content-Type': 'text/html'}
            )

            yield updated_response

        except Exception as e:
            pass

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
                pass

        except Exception as e:
            pass

    def get_session_cookie_dict(self):
        cookies = {cookie['name']: cookie['value'] for cookie in self.session_cookies}
        return cookies

    def closed(self, reason):
        self.driver.quit()