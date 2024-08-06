import requests
from urllib.parse import urlparse
import urlunshort3


# 단축 URL 도메인 목록
SHORTENING_DOMAINS = set([
    'bit.ly', 'kl.am', 'cli.gs', 'bc.vc', 'po.st', 'v.gd', 'bkite.com', 
    'shorl.com', 'scrnch.me', 'to.ly', 'adf.ly', 'x.co', '1url.com', 
    'ad.vu', 'migre.me', 'su.pr', 'smallurl.co', 'cutt.us', 'filoops.info', 
    'shor7.com', 'yfrog.com', 'tinyurl.com', 'u.to', 'ow.ly', 'ff.im', 
    'rubyurl.com', 'r2me.com', 'post.ly', 'twitthis.com', 'buzurl.com', 
    'cur.lv', 'tr.im', 'bl.lnk', 'tiny.cc', 'lnkd.in', 'q.gs', 'is.gd', 
    'hurl.ws', 'om.ly', 'prettylinkpro.com', 'qr.net', 'qr.ae', 'snipurl.com', 
    'ity.im', 't.co', 'db.tt', 'link.zip.net', 'doiop.com', 'url4.eu', 
    'poprl.com', 'tweez.me', 'short.ie', 'me2.do', 'bit.do', 'shorte.st', 
    'go2l.ink', 'yourls.org', 'wp.me', 'goo.gl', 'j.mp', 'twurl.nl', 
    'snipr.com', 'shortto.com', 'vzturl.com', 'u.bb', 'shorturl.at', 
    'han.gl', 'wo.gl', 'wa.gl'
])

# 단축 URL 여부
def is_shortened_url(url):
    """
    주어진 URL이 단축 URL인지 확인합니다.
    
    Args:
    - url (str): 검사할 URL
    
    Returns:
    - int: 단축 URL이면 1, 그렇지 않으면 0
    """
    # try:
    #     hostname = urlparse(url).netloc
    #     # 호스트 이름에서 'www.'를 제거
    #     # hostname = hostname.replace('www.', '')
        
    #     # 호스트 이름이 단축 URL 도메인 목록에 포함되어 있는지 확인
    #     return 1 if hostname in SHORTENING_DOMAINS else 0
    # except Exception as e:
    #     # 예외가 발생한 경우, 의심스러운 사이트로 간주
    #     print(f"An error occurred: {e}")
    #     return -1  # 의심
    parsed_url = urlparse(url)
    return parsed_url.netloc in SHORTENING_DOMAINS
    
def check_if_shortened(url):
    """
    단축 URL 서비스 사용 여부를 검사하는 함수입니다.
    정상 : 단축 URL 서비스를 사용하지 않는 경우
    악성 : 단축 URL 서비스를 사용하는 경우
    @return 정상이면 0, 악성이면 1
    """
    try:
        tiny_url = urlunshort3.UrlUnshortener()
        return 1 if tiny_url.is_shortened(url) else 0
    except:
        return 1

#  페이지 리다이렉션된 횟수
def redirect_count(url):
    try:
        response = requests.head(url, allow_redirects=True)
        count = len(response.history)

        if count <= 1 :
            return 0
        elif count>=2 and count<4:
            return -1
        else:
            return 1
    except requests.RequestException:
        return -1  # 의심

# 리다이렉션 상태 코드
def redirect_status(url):
    try:
        # HEAD 요청을 통해 URL의 리다이렉션 정보를 가져옴
        response = requests.head(url, allow_redirects=True)
        
        # 리다이렉션 히스토리에서 상태 코드 추출
        status_codes = [res.status_code for res in response.history]
        
        # 상태 코드가 301, 302, 307, 308 중 하나라도 있으면 피싱 사이트로 간주
        if any(code in [301, 302, 307, 308] for code in status_codes):
            return 1  # 피싱 사이트
        else:
            return 0  # 정상 사이트
    except requests.RequestException as e:
        # 예외 발생 시 예외 메시지를 출력하고 의심스러운 사이트로 간주
        print(f"An error occurred: {e}")
        return -1  # 의심 사이트

# 서브도메인의 개수
def nb_subdomains(url):
    """
    서브도메인의 개수를 계산합니다. 너무 많은 서브도메인은 피싱 사이트일 가능성이 있습니다.
    
    Args:
    - url (str): 검사할 URL
    
    Returns:
    - int: 서브도메인 개수
    """
    hostname = urlparse(url).netloc
    subdomain_count = len(hostname.split('.')) - 2
    
    # 피싱 사이트일 가능성이 있는 조건: 서브도메인이 2개 이상인 경우
    if subdomain_count == 0:
        return 0  # 정상 사이트
    elif subdomain_count == 1:
        return -1  # 의심 사이트
    else:
        return 1  # 피싱 사이트

# if __name__ == '__main__':
#     test_url = 'https://bit.ly/xyz123'  # 여기에 테스트할 URL을 넣으세요

#     print('Shortening Service:', is_shortened_url(test_url))
#     print('Redirect Count:', redirect_count(test_url))
#     print('Redirect Status:', redirect_status(test_url))
#     print('Length of URL:', length_url(test_url))
#     print('Length of Hostname:', length_hostname(test_url))
#     print('Number of Subdomains:', nb_subdomains(test_url))
#     print('Domain Age:', domain_age(test_url))
